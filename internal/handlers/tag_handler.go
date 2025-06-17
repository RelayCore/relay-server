package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/user"
)

type UserTagResponse struct {
    ID             uint      `json:"id"`
    MessageID      uint      `json:"message_id"`
    ChannelID      uint      `json:"channel_id"`
    ChannelName    string    `json:"channel_name"`
    TaggerUserID   string    `json:"tagger_user_id"`
    TaggerUsername string    `json:"tagger_username"`
    TaggerNickname string    `json:"tagger_nickname"`
    MessageContent string    `json:"message_content"`
    IsRead         bool      `json:"is_read"`
    TaggedAt       time.Time `json:"tagged_at"`
    ReadAt         *time.Time `json:"read_at,omitempty"`
}

// GetUserTagsHandler returns all tags for the authenticated user
func GetUserTagsHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    if userID == "" {
        http.Error(w, "User ID required", http.StatusUnauthorized)
        return
    }

    // Get optional filters
    unreadOnly := r.URL.Query().Get("unread_only") == "true"

    // Get limit (default 50, max 100)
    limitStr := r.URL.Query().Get("limit")
    limit := 50
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
            if parsedLimit > 100 {
                limit = 100
            } else {
                limit = parsedLimit
            }
        }
    }

    // Get offset (default 0)
    offsetStr := r.URL.Query().Get("offset")
    offset := 0
    if offsetStr != "" {
        if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
            offset = parsedOffset
        }
    }

    // Build query
    query := db.DB.Preload("Message").Where("tagged_user_id = ?", userID)
    if unreadOnly {
        query = query.Where("is_read = ?", false)
    }

    var tags []channel.UserTag
    if err := query.Order("created_at DESC").
        Limit(limit).
        Offset(offset).
        Find(&tags).Error; err != nil {
        http.Error(w, "Failed to fetch tags", http.StatusInternalServerError)
        return
    }

    // Convert to response format
    tagResponses := make([]UserTagResponse, 0)
    for _, tag := range tags {
        // Get channel name
        var ch channel.Channel
        channelName := "Unknown Channel"
        if err := db.DB.Select("name").First(&ch, tag.ChannelID).Error; err == nil {
            channelName = ch.Name
        }

        // Get tagger info
        user.Mu.RLock()
        taggerUsername := "Unknown User"
        taggerNickname := ""
        if taggerUser, exists := user.Users[tag.TaggerUserID]; exists {
            taggerUsername = taggerUser.Username
            taggerNickname = taggerUser.Nickname
        }
        user.Mu.RUnlock()

        tagResponses = append(tagResponses, UserTagResponse{
            ID:             tag.ID,
            MessageID:      tag.MessageID,
            ChannelID:      tag.ChannelID,
            ChannelName:    channelName,
            TaggerUserID:   tag.TaggerUserID,
            TaggerUsername: taggerUsername,
            TaggerNickname: taggerNickname,
            MessageContent: tag.Message.Content,
            IsRead:         tag.IsRead,
            TaggedAt:       tag.CreatedAt,
            ReadAt:         tag.ReadAt,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "tags":  tagResponses,
        "count": len(tagResponses),
    })
}

// MarkTagAsReadHandler marks a specific tag as read
func MarkTagAsReadHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    if userID == "" {
        http.Error(w, "User ID required", http.StatusUnauthorized)
        return
    }

    var req struct {
        TagID uint `json:"tag_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if req.TagID == 0 {
        http.Error(w, "Tag ID is required", http.StatusBadRequest)
        return
    }

    // Find the tag and verify it belongs to the user
    var tag channel.UserTag
    if err := db.DB.Where("id = ? AND tagged_user_id = ?", req.TagID, userID).First(&tag).Error; err != nil {
        http.Error(w, "Tag not found", http.StatusNotFound)
        return
    }

    // Mark as read
    now := time.Now()
    tag.IsRead = true
    tag.ReadAt = &now

    if err := db.DB.Save(&tag).Error; err != nil {
        http.Error(w, "Failed to mark tag as read", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status":  "success",
        "message": "Tag marked as read",
    })
}

// MarkAllTagsAsReadHandler marks all tags for a user as read
func MarkAllTagsAsReadHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    if userID == "" {
        http.Error(w, "User ID required", http.StatusUnauthorized)
        return
    }

    now := time.Now()
    if err := db.DB.Model(&channel.UserTag{}).
        Where("tagged_user_id = ? AND is_read = ?", userID, false).
        Updates(map[string]interface{}{
            "is_read": true,
            "read_at": now,
        }).Error; err != nil {
        http.Error(w, "Failed to mark tags as read", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "status":  "success",
        "message": "All tags marked as read",
    })
}

// GetUnreadTagCountHandler returns the count of unread tags for a user
func GetUnreadTagCountHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    if userID == "" {
        http.Error(w, "User ID required", http.StatusUnauthorized)
        return
    }

    var count int64
    if err := db.DB.Model(&channel.UserTag{}).
        Where("tagged_user_id = ? AND is_read = ?", userID, false).
        Count(&count).Error; err != nil {
        http.Error(w, "Failed to get unread tag count", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "unread_count": count,
    })
}