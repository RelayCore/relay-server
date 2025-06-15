package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/voice"

	"gorm.io/gorm"
)

// ChannelResponse represents a channel with its group information
type ChannelResponse struct {
    ID           uint                        `json:"id"`
    Name         string                      `json:"name"`
    Description  string                      `json:"description"`
    GroupID      uint                        `json:"group_id"`
    GroupName    string                      `json:"group_name"`
    Position     int                         `json:"position"`
    Type         string                      `json:"type"` // "text" or "voice"
    IsVoice      bool                        `json:"is_voice"`
    VoiceRoomID  *uint                       `json:"voice_room_id,omitempty"`
    Permissions  []ChannelPermissionResponse `json:"permissions"`
    Participants []VoiceParticipantResponse  `json:"participants"`
}

// GroupResponse represents a group with its channels
type GroupResponse struct {
	ID       uint              `json:"id"`
	Name     string            `json:"name"`
	Channels []ChannelResponse `json:"channels"`
}

// ChannelPermissionResponse represents a channel permission with proper JSON field names
type ChannelPermissionResponse struct {
	ID         uint    `json:"id"`
	ChannelID  uint    `json:"channel_id"`
	UserID     *string `json:"user_id,omitempty"`
	RoleName   *string `json:"role_name,omitempty"`
	CanRead    bool    `json:"can_read"`
	CanWrite   bool    `json:"can_write"`
	CanPin     bool    `json:"can_pin"`
	IsAdmin    bool    `json:"is_admin"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}

// GetChannelsHandler returns all channels organized by groups
func GetChannelsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var groups []channel.Group
	if err := db.DB.Preload("Channels", func(db *gorm.DB) *gorm.DB {
		return db.Order("position ASC")
	}).Preload("Channels.Permissions").Find(&groups).Error; err != nil {
		http.Error(w, "Failed to fetch channels", http.StatusInternalServerError)
		return
	}

	groupResponses := make([]GroupResponse, 0)
	for _, group := range groups {
		channelResponses := make([]ChannelResponse, 0)
		for _, ch := range group.Channels {
			// Check if user can access this channel
			if !channel.CanUserAccessChannel(userID, ch.ID) {
				continue
			}

			isVoice := ch.Type == channel.ChannelTypeVoice
			var voiceRoomID *uint

			var participants []VoiceParticipantResponse
            if isVoice {
                voiceParticipants := voice.GetVoiceParticipants(ch.ID)
                participants = make([]VoiceParticipantResponse, 0, len(voiceParticipants))
                for _, vp := range voiceParticipants {
                    profileURL := ""
                    user.Mu.RLock()
                    if userObj, exists := user.Users[vp.UserID]; exists && userObj.ProfilePictureHash != "" {
                        profileURL = util.GetProfilePictureURL(r, vp.UserID)
                    }
                    user.Mu.RUnlock()

                    participants = append(participants, VoiceParticipantResponse{
                        UserID:            vp.UserID,
                        Username:          vp.Username,
                        Nickname:          vp.Nickname,
                        IsMuted:           vp.IsMuted,
                        IsDeafened:        vp.IsDeafened,
                        IsSpeaking:        vp.IsSpeaking,
                        JoinedAt:          vp.JoinedAt,
                        ProfilePictureURL: profileURL,
                    })
                }
            } else {
                participants = make([]VoiceParticipantResponse, 0)
            }

			// Convert permissions to response format
			permissionResponses := make([]ChannelPermissionResponse, 0, len(ch.Permissions))
			for _, perm := range ch.Permissions {
				permissionResponses = append(permissionResponses, ChannelPermissionResponse{
					ID:        perm.ID,
					ChannelID: perm.ChannelID,
					UserID:    perm.UserID,
					RoleName:  perm.RoleName,
					CanRead:   perm.CanRead,
					CanWrite:  perm.CanWrite,
					CanPin:    perm.CanPin,
					IsAdmin:   perm.IsAdmin,
					CreatedAt: perm.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
					UpdatedAt: perm.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
				})
			}

			channelResponses = append(channelResponses, ChannelResponse{
				ID:          ch.ID,
				Name:        ch.Name,
				Description: ch.Description,
				GroupID:     ch.GroupID,
				GroupName:   group.Name,
				Position:    ch.Position,
				Type:        string(ch.Type),
				IsVoice:     isVoice,
				VoiceRoomID: voiceRoomID,
				Permissions: permissionResponses,
				Participants: participants,
			})
		}

		// Only include groups that have accessible channels
		if len(channelResponses) > 0 {
			groupResponses = append(groupResponses, GroupResponse{
				ID:       group.ID,
				Name:     group.Name,
				Channels: channelResponses,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"groups": groupResponses,
	})
}

// CreateGroupHandler creates a new channel group
func CreateGroupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Group name is required", http.StatusBadRequest)
		return
	}

	group := channel.Group{
		Name: req.Name,
	}

	if err := db.DB.Create(&group).Error; err != nil {
		http.Error(w, "Failed to create group", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(group)
}

// CreateChannelHandler creates a new channel in a group
func CreateChannelHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		GroupID     uint   `json:"group_id"`
		Position    *int   `json:"position,omitempty"`
		IsVoice     bool   `json:"is_voice,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Channel name is required", http.StatusBadRequest)
		return
	}

	if req.GroupID == 0 {
		http.Error(w, "Group ID is required", http.StatusBadRequest)
		return
	}

	// Verify group exists
	var group channel.Group
	if err := db.DB.First(&group, req.GroupID).Error; err != nil {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	// If no position specified, put at the end
	position := 0
	if req.Position != nil {
		position = *req.Position
	} else {
		// Get the highest position in the group and add 1
		var maxPosition int
		db.DB.Model(&channel.Channel{}).Where("group_id = ?", req.GroupID).Select("COALESCE(MAX(position), -1) + 1").Scan(&maxPosition)
		position = maxPosition
	}

	// Set channel type based on isVoice flag
	channelType := channel.ChannelTypeText
	if req.IsVoice {
		channelType = channel.ChannelTypeVoice
	}

	ch := channel.Channel{
		Name:        req.Name,
		Description: req.Description,
		GroupID:     req.GroupID,
		Position:    position,
		Type:        channelType,
	}

	if err := db.DB.Create(&ch).Error; err != nil {
		http.Error(w, "Failed to create channel", http.StatusInternalServerError)
		return
	}

	response := ChannelResponse{
		ID:          ch.ID,
		Name:        ch.Name,
		Description: ch.Description,
		GroupID:     ch.GroupID,
		GroupName:   group.Name,
		Position:    ch.Position,
		Type:        string(ch.Type),
		IsVoice:     req.IsVoice,
		Permissions: []ChannelPermissionResponse{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DeleteChannelHandler deletes a channel and its associated data
func DeleteChannelHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChannelID uint `json:"channel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChannelID == 0 {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	// Verify channel exists
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Start transaction to ensure all deletions succeed or fail together
	tx := db.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Delete message attachments
	if err := tx.Where("message_id IN (SELECT id FROM messages WHERE channel_id = ?)", req.ChannelID).Delete(&channel.Attachment{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Failed to delete message attachments", http.StatusInternalServerError)
		return
	}

	// Delete messages
	if err := tx.Where("channel_id = ?", req.ChannelID).Delete(&channel.Message{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Failed to delete messages", http.StatusInternalServerError)
		return
	}

	// Delete channel permissions
	if err := tx.Where("channel_id = ?", req.ChannelID).Delete(&channel.ChannelPermission{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Failed to delete channel permissions", http.StatusInternalServerError)
		return
	}

	// Finally delete the channel
	if err := tx.Delete(&ch).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Failed to delete channel", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		http.Error(w, "Failed to commit deletion", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Channel deleted successfully",
	})
}

// UpdateChannelHandler updates channel properties
func UpdateChannelHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChannelID   uint    `json:"channel_id"`
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
		Position    *int    `json:"position,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChannelID == 0 {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	// Check if user can manage this channel
	if !channel.CanUserManageChannel(userID, req.ChannelID) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Verify channel exists
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Update fields if provided
	updates := make(map[string]interface{})
	if req.Name != nil {
		if *req.Name == "" {
			http.Error(w, "Channel name cannot be empty", http.StatusBadRequest)
			return
		}
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Position != nil {
		updates["position"] = *req.Position
	}

	if len(updates) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	if err := db.DB.Model(&ch).Updates(updates).Error; err != nil {
		http.Error(w, "Failed to update channel", http.StatusInternalServerError)
		return
	}

	// Fetch updated channel with group info and permissions
	var group channel.Group
	db.DB.First(&group, ch.GroupID)

	var permissions []channel.ChannelPermission
	db.DB.Where("channel_id = ?", ch.ID).Find(&permissions)

	// Convert permissions to response format
	permissionResponses := make([]ChannelPermissionResponse, 0, len(permissions))
	for _, perm := range permissions {
		permissionResponses = append(permissionResponses, ChannelPermissionResponse{
			ID:        perm.ID,
			ChannelID: perm.ChannelID,
			UserID:    perm.UserID,
			RoleName:  perm.RoleName,
			CanRead:   perm.CanRead,
			CanWrite:  perm.CanWrite,
			CanPin:    perm.CanPin,
			IsAdmin:   perm.IsAdmin,
			CreatedAt: perm.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
			UpdatedAt: perm.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		})
	}

	response := ChannelResponse{
		ID:          ch.ID,
		Name:        ch.Name,
		Description: ch.Description,
		GroupID:     ch.GroupID,
		GroupName:   group.Name,
		Position:    ch.Position,
		Type:        string(ch.Type),
		IsVoice:     ch.Type == channel.ChannelTypeVoice,
		Permissions: permissionResponses,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// SetChannelPermissionHandler sets permissions for a user or role on a channel
func SetChannelPermissionHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChannelID uint    `json:"channel_id"`
		UserID    *string `json:"user_id,omitempty"`
		RoleName  *string `json:"role_name,omitempty"`
		CanRead   *bool   `json:"can_read,omitempty"`
		CanWrite  *bool   `json:"can_write,omitempty"`
		CanPin    *bool   `json:"can_pin,omitempty"`
		IsAdmin   *bool   `json:"is_admin,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChannelID == 0 {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	if req.UserID == nil && req.RoleName == nil {
		http.Error(w, "Either user_id or role_name is required", http.StatusBadRequest)
		return
	}

	if req.UserID != nil && req.RoleName != nil {
		http.Error(w, "Cannot set both user_id and role_name", http.StatusBadRequest)
		return
	}

	// Check if user can manage this channel
	if !channel.CanUserManageChannel(userID, req.ChannelID) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Verify channel exists
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Find or create permission entry
	var permission channel.ChannelPermission
	var whereClause string
	var whereArgs []interface{}

	if req.UserID != nil {
		whereClause = "channel_id = ? AND user_id = ?"
		whereArgs = []interface{}{req.ChannelID, *req.UserID}
	} else {
		whereClause = "channel_id = ? AND role_name = ?"
		whereArgs = []interface{}{req.ChannelID, *req.RoleName}
	}

	err := db.DB.Where(whereClause, whereArgs...).First(&permission).Error
	if err != nil {
		// Create new permission
		permission = channel.ChannelPermission{
			ChannelID: req.ChannelID,
			UserID:    req.UserID,
			RoleName:  req.RoleName,
		}
	}

	// Update permissions
	if req.CanRead != nil {
		permission.CanRead = *req.CanRead
	}
	if req.CanWrite != nil {
		permission.CanWrite = *req.CanWrite
	}
	if req.CanPin != nil {
		permission.CanPin = *req.CanPin
	}
	if req.IsAdmin != nil {
		permission.IsAdmin = *req.IsAdmin
	}

	if err := db.DB.Save(&permission).Error; err != nil {
		http.Error(w, "Failed to save permission", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	response := ChannelPermissionResponse{
		ID:        permission.ID,
		ChannelID: permission.ChannelID,
		UserID:    permission.UserID,
		RoleName:  permission.RoleName,
		CanRead:   permission.CanRead,
		CanWrite:  permission.CanWrite,
		CanPin:    permission.CanPin,
		IsAdmin:   permission.IsAdmin,
		CreatedAt: permission.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		UpdatedAt: permission.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetChannelPermissionsHandler returns all permissions for a channel
func GetChannelPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	channelIDStr := r.URL.Query().Get("channel_id")
	if channelIDStr == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channelID, err := strconv.ParseUint(channelIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	// Check if user can manage this channel
	if !channel.CanUserManageChannel(userID, uint(channelID)) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	var permissions []channel.ChannelPermission
	if err := db.DB.Where("channel_id = ?", uint(channelID)).Find(&permissions).Error; err != nil {
		http.Error(w, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}

	// Convert to response format
	permissionResponses := make([]ChannelPermissionResponse, 0, len(permissions))
	for _, perm := range permissions {
		permissionResponses = append(permissionResponses, ChannelPermissionResponse{
			ID:        perm.ID,
			ChannelID: perm.ChannelID,
			UserID:    perm.UserID,
			RoleName:  perm.RoleName,
			CanRead:   perm.CanRead,
			CanWrite:  perm.CanWrite,
			CanPin:    perm.CanPin,
			IsAdmin:   perm.IsAdmin,
			CreatedAt: perm.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
			UpdatedAt: perm.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"permissions": permissionResponses,
	})
}

// DeleteChannelPermissionHandler removes a permission entry
func DeleteChannelPermissionHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChannelID uint    `json:"channel_id"`
		UserID    *string `json:"user_id,omitempty"`
		RoleName  *string `json:"role_name,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChannelID == 0 {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	if req.UserID == nil && req.RoleName == nil {
		http.Error(w, "Either user_id or role_name is required", http.StatusBadRequest)
		return
	}

	// Check if user can manage this channel
	if !channel.CanUserManageChannel(userID, req.ChannelID) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	var whereClause string
	var whereArgs []interface{}

	if req.UserID != nil {
		whereClause = "channel_id = ? AND user_id = ?"
		whereArgs = []interface{}{req.ChannelID, *req.UserID}
	} else {
		whereClause = "channel_id = ? AND role_name = ?"
		whereArgs = []interface{}{req.ChannelID, *req.RoleName}
	}

	if err := db.DB.Where(whereClause, whereArgs...).Delete(&channel.ChannelPermission{}).Error; err != nil {
		http.Error(w, "Failed to delete permission", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Permission deleted successfully",
	})
}

func GetChannelMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	channelIDStr := r.URL.Query().Get("channel_id")
	if channelIDStr == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channelID, err := strconv.ParseUint(channelIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	// Check if user can access this channel
	if !channel.CanUserAccessChannel(userID, uint(channelID)) {
		http.Error(w, "Insufficient permissions to access this channel", http.StatusForbidden)
		return
	}

	// Verify channel exists and is a text channel
	var ch channel.Channel
	if err := db.DB.First(&ch, uint(channelID)).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow message retrieval for text channels
	if ch.Type == channel.ChannelTypeVoice {
		http.Error(w, "Cannot retrieve messages from voice channels", http.StatusBadRequest)
		return
	}

	// Get limit from query params (default to 50)
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Get offset from query params (default to 0)
	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	var messages []channel.Message
	if err := db.DB.Preload("Attachments").
		Where("channel_id = ?", uint(channelID)).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&messages).Error; err != nil {
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}

	// Get pinned message IDs for this channel
	var pinnedMessageIDs []uint
	db.DB.Table("channel_pins").Where("channel_id = ?", uint(channelID)).Pluck("message_id", &pinnedMessageIDs)

	// Create a map for quick lookup of pinned messages
	pinnedMap := make(map[uint]bool)
	for _, id := range pinnedMessageIDs {
		pinnedMap[id] = true
	}

	// Initialize with empty slice to ensure [] instead of null
	messageResponses := make([]MessageResponse, 0)
	for _, msg := range messages {
		// Get user information
		user.Mu.RLock()
		userObj, exists := user.Users[msg.AuthorID]
		user.Mu.RUnlock()

		var username, nickname string
		if exists {
			username = userObj.Username
			nickname = userObj.Nickname
		}

		// Initialize attachment responses with empty slice
		attachmentResponses := make([]AttachmentResponse, 0)
		for _, att := range msg.Attachments {
			// Add server URL to file paths
			filePath := att.FilePath
			if filePath != "" && filePath[0] == '/' {
				filePath = util.GetFullURL(r, filePath)
			} else if filePath != "" {
				filePath = util.GetFullURL(r, filePath)
			}

			var thumbnailPath *string
			if att.ThumbnailPath != nil {
				path := *att.ThumbnailPath
				if path != "" && path[0] == '/' {
					path = util.GetFullURL(r, path)
				} else if path != "" {
					path = util.GetFullURL(r, path)
				}
				thumbnailPath = &path
			}

			attachmentResponses = append(attachmentResponses, AttachmentResponse{
				ID:            att.ID,
				Type:          att.Type,
				FileName:      att.FileName,
				FileSize:      att.FileSize,
				FilePath:      filePath,
				MimeType:      att.MimeType,
				ThumbnailPath: thumbnailPath,
			})
		}

		messageResponses = append(messageResponses, MessageResponse{
			ID:          msg.ID,
			ChannelID:   msg.ChannelID,
			AuthorID:    msg.AuthorID,
			Content:     msg.Content,
			CreatedAt:   msg.CreatedAt,
			UpdatedAt:   msg.UpdatedAt,
			Username:    username,
			NickName:    nickname,
			Attachments: attachmentResponses,
			Pinned:      pinnedMap[msg.ID], // Check if message is pinned
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": messageResponses,
		"count":    len(messageResponses),
	})
}
