package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/voice"
	"relay-server/internal/websocket"

	"gorm.io/gorm"
)

type ChannelResponse struct {
	ID            uint                        `json:"id"`
	Name          string                      `json:"name"`
	Description   string                      `json:"description"`
	GroupID       uint                        `json:"group_id"`
	GroupName     string                      `json:"group_name"`
	Position      int                         `json:"position"`
	Type          string                      `json:"type"` // "text" or "voice"
	IsVoice       bool                        `json:"is_voice"`
	VoiceRoomID   *uint                       `json:"voice_room_id,omitempty"`
	LastMessageAt *time.Time                  `json:"last_message_at,omitempty"`
	Permissions   []ChannelPermissionResponse `json:"permissions"`
	Participants  []VoiceParticipantResponse  `json:"participants"`
}

type GroupResponse struct {
	ID       uint              `json:"id"`
	Name     string            `json:"name"`
	Channels []ChannelResponse `json:"channels"`
}

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

type AttachmentApiResponse struct {
    ID            uint      `json:"id"`
    Type          string    `json:"type"`
    FileName      string    `json:"file_name"`
    FileSize      int64     `json:"file_size"`
    FilePath      string    `json:"file_path"`
    MimeType      string    `json:"mime_type"`
    FileHash      string    `json:"file_hash"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}

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
				ID:            ch.ID,
				Name:          ch.Name,
				Description:   ch.Description,
				GroupID:       ch.GroupID,
				GroupName:     group.Name,
				Position:      ch.Position,
				Type:          string(ch.Type),
				IsVoice:       isVoice,
				VoiceRoomID:   voiceRoomID,
				LastMessageAt: ch.LastMessageAt,
				Permissions:   permissionResponses,
				Participants:  participants,
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

	// Broadcast group creation
	go func() {
		websocket.GlobalHub.BroadcastMessage("group_created", map[string]interface{}{
			"id":   group.ID,
			"name": group.Name,
		})
	}()

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

	// Broadcast channel creation
	go func() {
		websocket.GlobalHub.BroadcastMessage("channel_created", map[string]interface{}{
			"id":          ch.ID,
			"name":        ch.Name,
			"description": ch.Description,
			"group_id":    ch.GroupID,
			"group_name":  group.Name,
			"position":    ch.Position,
			"type":        string(ch.Type),
			"is_voice":    req.IsVoice,
		})
	}()

	response := ChannelResponse{
		ID:            ch.ID,
		Name:          ch.Name,
		Description:   ch.Description,
		GroupID:       ch.GroupID,
		GroupName:     group.Name,
		Position:      ch.Position,
		Type:          string(ch.Type),
		IsVoice:       req.IsVoice,
		LastMessageAt: ch.LastMessageAt,
		Permissions:   []ChannelPermissionResponse{},
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

	// Broadcast channel deletion
	go func() {
		websocket.GlobalHub.BroadcastMessage("channel_deleted", map[string]interface{}{
			"channel_id": req.ChannelID,
		})
	}()

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
		GroupID     *uint   `json:"group_id,omitempty"`
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

	// Check if there are any fields to update
	if req.Name == nil && req.Description == nil && req.Position == nil && req.GroupID == nil {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	// If group is being changed, verify the new group exists
	if req.GroupID != nil && *req.GroupID != ch.GroupID {
		var newGroup channel.Group
		if err := db.DB.First(&newGroup, *req.GroupID).Error; err != nil {
			http.Error(w, "New group not found", http.StatusNotFound)
			return
		}
	}

	// Track which channels were affected for websocket broadcast
	type ChannelUpdate struct {
		ID          uint    `json:"id"`
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
		GroupID     uint    `json:"group_id"`
		Position    int     `json:"position"`
	}
	var updatedChannels []ChannelUpdate

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

	// Handle group changes
	isGroupChanged := req.GroupID != nil && *req.GroupID != ch.GroupID
	var newGroupPosition int

	if isGroupChanged {
		// Get the next position in the new group
		db.DB.Model(&channel.Channel{}).Where("group_id = ?", *req.GroupID).Select("COALESCE(MAX(position), -1) + 1").Scan(&newGroupPosition)
		updates["group_id"] = *req.GroupID
		updates["position"] = newGroupPosition
	}

	// Handle position updates (only if not changing groups)
	if req.Position != nil && !isGroupChanged {
		oldPosition := ch.Position
		newPosition := *req.Position

		if oldPosition != newPosition {
			// Start transaction for position updates
			tx := db.DB.Begin()
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
				}
			}()

			// Get affected channels for broadcast
			var affectedChannels []channel.Channel
			if newPosition > oldPosition {
				// Moving down: get channels that will shift up
				tx.Where("group_id = ? AND position > ? AND position <= ? AND id != ?",
					ch.GroupID, oldPosition, newPosition, req.ChannelID).Find(&affectedChannels)
			} else {
				// Moving up: get channels that will shift down
				tx.Where("group_id = ? AND position >= ? AND position < ? AND id != ?",
					ch.GroupID, newPosition, oldPosition, req.ChannelID).Find(&affectedChannels)
			}

			// Add affected channels to update list
			for _, affectedCh := range affectedChannels {
				var newPos int
				if newPosition > oldPosition {
					newPos = affectedCh.Position - 1
				} else {
					newPos = affectedCh.Position + 1
				}
				updatedChannels = append(updatedChannels, ChannelUpdate{
					ID:       affectedCh.ID,
					GroupID:  affectedCh.GroupID,
					Position: newPos,
				})
			}

			// Update other channels' positions in the same group
			if newPosition > oldPosition {
				if err := tx.Model(&channel.Channel{}).
					Where("group_id = ? AND position > ? AND position <= ? AND id != ?",
						ch.GroupID, oldPosition, newPosition, req.ChannelID).
					Update("position", gorm.Expr("position - 1")).Error; err != nil {
					tx.Rollback()
					http.Error(w, "Failed to update channel positions", http.StatusInternalServerError)
					return
				}
			} else if newPosition < oldPosition {
				if err := tx.Model(&channel.Channel{}).
					Where("group_id = ? AND position >= ? AND position < ? AND id != ?",
						ch.GroupID, newPosition, oldPosition, req.ChannelID).
					Update("position", gorm.Expr("position + 1")).Error; err != nil {
					tx.Rollback()
					http.Error(w, "Failed to update channel positions", http.StatusInternalServerError)
					return
				}
			}

			updates["position"] = newPosition

			// Update the channel
			if err := tx.Model(&ch).Updates(updates).Error; err != nil {
				tx.Rollback()
				http.Error(w, "Failed to update channel", http.StatusInternalServerError)
				return
			}

			// Commit transaction
			if err := tx.Commit().Error; err != nil {
				http.Error(w, "Failed to commit updates", http.StatusInternalServerError)
				return
			}
		} else {
			// No position change, just update other fields
			if len(updates) > 0 {
				if err := db.DB.Model(&ch).Updates(updates).Error; err != nil {
					http.Error(w, "Failed to update channel", http.StatusInternalServerError)
					return
				}
			}
		}
	} else if isGroupChanged {
		// Handle group change with transaction to clean up old positions
		tx := db.DB.Begin()
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			}
		}()

		// Get channels that will shift up in the old group
		var oldGroupChannels []channel.Channel
		tx.Where("group_id = ? AND position > ?", ch.GroupID, ch.Position).Find(&oldGroupChannels)

		// Add old group affected channels to update list
		for _, oldCh := range oldGroupChannels {
			updatedChannels = append(updatedChannels, ChannelUpdate{
				ID:       oldCh.ID,
				GroupID:  oldCh.GroupID,
				Position: oldCh.Position - 1,
			})
		}

		// Update the channel first
		if err := tx.Model(&ch).Updates(updates).Error; err != nil {
			tx.Rollback()
			http.Error(w, "Failed to update channel", http.StatusInternalServerError)
			return
		}

		// Clean up positions in the old group by shifting channels up
		if err := tx.Model(&channel.Channel{}).
			Where("group_id = ? AND position > ?", ch.GroupID, ch.Position).
			Update("position", gorm.Expr("position - 1")).Error; err != nil {
			tx.Rollback()
			http.Error(w, "Failed to update old group positions", http.StatusInternalServerError)
			return
		}

		// Commit transaction
		if err := tx.Commit().Error; err != nil {
			http.Error(w, "Failed to commit group change", http.StatusInternalServerError)
			return
		}
	} else {
		// No position or group change, just update other fields
		if len(updates) > 0 {
			if err := db.DB.Model(&ch).Updates(updates).Error; err != nil {
				http.Error(w, "Failed to update channel", http.StatusInternalServerError)
				return
			}
		}
	}

	// Reload the channel to get updated data
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Failed to reload updated channel", http.StatusInternalServerError)
		return
	}

	// Add the main updated channel to the list
	mainUpdate := ChannelUpdate{
		ID:       ch.ID,
		GroupID:  ch.GroupID,
		Position: ch.Position,
	}
	if req.Name != nil {
		mainUpdate.Name = req.Name
	}
	if req.Description != nil {
		mainUpdate.Description = req.Description
	}
	updatedChannels = append(updatedChannels, mainUpdate)

	// Broadcast the channel updates
	websocket.GlobalHub.BroadcastMessage("channel_update", map[string]interface{}{
		"channels": updatedChannels,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedChannels)
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

	// Broadcast permission change
	go func() {
		websocket.GlobalHub.BroadcastMessage("channel_permission_updated", map[string]interface{}{
			"channel_id": permission.ChannelID,
			"permission": response,
		})
	}()

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

	// Broadcast permission deletion
	go func() {
		websocket.GlobalHub.BroadcastMessage("channel_permission_deleted", map[string]interface{}{
			"channel_id": req.ChannelID,
			"user_id":    req.UserID,
			"role_name":  req.RoleName,
		})
	}()

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

    messageIDs := make([]uint, 0, len(messages))
    for _, msg := range messages {
        messageIDs = append(messageIDs, msg.ID)
    }

    var userTags []channel.UserTag
    tagsByMessage := make(map[uint][]TaggedUser)
    if len(messageIDs) > 0 {
        if err := db.DB.Where("message_id IN ?", messageIDs).Find(&userTags).Error; err == nil {
            // Group tags by message ID
            for _, tag := range userTags {
                user.Mu.RLock()
                if taggedUser, exists := user.Users[tag.TaggedUserID]; exists {
                    tagsByMessage[tag.MessageID] = append(tagsByMessage[tag.MessageID], TaggedUser{
                        UserID:   tag.TaggedUserID,
                        Username: taggedUser.Username,
                        Nickname: taggedUser.Nickname,
                    })
                }
                user.Mu.RUnlock()
            }
        }
    }

    // Get pinned message IDs for this channel
    var pinnedMessageIDs []uint
    db.DB.Table("channel_pins").Where("channel_id = ?", uint(channelID)).Pluck("message_id", &pinnedMessageIDs)

    // Create a map for quick lookup of pinned messages
    pinnedMap := make(map[uint]bool)
    for _, id := range pinnedMessageIDs {
        pinnedMap[id] = true
    }

    // Get reply-to messages for messages that are replies
    replyToMessageIDs := make([]uint, 0)
    for _, msg := range messages {
        if msg.ReplyToMessageID != nil {
            replyToMessageIDs = append(replyToMessageIDs, *msg.ReplyToMessageID)
        }
    }

    replyToMessages := make(map[uint]channel.Message)
    if len(replyToMessageIDs) > 0 {
        var replyMessages []channel.Message
        if err := db.DB.Where("id IN ?", replyToMessageIDs).Find(&replyMessages).Error; err == nil {
            for _, replyMsg := range replyMessages {
                replyToMessages[replyMsg.ID] = replyMsg
            }
        }
    }

    // Get reply counts for all messages
    replyCounts := make(map[uint]int64)
    if len(messageIDs) > 0 {
        var replyCountResults []struct {
            ReplyToMessageID uint
            Count            int64
        }
        db.DB.Model(&channel.Message{}).
            Select("reply_to_message_id, COUNT(*) as count").
            Where("reply_to_message_id IN ?", messageIDs).
            Group("reply_to_message_id").
            Scan(&replyCountResults)

        for _, result := range replyCountResults {
            replyCounts[result.ReplyToMessageID] = result.Count
        }
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

            attachmentResponses = append(attachmentResponses, AttachmentResponse{
                ID:            att.ID,
                Type:          att.Type,
                FileName:      att.FileName,
                FileSize:      att.FileSize,
                FilePath:      filePath,
                MimeType:      att.MimeType,
            })
        }

        // Prepare reply information
        var replyToResponse *ReplyToMessageResponse
        if msg.ReplyToMessageID != nil {
            if replyToMsg, exists := replyToMessages[*msg.ReplyToMessageID]; exists {
                // Get reply author info
                user.Mu.RLock()
                replyAuthor, replyExists := user.Users[replyToMsg.AuthorID]
                user.Mu.RUnlock()

                var replyUsername, replyNickname string
                if replyExists {
                    replyUsername = replyAuthor.Username
                    replyNickname = replyAuthor.Nickname
                }

                replyToResponse = &ReplyToMessageResponse{
                    ID:        replyToMsg.ID,
                    AuthorID:  replyToMsg.AuthorID,
                    Content:   replyToMsg.Content,
                    CreatedAt: replyToMsg.CreatedAt,
                    Username:  replyUsername,
                    NickName:  replyNickname,
                }
            }
        }

        messageResponses = append(messageResponses, MessageResponse{
            ID:               msg.ID,
            ChannelID:        msg.ChannelID,
            AuthorID:         msg.AuthorID,
            Content:          msg.Content,
            CreatedAt:        msg.CreatedAt,
            UpdatedAt:        msg.UpdatedAt,
            Username:         username,
            NickName:         nickname,
            Attachments:      attachmentResponses,
            Pinned:           pinnedMap[msg.ID],
            TaggedUsers:      tagsByMessage[msg.ID],
            ReplyToMessageID: msg.ReplyToMessageID,
            ReplyToMessage:   replyToResponse,
            ReplyCount:       int(replyCounts[msg.ID]),
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "messages": messageResponses,
        "count":    len(messageResponses),
    })
}

func GetAllAttachmentsHandler(w http.ResponseWriter, r *http.Request) {
    // Get query parameters
    limitStr := r.URL.Query().Get("limit")
    limit := 50
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 200 {
            limit = parsedLimit
        }
    }

    offsetStr := r.URL.Query().Get("offset")
    offset := 0
    if offsetStr != "" {
        if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
            offset = parsedOffset
        }
    }

    // Filter by attachment type if specified
    attachmentType := r.URL.Query().Get("type")

    // Build query
    query := db.DB.Model(&channel.Attachment{}).Order("created_at DESC")

    // Apply type filter
    if attachmentType != "" {
        query = query.Where("type = ?", attachmentType)
    }

    // Get total count
    var total int64
    if err := query.Count(&total).Error; err != nil {
        http.Error(w, "Failed to count attachments", http.StatusInternalServerError)
        return
    }

    // Apply pagination and fetch attachments
    var attachments []channel.Attachment
    if err := query.Limit(limit).Offset(offset).Find(&attachments).Error; err != nil {
        http.Error(w, "Failed to fetch attachments", http.StatusInternalServerError)
        return
    }

    // Convert to response format
    attachmentResponses := make([]AttachmentApiResponse, 0, len(attachments))
    for _, attachment := range attachments {
        // Convert file path to URL-friendly format
        filePath := attachment.FilePath
        if filePath != "" {
            // Replace backslashes with forward slashes for URLs
            filePath = strings.ReplaceAll(filePath, "\\", "/")
            // Ensure it starts with /uploads/
            if !strings.HasPrefix(filePath, "/uploads/") {
                if strings.HasPrefix(filePath, "uploads/") {
                    filePath = "/" + filePath
                } else {
                    filePath = "/uploads/" + filePath
                }
            }
            filePath = util.GetFullURL(r, filePath)
        }

        attachmentResponses = append(attachmentResponses, AttachmentApiResponse{
            ID:            attachment.ID,
            Type:          string(attachment.Type),
            FileName:      attachment.FileName,
            FileSize:      attachment.FileSize,
            FilePath:      filePath,
            MimeType:      attachment.MimeType,
            FileHash:      attachment.FileHash,
            CreatedAt:     attachment.CreatedAt,
            UpdatedAt:     attachment.UpdatedAt,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "attachments": attachmentResponses,
        "total":       total,
        "count":       len(attachmentResponses),
        "limit":       limit,
        "offset":      offset,
    })
}

// GetAttachmentStatsHandler returns statistics about attachments
func GetAttachmentStatsHandler(w http.ResponseWriter, r *http.Request) {
    // Get total attachment count and size
    var totalCount int64
    var totalSize int64

    db.DB.Model(&channel.Attachment{}).Count(&totalCount)
    db.DB.Model(&channel.Attachment{}).Select("COALESCE(SUM(file_size), 0)").Scan(&totalSize)

    // Get statistics by type
    var typeStats []struct {
        Type  string `json:"type"`
        Count int64  `json:"count"`
        Size  int64  `json:"size"`
    }

    db.DB.Model(&channel.Attachment{}).
        Select("type, COUNT(*) as count, COALESCE(SUM(file_size), 0) as size").
        Group("type").
        Scan(&typeStats)

    // Convert to map
    byType := make(map[string]interface{})
    for _, stat := range typeStats {
        byType[stat.Type] = map[string]interface{}{
            "count": stat.Count,
            "size":  stat.Size,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "total_attachments": totalCount,
        "total_size":        totalSize,
        "by_type":          byType,
    })
}
