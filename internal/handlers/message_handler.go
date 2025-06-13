package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"chat-server/internal/channel"
	"chat-server/internal/config"
	"chat-server/internal/db"
	"chat-server/internal/user"
	"chat-server/internal/websocket"
)

// SendMessageRequest represents the request body for sending a message
type SendMessageRequest struct {
	ChannelID uint   `json:"channel_id"`
	Content   string `json:"content"`
}

// EditMessageRequest represents the request body for editing a message
type EditMessageRequest struct {
	MessageID uint   `json:"message_id"`
	Content   string `json:"content"`
}

// AttachmentResponse represents an attachment in the response
type AttachmentResponse struct {
	ID            uint                   `json:"id"`
	Type          channel.AttachmentType `json:"type"`
	FileName      string                 `json:"file_name"`
	FileSize      int64                  `json:"file_size"`
	FilePath      string                 `json:"file_path"`
	MimeType      string                 `json:"mime_type"`
	ThumbnailPath *string                `json:"thumbnail_path,omitempty"`
}

// MessageResponse represents a message response with user information
type MessageResponse struct {
	ID          uint                 `json:"id"`
	ChannelID   uint                 `json:"channel_id"`
	AuthorID    string               `json:"author_id"`
	Content     string               `json:"content"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Username    string               `json:"username,omitempty"`
	NickName    string               `json:"nickname,omitempty"`
	Attachments []AttachmentResponse `json:"attachments,omitempty"`
	Pinned      bool                 `json:"pinned"`
}

// SendMessageHandler handles sending messages to channels with optional attachments
func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure we always respond to the client
	defer func() {
		if r := recover(); r != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// Parse multipart form data
	err := r.ParseMultipartForm(config.Conf.MaxFileSize)
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Get channel ID from form
	channelIDStr := r.FormValue("channel_id")
	if channelIDStr == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channelID, err := strconv.ParseUint(channelIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	// Get message content from form
	content := r.FormValue("content")

	// Get files from form
	files := r.MultipartForm.File["attachments"]

	// Validate that we have either content or attachments
	if content == "" && len(files) == 0 {
		http.Error(w, "Message content or attachments are required", http.StatusBadRequest)
		return
	}

	// Validate attachment count
	if len(files) > config.Conf.MaxAttachments {
		http.Error(w, fmt.Sprintf("Too many attachments (max %d)", config.Conf.MaxAttachments), http.StatusBadRequest)
		return
	}

	// Get user from context (set by middleware)
	userObj, ok := r.Context().Value("user").(*user.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		http.Error(w, "User ID not found in context", http.StatusUnauthorized)
		return
	}

	// Verify channel exists
	var ch channel.Channel
	if err := db.DB.First(&ch, uint(channelID)).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Create the message
	message := channel.Message{
		ChannelID: uint(channelID),
		AuthorID:  userID,
		Content:   content,
	}

	if err := db.DB.Create(&message).Error; err != nil {
		http.Error(w, "Failed to create message", http.StatusInternalServerError)
		return
	}

	// Process attachments
	var attachments []channel.Attachment
	var attachmentResponses []AttachmentResponse

	for _, fileHeader := range files {
		attachment, err := processAttachment(fileHeader, message.ID)
		if err != nil {
			// Log error but don't fail the entire message
			fmt.Printf("Failed to process attachment %s: %v\n", fileHeader.Filename, err)
			continue
		}

		if err := db.DB.Create(&attachment).Error; err != nil {
			fmt.Printf("Failed to save attachment %s: %v\n", fileHeader.Filename, err)
			continue
		}

		attachments = append(attachments, *attachment)
		attachmentResponses = append(attachmentResponses, AttachmentResponse{
			ID:            attachment.ID,
			Type:          attachment.Type,
			FileName:      attachment.FileName,
			FileSize:      attachment.FileSize,
			FilePath:      attachment.FilePath,
			MimeType:      attachment.MimeType,
			ThumbnailPath: attachment.ThumbnailPath,
		})
	}

	// Create response with user information and attachments
	response := MessageResponse{
		ID:          message.ID,
		ChannelID:   message.ChannelID,
		AuthorID:    message.AuthorID,
		Content:     message.Content,
		CreatedAt:   message.CreatedAt,
		UpdatedAt:   message.UpdatedAt,
		Username:    userObj.Username,
		NickName:    userObj.Nickname,
		Attachments: attachmentResponses,
		Pinned:      false, // New messages are not pinned by default
	}

	// Set headers before writing response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Encode and send response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		fmt.Printf("Failed to encode response: %v\n", err)
		return
	}

	// Broadcast the message to all connected clients via WebSocket
	// Do this after responding to avoid blocking the HTTP response
	go func() {
		websocket.GlobalHub.BroadcastMessage("new_message", response)
	}()
}

// processAttachment handles file upload and creates attachment record
func processAttachment(fileHeader *multipart.FileHeader, messageID uint) (*channel.Attachment, error) {
	// Open the uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Validate file size
	if fileHeader.Size > config.Conf.MaxFileSize {
		return nil, fmt.Errorf("file too large (max %d bytes)", config.Conf.MaxFileSize)
	}

	// Create uploads directory if it doesn't exist
	uploadsDir := "uploads/attachments"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create uploads directory: %v", err)
	}

	// Generate file hash for deduplication
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("failed to hash file: %v", err)
	}
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer
	file.Seek(0, 0)

	// Generate unique filename using hash and timestamp
	ext := filepath.Ext(fileHeader.Filename)
	timestamp := time.Now().Unix()
	newFileName := fmt.Sprintf("%d_%s%s", timestamp, fileHash[:16], ext)
	filePath := filepath.Join(uploadsDir, newFileName)

	// Create the destination file
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination file: %v", err)
	}
	defer dst.Close()

	// Copy file content
	if _, err := io.Copy(dst, file); err != nil {
		return nil, fmt.Errorf("failed to copy file: %v", err)
	}

	// Determine attachment type from MIME type
	mimeType := fileHeader.Header.Get("Content-Type")
	if mimeType == "" {
		// Fallback to file extension detection
		mimeType = getMimeTypeFromExtension(ext)
	}

	attachmentType := getAttachmentType(mimeType)

	// Create attachment record
	attachment := &channel.Attachment{
		MessageID: messageID,
		Type:      attachmentType,
		FileName:  fileHeader.Filename,
		FileSize:  fileHeader.Size,
		FilePath:  filePath,
		MimeType:  mimeType,
		FileHash:  fileHash,
	}

	// TODO: Generate thumbnail for images/videos if needed
	// This would be implemented later with image processing libraries

	return attachment, nil
}

func DeleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get message ID from URL query parameter
	messageIDStr := r.URL.Query().Get("message_id")
	if messageIDStr == "" {
		http.Error(w, "Message ID is required", http.StatusBadRequest)
		return
	}

	messageID, err := strconv.ParseUint(messageIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	userObj, ok := r.Context().Value("user").(*user.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		http.Error(w, "User ID not found in context", http.StatusUnauthorized)
		return
	}

	// Find the message
	var message channel.Message
	if err := db.DB.First(&message, uint(messageID)).Error; err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	// Check permissions: user can delete their own messages OR user has server management permission
	canDelete := false
	if message.AuthorID == userID {
		canDelete = true
	} else if userObj.HasPermission(user.PermissionManageServer) {
		canDelete = true
	}

	if !canDelete {
		http.Error(w, "Insufficient permissions to delete this message", http.StatusForbidden)
		return
	}

	// Delete associated attachments from filesystem and database
	var attachments []channel.Attachment
	if err := db.DB.Where("message_id = ?", messageID).Find(&attachments).Error; err == nil {
		for _, attachment := range attachments {
			// Delete file from filesystem
			if err := os.Remove(attachment.FilePath); err != nil {
				fmt.Printf("Warning: Failed to delete attachment file %s: %v\n", attachment.FilePath, err)
			}
		}
		// Delete attachment records from database
		db.DB.Where("message_id = ?", messageID).Delete(&channel.Attachment{})
	}

	// Delete the message from database
	if err := db.DB.Delete(&message).Error; err != nil {
		http.Error(w, "Failed to delete message", http.StatusInternalServerError)
		return
	}

	// Create response
	response := map[string]interface{}{
		"message":    "Message deleted successfully",
		"message_id": messageID,
		"channel_id": message.ChannelID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	// Broadcast message deletion to all connected clients
	go func() {
		websocket.GlobalHub.BroadcastMessage("message_deleted", map[string]interface{}{
			"message_id": messageID,
			"channel_id": message.ChannelID,
			"deleted_by": userID,
		})
	}()
}

func EditMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req EditMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.MessageID == 0 {
		http.Error(w, "Message ID is required", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Content) == "" {
		http.Error(w, "Message content cannot be empty", http.StatusBadRequest)
		return
	}

	// Get user from context
	userObj, ok := r.Context().Value("user").(*user.User)
	if !ok {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		http.Error(w, "User ID not found in context", http.StatusUnauthorized)
		return
	}

	// Find the message
	var message channel.Message
	if err := db.DB.First(&message, req.MessageID).Error; err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	// Check permissions: only the message author can edit their own message
	if message.AuthorID != userID {
		http.Error(w, "You can only edit your own messages", http.StatusForbidden)
		return
	}

	// Update the message content
	message.Content = strings.TrimSpace(req.Content)
	message.UpdatedAt = time.Now()

	if err := db.DB.Save(&message).Error; err != nil {
		http.Error(w, "Failed to update message", http.StatusInternalServerError)
		return
	}

	// Load attachments for the response
	var attachments []channel.Attachment
	var attachmentResponses []AttachmentResponse
	if err := db.DB.Where("message_id = ?", message.ID).Find(&attachments).Error; err == nil {
		for _, attachment := range attachments {
			attachmentResponses = append(attachmentResponses, AttachmentResponse{
				ID:            attachment.ID,
				Type:          attachment.Type,
				FileName:      attachment.FileName,
				FileSize:      attachment.FileSize,
				FilePath:      attachment.FilePath,
				MimeType:      attachment.MimeType,
				ThumbnailPath: attachment.ThumbnailPath,
			})
		}
	}

	// Check if message is pinned
	var isPinned bool
	var pinnedCount int64
	db.DB.Table("channel_pins").Where("channel_id = ? AND message_id = ?", message.ChannelID, message.ID).Count(&pinnedCount)
	isPinned = pinnedCount > 0

	// Create response with user information
	response := MessageResponse{
		ID:          message.ID,
		ChannelID:   message.ChannelID,
		AuthorID:    message.AuthorID,
		Content:     message.Content,
		CreatedAt:   message.CreatedAt,
		UpdatedAt:   message.UpdatedAt,
		Username:    userObj.Username,
		NickName:    userObj.Nickname,
		Attachments: attachmentResponses,
		Pinned:      isPinned,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	// Broadcast message edit to all connected clients
	go func() {
		websocket.GlobalHub.BroadcastMessage("message_edited", response)
	}()
}

// PinMessageHandler pins a message to a channel
func PinMessageHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var req struct {
		MessageID uint `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.MessageID == 0 {
		http.Error(w, "Message ID is required", http.StatusBadRequest)
		return
	}

	// Get the message to verify it exists and get channel info
	var message channel.Message
	if err := db.DB.First(&message, req.MessageID).Error; err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	// Check if user has pin permission on this channel
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Server admins can pin anything
	if !userObj.HasPermission(user.PermissionManageServer) {
		// Check channel-specific pin permissions
		var userPermission channel.ChannelPermission
		hasUserPerm := db.DB.Where("channel_id = ? AND user_id = ?", message.ChannelID, userID).First(&userPermission).Error == nil

		if hasUserPerm && !userPermission.CanPin {
			http.Error(w, "Insufficient permissions to pin messages", http.StatusForbidden)
			return
		}

		// Check role-based pin permissions if no user-specific permission
		if !hasUserPerm {
			hasRolePerm := false
			for _, roleID := range userObj.RoleIDs {
				var rolePermission channel.ChannelPermission
				if err := db.DB.Where("channel_id = ? AND role_name = ?", message.ChannelID, roleID).First(&rolePermission).Error; err == nil {
					if rolePermission.CanPin {
						hasRolePerm = true
						break
					}
				}
			}

			if !hasRolePerm {
				// Check if user has channel management permission
				if !userObj.HasPermission(user.PermissionManageChannels) {
					http.Error(w, "Insufficient permissions to pin messages", http.StatusForbidden)
					return
				}
			}
		}
	}

	// Get the channel to add the pinned message
	var ch channel.Channel
	if err := db.DB.First(&ch, message.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Add message to pinned messages using GORM's association
	if err := db.DB.Model(&ch).Association("Pinned").Append(&message); err != nil {
		http.Error(w, "Failed to pin message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Message pinned successfully",
	})
}

// UnpinMessageHandler unpins a message from a channel
func UnpinMessageHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	var req struct {
		MessageID uint `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.MessageID == 0 {
		http.Error(w, "Message ID is required", http.StatusBadRequest)
		return
	}

	// Get the message to verify it exists and get channel info
	var message channel.Message
	if err := db.DB.First(&message, req.MessageID).Error; err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	// Check if user has pin permission on this channel (same logic as pinning)
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Server admins can unpin anything
	if !userObj.HasPermission(user.PermissionManageServer) {
		// Check channel-specific pin permissions
		var userPermission channel.ChannelPermission
		hasUserPerm := db.DB.Where("channel_id = ? AND user_id = ?", message.ChannelID, userID).First(&userPermission).Error == nil

		if hasUserPerm && !userPermission.CanPin {
			http.Error(w, "Insufficient permissions to unpin messages", http.StatusForbidden)
			return
		}

		// Check role-based pin permissions if no user-specific permission
		if !hasUserPerm {
			hasRolePerm := false
			for _, roleID := range userObj.RoleIDs {
				var rolePermission channel.ChannelPermission
				if err := db.DB.Where("channel_id = ? AND role_name = ?", message.ChannelID, roleID).First(&rolePermission).Error; err == nil {
					if rolePermission.CanPin {
						hasRolePerm = true
						break
					}
				}
			}

			if !hasRolePerm {
				// Check if user has channel management permission
				if !userObj.HasPermission(user.PermissionManageChannels) {
					http.Error(w, "Insufficient permissions to unpin messages", http.StatusForbidden)
					return
				}
			}
		}
	}

	// Get the channel to remove the pinned message
	var ch channel.Channel
	if err := db.DB.First(&ch, message.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Remove message from pinned messages using GORM's association
	if err := db.DB.Model(&ch).Association("Pinned").Delete(&message); err != nil {
		http.Error(w, "Failed to unpin message", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Message unpinned successfully",
	})
}

// GetPinnedMessagesHandler returns all pinned messages for a channel
func GetPinnedMessagesHandler(w http.ResponseWriter, r *http.Request) {
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

	// Get the channel with pinned messages
	var ch channel.Channel
	if err := db.DB.Preload("Pinned.Attachments").First(&ch, uint(channelID)).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow pinned message retrieval for text channels
	if ch.Type == channel.ChannelTypeVoice {
		http.Error(w, "Voice channels do not support pinned messages", http.StatusBadRequest)
		return
	}

	// Get server URL from request
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	serverURL := scheme + "://" + r.Host

	// Convert pinned messages to response format
	messageResponses := make([]MessageResponse, 0)
	for _, msg := range ch.Pinned {
		// Get user information
		user.Mu.RLock()
		userObj, exists := user.Users[msg.AuthorID]
		user.Mu.RUnlock()

		var username, nickname string
		if exists {
			username = userObj.Username
			nickname = userObj.Nickname
		}

		// Convert attachments
		attachmentResponses := make([]AttachmentResponse, 0)
		for _, att := range msg.Attachments {
			// Add server URL to file paths
			filePath := att.FilePath
			if filePath != "" && filePath[0] == '/' {
				filePath = serverURL + filePath
			} else if filePath != "" {
				filePath = serverURL + "/" + filePath
			}

			var thumbnailPath *string
			if att.ThumbnailPath != nil {
				path := *att.ThumbnailPath
				if path != "" && path[0] == '/' {
					path = serverURL + path
				} else if path != "" {
					path = serverURL + "/" + path
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
			Pinned:      true, // These are all pinned messages
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pinned_messages": messageResponses,
		"count":          len(messageResponses),
	})
}

// getAttachmentType determines the attachment type from MIME type
func getAttachmentType(mimeType string) channel.AttachmentType {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return channel.AttachmentTypeImage
	case strings.HasPrefix(mimeType, "video/"):
		return channel.AttachmentTypeVideo
	case strings.HasPrefix(mimeType, "audio/"):
		return channel.AttachmentTypeAudio
	default:
		return channel.AttachmentTypeFile
	}
}

// getMimeTypeFromExtension provides fallback MIME type detection
func getMimeTypeFromExtension(ext string) string {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".ogg":
		return "audio/ogg"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}