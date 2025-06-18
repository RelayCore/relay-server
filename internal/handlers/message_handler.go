package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/config"
	"relay-server/internal/db"
	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/websocket"
)

// SendMessageRequest represents the request body for sending a message
type SendMessageRequest struct {
    ChannelID        uint   `json:"channel_id"`
    Content          string `json:"content"`
    ReplyToMessageID *uint  `json:"reply_to_message_id,omitempty"`
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
}

type TaggedUser struct {
    UserID   string `json:"user_id"`
    Username string `json:"username"`
    Nickname string `json:"nickname"`
}

type MessageResponse struct {
    ID               uint                    `json:"id"`
    ChannelID        uint                    `json:"channel_id"`
    AuthorID         string                  `json:"author_id"`
    Content          string                  `json:"content"`
    CreatedAt        time.Time               `json:"created_at"`
    UpdatedAt        time.Time               `json:"updated_at"`
    Username         string                  `json:"username,omitempty"`
    NickName         string                  `json:"nickname,omitempty"`
    Attachments      []AttachmentResponse    `json:"attachments,omitempty"`
    Pinned           bool                    `json:"pinned"`
    TaggedUsers      []TaggedUser            `json:"tagged_users,omitempty"`
    ReplyToMessageID *uint                   `json:"reply_to_message_id,omitempty"`
    ReplyToMessage   *ReplyToMessageResponse `json:"reply_to_message,omitempty"`
    ReplyCount       int                     `json:"reply_count"`
}

type ReplyToMessageResponse struct {
    ID        uint      `json:"id"`
    AuthorID  string    `json:"author_id"`
    Content   string    `json:"content"`
    CreatedAt time.Time `json:"created_at"`
    Username  string    `json:"username,omitempty"`
    NickName  string    `json:"nickname,omitempty"`
}

func detectUserTags(content string) []string {
    // Regex to match @username patterns (alphanumeric + underscore)
    re := regexp.MustCompile(`@([a-zA-Z0-9_]+)`)
    matches := re.FindAllStringSubmatch(content, -1)

    usernames := make([]string, 0)
    seen := make(map[string]bool) // Prevent duplicates

    for _, match := range matches {
        if len(match) > 1 {
            username := match[1]
            if !seen[username] {
                usernames = append(usernames, username)
                seen[username] = true
            }
        }
    }

    return usernames
}

// storeUserTags creates UserTag records for mentioned users
func storeUserTags(messageID uint, channelID uint, taggerUserID string, taggedUsernames []string) []TaggedUser {
    var taggedUsers []TaggedUser

    // Look up users by username
    user.Mu.RLock()
    for _, username := range taggedUsernames {
        for userID, userObj := range user.Users {
            if userObj.Username == username {
                // Don't tag yourself
                if userID == taggerUserID {
                    continue
                }

                // Create tag record
                tag := channel.UserTag{
                    MessageID:    messageID,
                    TaggedUserID: userID,
                    TaggerUserID: taggerUserID,
                    ChannelID:    channelID,
                    IsRead:       false,
                }

                if err := db.DB.Create(&tag).Error; err != nil {
                    log.Printf("Failed to create user tag: %v", err)
                    continue
                }

                taggedUsers = append(taggedUsers, TaggedUser{
                    UserID:   userID,
                    Username: userObj.Username,
                    Nickname: userObj.Nickname,
                })
                break
            }
        }
    }
    user.Mu.RUnlock()

    return taggedUsers
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

    // Get reply_to_message_id from form (optional)
    var replyToMessageID *uint
    replyToStr := r.FormValue("reply_to_message_id")
    if replyToStr != "" {
        if replyID, err := strconv.ParseUint(replyToStr, 10, 32); err == nil {
            replyToUint := uint(replyID)
            replyToMessageID = &replyToUint
        }
    }

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

    // Verify the message being replied to exists and is in the same channel (if replying)
    var replyToMessage *channel.Message
    if replyToMessageID != nil {
        replyToMessage = &channel.Message{}
        if err := db.DB.First(replyToMessage, *replyToMessageID).Error; err != nil {
            http.Error(w, "Reply target message not found", http.StatusNotFound)
            return
        }

        // Ensure the message being replied to is in the same channel
        if replyToMessage.ChannelID != uint(channelID) {
            http.Error(w, "Cannot reply to message from different channel", http.StatusBadRequest)
            return
        }
    }

    // Create the message
    message := channel.Message{
        ChannelID:        uint(channelID),
        AuthorID:         userID,
        Content:          content,
        ReplyToMessageID: replyToMessageID,
    }

    if err := db.DB.Create(&message).Error; err != nil {
        http.Error(w, "Failed to create message", http.StatusInternalServerError)
        return
    }

    // Update channel's last message timestamp
    now := time.Now()
    if err := db.DB.Model(&channel.Channel{}).Where("id = ?", channelID).Update("last_message_at", now).Error; err != nil {
        // Log error but don't fail the request
        fmt.Printf("Failed to update channel last_message_at: %v\n", err)
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
        })
    }

    var taggedUsers []TaggedUser
    if content != "" {
        taggedUsernames := detectUserTags(content)
        if len(taggedUsernames) > 0 {
            taggedUsers = storeUserTags(message.ID, uint(channelID), userID, taggedUsernames)
        }
    }

    // Prepare reply information for response
	var replyToResponse *ReplyToMessageResponse
	var replyCount int64
	if replyToMessage != nil {
		// Get reply author info
		user.Mu.RLock()
		replyAuthor, exists := user.Users[replyToMessage.AuthorID]
		user.Mu.RUnlock()

        var replyUsername, replyNickname string
        if exists {
            replyUsername = replyAuthor.Username
            replyNickname = replyAuthor.Nickname
        }

        replyToResponse = &ReplyToMessageResponse{
            ID:        replyToMessage.ID,
            AuthorID:  replyToMessage.AuthorID,
            Content:   replyToMessage.Content,
            CreatedAt: replyToMessage.CreatedAt,
            Username:  replyUsername,
            NickName:  replyNickname,
        }
    }

    // Get reply count for this message (should be 0 for new messages)
    db.DB.Model(&channel.Message{}).Where("reply_to_message_id = ?", message.ID).Count(&replyCount)

    // Create response with user information and attachments
	response := MessageResponse{
		ID:               message.ID,
		ChannelID:        message.ChannelID,
		AuthorID:         message.AuthorID,
		Content:          message.Content,
		CreatedAt:        message.CreatedAt,
		UpdatedAt:        message.UpdatedAt,
		Username:         userObj.Username,
		NickName:         userObj.Nickname,
		Attachments:      attachmentResponses,
		Pinned:           false,
		TaggedUsers:      taggedUsers,
		ReplyToMessageID: replyToMessageID,
		ReplyToMessage:   replyToResponse,
		ReplyCount:       int(replyCount),
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
        // Broadcast to all users in channel
        websocket.GlobalHub.BroadcastMessage("new_message", response)

        // Send individual tag notifications to tagged users
        for _, taggedUser := range taggedUsers {
            websocket.GlobalHub.SendMessageToUser(taggedUser.UserID, "user_tagged", map[string]interface{}{
                "message_id":        message.ID,
                "channel_id":        message.ChannelID,
                "tagger_id":         userID,
                "tagger_username":   userObj.Username,
                "tagger_nickname":   userObj.Nickname,
                "tagged_at":         message.CreatedAt,
            })
        }

        // If this is a reply, notify the original message author
        if replyToMessage != nil && replyToMessage.AuthorID != userID {
            websocket.GlobalHub.SendMessageToUser(replyToMessage.AuthorID, "message_reply", map[string]interface{}{
                "message_id":           message.ID,
                "reply_to_message_id":  replyToMessage.ID,
                "channel_id":           message.ChannelID,
                "replier_id":           userID,
                "replier_username":     userObj.Username,
                "replier_nickname":     userObj.Nickname,
                "reply_content":        message.Content,
                "replied_at":           message.CreatedAt,
            })
        }
    }()
}

func GetMessageRepliesHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    if userID == "" {
        http.Error(w, "User ID required", http.StatusUnauthorized)
        return
    }

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

    // Get the original message to verify it exists and check channel access
    var originalMessage channel.Message
    if err := db.DB.First(&originalMessage, uint(messageID)).Error; err != nil {
        http.Error(w, "Message not found", http.StatusNotFound)
        return
    }

    // Check if user can access the channel
    if !channel.CanUserAccessChannel(userID, originalMessage.ChannelID) {
        http.Error(w, "Insufficient permissions to access this channel", http.StatusForbidden)
        return
    }

    // Get limit from query params (default to 20)
    limitStr := r.URL.Query().Get("limit")
    limit := 20
    if limitStr != "" {
        if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
            if parsedLimit > 100 {
                limit = 100
            } else {
                limit = parsedLimit
            }
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

    // Get replies to this message
    var replies []channel.Message
    if err := db.DB.Preload("Attachments").
        Where("reply_to_message_id = ?", uint(messageID)).
        Order("created_at ASC").
        Limit(limit).
        Offset(offset).
        Find(&replies).Error; err != nil {
        http.Error(w, "Failed to fetch replies", http.StatusInternalServerError)
        return
    }

    // Get user tags for replies
    replyIDs := make([]uint, 0, len(replies))
    for _, reply := range replies {
        replyIDs = append(replyIDs, reply.ID)
    }

    var userTags []channel.UserTag
    tagsByMessage := make(map[uint][]TaggedUser)
    if len(replyIDs) > 0 {
        if err := db.DB.Where("message_id IN ?", replyIDs).Find(&userTags).Error; err == nil {
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

    // Convert replies to response format
    replyResponses := make([]MessageResponse, 0)
    for _, reply := range replies {
        // Get user information
        user.Mu.RLock()
        userObj, exists := user.Users[reply.AuthorID]
        user.Mu.RUnlock()

        var username, nickname string
        if exists {
            username = userObj.Username
            nickname = userObj.Nickname
        }

        // Convert attachments
        attachmentResponses := make([]AttachmentResponse, 0)
        for _, att := range reply.Attachments {
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

        // Get reply count for this reply (nested replies)
        var nestedReplyCount int64
        db.DB.Model(&channel.Message{}).Where("reply_to_message_id = ?", reply.ID).Count(&nestedReplyCount)

        replyResponses = append(replyResponses, MessageResponse{
            ID:               reply.ID,
            ChannelID:        reply.ChannelID,
            AuthorID:         reply.AuthorID,
            Content:          reply.Content,
            CreatedAt:        reply.CreatedAt,
            UpdatedAt:        reply.UpdatedAt,
            Username:         username,
            NickName:         nickname,
            Attachments:      attachmentResponses,
            Pinned:           false, // Replies are not pinned directly
            TaggedUsers:      tagsByMessage[reply.ID],
            ReplyToMessageID: reply.ReplyToMessageID,
            ReplyCount:       int(nestedReplyCount),
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "replies":             replyResponses,
        "count":               len(replyResponses),
        "original_message_id": messageID,
    })
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

	// Update channel's last message timestamp to the most recent remaining message
	var lastMessage channel.Message
	if err := db.DB.Where("channel_id = ?", message.ChannelID).Order("created_at DESC").First(&lastMessage).Error; err != nil {
		// No messages left, set last_message_at to nil
		db.DB.Model(&channel.Channel{}).Where("id = ?", message.ChannelID).Update("last_message_at", nil)
	} else {
		// Update to the timestamp of the most recent remaining message
		db.DB.Model(&channel.Channel{}).Where("id = ?", message.ChannelID).Update("last_message_at", lastMessage.CreatedAt)
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

	// Update channel's last message timestamp when message is edited
	if err := db.DB.Model(&channel.Channel{}).Where("id = ?", message.ChannelID).Update("last_message_at", message.UpdatedAt).Error; err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to update channel last_message_at on edit: %v\n", err)
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

	// Broadcast message pin event
	go func() {
		websocket.GlobalHub.BroadcastMessage("message_pinned", map[string]interface{}{
			"message_id": req.MessageID,
			"channel_id": message.ChannelID,
			"pinned_by":  userID,
		})
	}()

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

	// Broadcast message unpin event
	go func() {
		websocket.GlobalHub.BroadcastMessage("message_unpinned", map[string]interface{}{
			"message_id": req.MessageID,
			"channel_id": message.ChannelID,
			"unpinned_by": userID,
		})
	}()

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

// SearchMessagesHandler searches for messages across channels the user has access to
func SearchMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID required", http.StatusUnauthorized)
		return
	}

	// Get search parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Search query is required", http.StatusBadRequest)
		return
	}

	// Optional channel filter
	channelIDStr := r.URL.Query().Get("channel_id")
	var channelID *uint
	if channelIDStr != "" {
		if parsed, err := strconv.ParseUint(channelIDStr, 10, 32); err == nil {
			id := uint(parsed)
			channelID = &id
		}
	}

	// Optional author filter
	authorID := r.URL.Query().Get("author_id")

	// Get limit from query params (default to 20, max 100)
	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				limit = 100
			} else {
				limit = parsedLimit
			}
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

	// Get channels user has access to
	var accessibleChannels []uint
	var channels []channel.Channel
	if err := db.DB.Find(&channels).Error; err != nil {
		http.Error(w, "Failed to fetch channels", http.StatusInternalServerError)
		return
	}

	for _, ch := range channels {
		if channel.CanUserAccessChannel(userID, ch.ID) {
			// Only include text channels in search
			if ch.Type == channel.ChannelTypeText {
				accessibleChannels = append(accessibleChannels, ch.ID)
			}
		}
	}

	if len(accessibleChannels) == 0 {
		// User has no access to any text channels
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"messages": []MessageResponse{},
			"count":    0,
		})
		return
	}

	// Build search query
	searchQuery := db.DB.Preload("Attachments").
		Where("channel_id IN ?", accessibleChannels).
		Where("LOWER(content) LIKE ?", "%"+strings.ToLower(query)+"%")

	// Apply optional filters
	if channelID != nil {
		// Check if user has access to the specific channel
		if !channel.CanUserAccessChannel(userID, *channelID) {
			http.Error(w, "No access to specified channel", http.StatusForbidden)
			return
		}
		searchQuery = searchQuery.Where("channel_id = ?", *channelID)
	}

	if authorID != "" {
		searchQuery = searchQuery.Where("author_id = ?", authorID)
	}

	var messages []channel.Message
	if err := searchQuery.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&messages).Error; err != nil {
		http.Error(w, "Failed to search messages", http.StatusInternalServerError)
		return
	}

	// Get pinned message IDs for relevant channels
	var pinnedMessageIDs []uint
	if len(messages) > 0 {
		channelIDs := make([]uint, 0)
		for _, msg := range messages {
			channelIDs = append(channelIDs, msg.ChannelID)
		}
		db.DB.Table("channel_pins").Where("channel_id IN ?", channelIDs).Pluck("message_id", &pinnedMessageIDs)
	}

	// Create a map for quick lookup of pinned messages
	pinnedMap := make(map[uint]bool)
	for _, id := range pinnedMessageIDs {
		pinnedMap[id] = true
	}

	// Get channel names for context
	channelNames := make(map[uint]string)
	for _, ch := range channels {
		channelNames[ch.ID] = ch.Name
	}

	// Convert messages to response format
	messageResponses := make([]MessageSearchResponse, 0)
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

		// Convert attachments
		attachmentResponses := make([]AttachmentResponse, 0)
		for _, att := range msg.Attachments {
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

		messageResponses = append(messageResponses, MessageSearchResponse{
			ID:          msg.ID,
			ChannelID:   msg.ChannelID,
			ChannelName: channelNames[msg.ChannelID],
			AuthorID:    msg.AuthorID,
			Content:     msg.Content,
			CreatedAt:   msg.CreatedAt,
			UpdatedAt:   msg.UpdatedAt,
			Username:    username,
			NickName:    nickname,
			Attachments: attachmentResponses,
			Pinned:      pinnedMap[msg.ID],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": messageResponses,
		"count":    len(messageResponses),
		"query":    query,
	})
}

// MessageSearchResponse represents a message search result with channel context
type MessageSearchResponse struct {
    ID               uint                    `json:"id"`
    ChannelID        uint                    `json:"channel_id"`
    ChannelName      string                  `json:"channel_name"`
    AuthorID         string                  `json:"author_id"`
    Content          string                  `json:"content"`
    CreatedAt        time.Time               `json:"created_at"`
    UpdatedAt        time.Time               `json:"updated_at"`
    Username         string                  `json:"username,omitempty"`
    NickName         string                  `json:"nickname,omitempty"`
    Attachments      []AttachmentResponse    `json:"attachments,omitempty"`
    Pinned           bool                    `json:"pinned"`
    ReplyToMessageID *uint                   `json:"reply_to_message_id,omitempty"`
    ReplyToMessage   *ReplyToMessageResponse `json:"reply_to_message,omitempty"`
    ReplyCount       int                     `json:"reply_count"`
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