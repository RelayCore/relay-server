package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/websocket"
)

// UserResponse represents a user with populated role information
type UserResponse struct {
	ID                string      `json:"id"`
	Username          string      `json:"username"`
	Nickname          string      `json:"nickname"`
	Roles             []*user.Role `json:"roles"`
	IsOnline          bool        `json:"is_online"`
	ProfilePictureURL string      `json:"profile_picture_url"`
	LastOnline        *time.Time  `json:"last_online"`
}

// GetUsersHandler returns all users with their roles and online status
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	user.Mu.RLock()
	defer user.Mu.RUnlock()

	users := make([]UserResponse, 0, len(user.Users))
	for _, u := range user.Users {
		profileURL := ""
		if u.ProfilePictureHash != "" {
			profileURL = util.GetProfilePictureURL(r, u.ID)
		}

		var lastOnline *time.Time
		if !u.LastOnline.IsZero() {
			lastOnline = &u.LastOnline
		}

		userResp := UserResponse{
			ID:                u.ID,
			Username:          u.Username,
			Nickname:          u.Nickname,
			Roles:             u.GetRoles(),
			IsOnline:          websocket.GlobalHub.IsUserOnline(u.ID),
			ProfilePictureURL: profileURL,
			LastOnline:        lastOnline,
		}
		users = append(users, userResp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
		"count": len(users),
	})
}

// GetUserHandler returns a specific user by ID
func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	user.Mu.RLock()
	u, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	profileURL := ""
	if u.ProfilePictureHash != "" {
		profileURL = util.GetProfilePictureURL(r, u.ID)
	}

	var lastOnline *time.Time
	if !u.LastOnline.IsZero() {
		lastOnline = &u.LastOnline
	}

	userResp := UserResponse{
		ID:                u.ID,
		Username:          u.Username,
		Nickname:          u.Nickname,
		Roles:             u.GetRoles(),
		IsOnline:          websocket.GlobalHub.IsUserOnline(u.ID),
		ProfilePictureURL: profileURL,
		LastOnline:        lastOnline,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userResp)
}

// RemoveRoleHandler removes a role from a user
func RemoveRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if role exists
	_, exists := user.Roles.GetRole(req.RoleID)
	if !exists {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Check if user exists
	user.Mu.Lock()
	targetUser, exists := user.Users[req.UserID]
	if !exists {
		user.Mu.Unlock()
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Remove role
	targetUser.RemoveRole(req.RoleID)

	// Save updated user to database
	if err := user.SaveUserToDB(targetUser); err != nil {
		user.Mu.Unlock()
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	// Broadcast role removal
	go func() {
		websocket.GlobalHub.BroadcastMessage("role_removed", map[string]interface{}{
			"user_id": req.UserID,
			"role_id": req.RoleID,
		})
	}()

	user.Mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role removed successfully",
	})
}

// UpdateNicknameHandler allows users to update their own nickname or admins to update any nickname
func UpdateNicknameHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Nickname == "" {
		http.Error(w, "Nickname cannot be empty", http.StatusBadRequest)
		return
	}

	// Get the requesting user from context (set by auth middleware)
	requestingUserID := r.Context().Value("user_id").(string)

	user.Mu.Lock()
	defer user.Mu.Unlock()

	// Check if target user exists
	targetUser, exists := user.Users[req.UserID]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check permissions: user can update their own nickname OR has manage users permission
	requestingUser, exists := user.Users[requestingUserID]
	if !exists {
		http.Error(w, "Requesting user not found", http.StatusForbidden)
		return
	}

	// Allow if user is updating their own nickname OR has manage users permission
	if req.UserID != requestingUserID && !requestingUser.HasPermission(user.PermissionManageUsers) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Update nickname
	targetUser.Nickname = req.Nickname

	// Save to database
	if err := user.SaveUserToDB(targetUser); err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	profileURL := ""
	if targetUser.ProfilePictureHash != "" {
		profileURL = util.GetProfilePictureURL(r, targetUser.ID)
	}

	var lastOnline *time.Time
	if !targetUser.LastOnline.IsZero() {
		lastOnline = &targetUser.LastOnline
	}

	// Broadcast nickname update
	go func() {
		websocket.GlobalHub.BroadcastMessage("user_updated", map[string]interface{}{
			"user_id":  targetUser.ID,
			"nickname": targetUser.Nickname,
			"updated_by": requestingUserID,
		})
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Nickname updated successfully",
		"user": UserResponse{
			ID:                targetUser.ID,
			Username:          targetUser.Username,
			Nickname:          targetUser.Nickname,
			Roles:             targetUser.GetRoles(),
			IsOnline:          websocket.GlobalHub.IsUserOnline(targetUser.ID),
			ProfilePictureURL: profileURL,
			LastOnline:        lastOnline,
		},
	})
}

// UploadProfilePictureHandler allows users to upload their profile picture
func UploadProfilePictureHandler(w http.ResponseWriter, r *http.Request) {
	// Get the requesting user from context (set by auth middleware)
	requestingUserID := r.Context().Value("user_id").(string)

	// Parse multipart form (10MB max)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("profile_picture")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		http.Error(w, "File must be an image", http.StatusBadRequest)
		return
	}

	// Read file content for hash calculation
	fileContent, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Calculate hash of the file
	hash := sha256.Sum256(fileContent)
	hashString := hex.EncodeToString(hash[:])

	user.Mu.Lock()
	defer user.Mu.Unlock()

	// Check if user exists
	targetUser, exists := user.Users[requestingUserID]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check if the hash is the same as current profile picture
	if targetUser.ProfilePictureHash == hashString {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Profile picture is already up to date",
		})
		return
	}

	// Create uploads/icons directory if it doesn't exist
	iconsDir := filepath.Join("uploads", "icons")
	if err := os.MkdirAll(iconsDir, 0755); err != nil {
		http.Error(w, "Failed to create directory", http.StatusInternalServerError)
		return
	}

	// Determine file extension
	ext := filepath.Ext(header.Filename)
	if ext == "" {
		// Default to .jpg if no extension
		ext = ".jpg"
	}

	// Create file path
	filename := fmt.Sprintf("%s%s", requestingUserID, ext)
	filePath := filepath.Join(iconsDir, filename)

	// Create/overwrite the file
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Write file content
	if _, err := dst.Write(fileContent); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Update user's profile picture hash
	targetUser.ProfilePictureHash = hashString

	// Save to database
	if err := user.SaveUserToDB(targetUser); err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	// Broadcast profile picture update
	go func() {
		websocket.GlobalHub.BroadcastMessage("user_profile_updated", map[string]interface{}{
			"user_id":            requestingUserID,
			"profile_picture_url": util.GetFullURL(r, fmt.Sprintf("uploads/icons/%s", filename)),
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Profile picture uploaded successfully",
		"profile_url": util.GetFullURL(r, fmt.Sprintf("uploads/icons/%s", filename)),
		"hash":        hashString,
	})
}

// LeaveServerHandler allows users to leave the server (delete their account)
func LeaveServerHandler(w http.ResponseWriter, r *http.Request) {
	// Get the requesting user from context (set by auth middleware)
	requestingUserID := r.Context().Value("user_id").(string)

	user.Mu.Lock()
	defer user.Mu.Unlock()

	// Check if user exists
	targetUser, exists := user.Users[requestingUserID]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent the last user with owner role from leaving
	ownerRole, ownerExists := user.Roles.GetRole("owner")
	if ownerExists && targetUser.HasRole(ownerRole.ID) {
		http.Error(w, "Cannot leave server: you are the owner", http.StatusForbidden)
		return
	}

	// Disconnect user from websocket if connected
	websocket.GlobalHub.DisconnectUser(requestingUserID)

	// Delete user from memory
	delete(user.Users, requestingUserID)

	// Delete user from database
	if err := user.DeleteUserFromDB(requestingUserID); err != nil {
		// Re-add user back to memory if database deletion fails
		user.Users[requestingUserID] = targetUser
		http.Error(w, "Failed to delete user from database", http.StatusInternalServerError)
		return
	}

	// Broadcast user leave event
	go func() {
		websocket.GlobalHub.BroadcastMessage("user_left", map[string]interface{}{
			"user_id":  requestingUserID,
			"username": targetUser.Username,
			"nickname": targetUser.Nickname,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully left the server",
	})
}