package handlers

import (
	"encoding/json"
	"net/http"

	"relay-server/internal/user"
	"relay-server/internal/websocket"
)

// UserResponse represents a user with populated role information
type UserResponse struct {
	ID        string      `json:"id"`
	Username  string      `json:"username"`
	Nickname  string      `json:"nickname"`
	Roles     []*user.Role `json:"roles"`
	IsOnline  bool        `json:"is_online"`
}

// GetUsersHandler returns all users with their roles and online status
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	user.Mu.RLock()
	defer user.Mu.RUnlock()

	users := make([]UserResponse, 0, len(user.Users))
	for _, u := range user.Users {
		userResp := UserResponse{
			ID:       u.ID,
			Username: u.Username,
			Nickname: u.Nickname,
			Roles:    u.GetRoles(),
			IsOnline: websocket.GlobalHub.IsUserOnline(u.ID),
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

	userResp := UserResponse{
		ID:       u.ID,
		Username: u.Username,
		Nickname: u.Nickname,
		Roles:    u.GetRoles(),
		IsOnline: websocket.GlobalHub.IsUserOnline(u.ID),
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

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Nickname updated successfully",
		"user": UserResponse{
			ID:       targetUser.ID,
			Username: targetUser.Username,
			Nickname: targetUser.Nickname,
			Roles:    targetUser.GetRoles(),
			IsOnline: websocket.GlobalHub.IsUserOnline(targetUser.ID),
		},
	})
}