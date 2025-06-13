package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"chat-server/internal/user"
)

// CreateRoleHandler creates a new custom role
func CreateRoleHandler(w http.ResponseWriter, r *http.Request) {
    var req user.Role
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if req.ID == "" || req.Name == "" {
        http.Error(w, "Role ID and name are required", http.StatusBadRequest)
        return
    }

    // Check if role already exists
    if _, exists := user.Roles.GetRole(req.ID); exists {
        http.Error(w, "Role already exists", http.StatusConflict)
        return
    }

    // Set default values
    if req.Color == "" {
        req.Color = "#000000"
    }
    if req.Rank == 0 {
        req.Rank = 100
    }
    req.Assignable = true // Custom roles are assignable by default

    if err := user.Roles.CreateRole(&req); err != nil {
        http.Error(w, "Failed to create role", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(req)
}

// GetRolesHandler returns all roles
func GetRolesHandler(w http.ResponseWriter, r *http.Request) {
    roles := user.Roles.GetAllRoles()
    json.NewEncoder(w).Encode(roles)
}

// AssignRoleHandler assigns a role to a user
func AssignRoleHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        UserID string `json:"user_id"`
        RoleID string `json:"role_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Check if role exists and is assignable
    role, exists := user.Roles.GetRole(req.RoleID)
    if !exists {
        http.Error(w, "Role not found", http.StatusNotFound)
        return
    }

    if !role.Assignable {
        http.Error(w, "Role is not assignable", http.StatusForbidden)
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

    // Assign role
    targetUser.AddRole(req.RoleID)

    // Save updated user to database
    if err := user.SaveUserToDB(targetUser); err != nil {
        log.Printf("Error saving user to database: %v", err)
    }

    user.Mu.Unlock()

    json.NewEncoder(w).Encode(map[string]string{
        "message": "Role assigned successfully",
    })
}