package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"relay-server/internal/user"
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
    req.Assignable = true
    if !req.DisplayRoleMembers {
        req.DisplayRoleMembers = true
    }

    if err := user.Roles.CreateRole(&req); err != nil {
        http.Error(w, "Failed to create role", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(req)
}

func UpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ID                 string             `json:"id"`
        Name               string             `json:"name"`
        Color              string             `json:"color"`
        Rank               int                `json:"rank"`
        Permissions        []user.Permission  `json:"permissions"`
        DisplayRoleMembers *bool              `json:"display_role_members,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if req.ID == "" {
        http.Error(w, "Role ID is required", http.StatusBadRequest)
        return
    }

    // Check if role exists
    existingRole, exists := user.Roles.GetRole(req.ID)
    if !exists {
        http.Error(w, "Role not found", http.StatusNotFound)
        return
    }

    // Don't allow updating non-assignable roles (default system roles)
    if !existingRole.Assignable {
        http.Error(w, "Cannot update system role", http.StatusForbidden)
        return
    }

    // Update role with new values, keeping existing values if not provided
    updatedRole := &user.Role{
        ID:         req.ID,
        Assignable: existingRole.Assignable,
    }

    if req.Name != "" {
        updatedRole.Name = req.Name
    } else {
        updatedRole.Name = existingRole.Name
    }

    if req.Color != "" {
        updatedRole.Color = req.Color
    } else {
        updatedRole.Color = existingRole.Color
    }

    if req.Rank != 0 {
        updatedRole.Rank = req.Rank
    } else {
        updatedRole.Rank = existingRole.Rank
    }

    if req.Permissions != nil {
        updatedRole.Permissions = req.Permissions
    } else {
        updatedRole.Permissions = existingRole.Permissions
    }

    if req.DisplayRoleMembers != nil {
        updatedRole.DisplayRoleMembers = *req.DisplayRoleMembers
    } else {
        updatedRole.DisplayRoleMembers = existingRole.DisplayRoleMembers
    }

    // Update the role
    if err := user.Roles.UpdateRole(updatedRole); err != nil {
        log.Printf("Error updating role: %v", err)
        http.Error(w, "Failed to update role", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(updatedRole)
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

// DeleteRoleHandler deletes a custom role
func DeleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ID == "" {
		http.Error(w, "Role ID is required", http.StatusBadRequest)
		return
	}

	// Check if role exists
	role, exists := user.Roles.GetRole(req.ID)
	if !exists {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Don't allow deletion of non-assignable roles (default system roles)
	if !role.Assignable {
		http.Error(w, "Cannot delete system role", http.StatusForbidden)
		return
	}

	// Delete the role
	if err := user.Roles.DeleteRole(req.ID); err != nil {
		log.Printf("Error deleting role: %v", err)
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role deleted successfully",
	})
}