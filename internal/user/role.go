package user

import (
	"encoding/json"
	"fmt"
	"log"
	"relay-server/internal/db"
	"sort"
	"sync"
)

type Permission string

const (
    // Basic permissions
    PermissionSendMessages    Permission = "send_messages"
    PermissionReadMessages    Permission = "read_messages"
    PermissionCreateInvites   Permission = "create_invites"
    PermissionManageInvites   Permission = "manage_invites"

    // Channel permissions
    PermissionCreateChannels  Permission = "create_channels"
    PermissionDeleteChannels  Permission = "delete_channels"
    PermissionManageChannels  Permission = "manage_channels"
    PermissionJoinVoice       Permission = "join_voice"
    PermissionSpeakInVoice    Permission = "speak_in_voice"
    PermissionManageVoice     Permission = "manage_voice"

    // User management permissions
    PermissionKickUsers       Permission = "kick_users"
    PermissionBanUsers        Permission = "ban_users"
    PermissionManageUsers     Permission = "manage_users"
    PermissionAssignRoles     Permission = "assign_roles"

    // Server management permissions
    PermissionManageServer    Permission = "manage_server"
    PermissionManageRoles     Permission = "manage_roles"
    PermissionViewAuditLog    Permission = "view_audit_log"
)

type Role struct {
    ID                 string       `json:"id"`
    Name               string       `json:"name"`
    Color              string       `json:"color"`       // Hex color code (e.g., "#FF5733")
    Rank               int          `json:"rank"`        // Higher rank = more authority
    Permissions        []Permission `json:"permissions"`
    Assignable         bool         `json:"assignable"`  // Can this role be assigned by users with manage_roles permission
    DisplayRoleMembers bool         `json:"display_role_members"` // Whether this role should be displayed in members sidebar
}

// RoleManager handles role operations
type RoleManager struct {
    roles map[string]*Role
    mu    sync.RWMutex
}

var Roles = &RoleManager{
    roles: make(map[string]*Role),
}

// InitializeDefaultRoles sets up the default role hierarchy
func (rm *RoleManager) InitializeDefaultRoles() {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    rm.roles["owner"] = &Role{
        ID:    "owner",
        Name:  "Owner",
        Color: "#FFD700",
        Rank:  1000,
        Permissions: []Permission{
            PermissionSendMessages, PermissionReadMessages,
            PermissionCreateInvites, PermissionManageInvites,
            PermissionCreateChannels, PermissionDeleteChannels, PermissionManageChannels,
            PermissionKickUsers, PermissionBanUsers, PermissionManageUsers, PermissionAssignRoles,
            PermissionManageServer, PermissionManageRoles, PermissionViewAuditLog,
            PermissionJoinVoice, PermissionSpeakInVoice, PermissionManageVoice,
        },
        Assignable:         false, // Only manually assignable
        DisplayRoleMembers: true,  // Display owner role in members sidebar
    }
}

// GetRole retrieves a role by ID
func (rm *RoleManager) GetRole(id string) (*Role, bool) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    role, exists := rm.roles[id]
    return role, exists
}

// GetAllRoles returns all roles sorted by rank
func (rm *RoleManager) GetAllRoles() []*Role {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    roles := make([]*Role, 0, len(rm.roles))
    for _, role := range rm.roles {
        roles = append(roles, role)
    }

    sort.Slice(roles, func(i, j int) bool {
        return roles[i].Rank > roles[j].Rank
    })

    return roles
}

// HasPermission checks if a role has a specific permission
func (r *Role) HasPermission(permission Permission) bool {
    for _, perm := range r.Permissions {
        if perm == permission {
            return true
        }
    }
    return false
}

func (rm *RoleManager) LoadRolesFromDB() {
    var roleModels []RoleModel
    if err := db.DB.Find(&roleModels).Error; err != nil {
        log.Printf("Error loading roles from database: %v", err)
        return
    }

    rm.mu.Lock()
    defer rm.mu.Unlock()

    for _, roleModel := range roleModels {
        var permissions []Permission
        if err := json.Unmarshal([]byte(roleModel.Permissions), &permissions); err != nil {
            log.Printf("Error unmarshaling permissions for role %s: %v", roleModel.ID, err)
            continue
        }

        rm.roles[roleModel.ID] = &Role{
            ID:                 roleModel.ID,
            Name:               roleModel.Name,
            Color:              roleModel.Color,
            Rank:               roleModel.Rank,
            Permissions:        permissions,
            Assignable:         roleModel.Assignable,
            DisplayRoleMembers: roleModel.DisplayRoleMembers,
        }
    }

    log.Printf("Loaded %d custom roles from database", len(roleModels))
}

// SaveRoleToDB saves a role to the database
func (rm *RoleManager) SaveRoleToDB(role *Role) error {
    permissionsJSON, err := json.Marshal(role.Permissions)
    if err != nil {
        return err
    }

    roleModel := RoleModel{
        ID:                 role.ID,
        Name:               role.Name,
        Color:              role.Color,
        Rank:               role.Rank,
        Permissions:        string(permissionsJSON),
        Assignable:         role.Assignable,
        DisplayRoleMembers: role.DisplayRoleMembers,
    }

    return db.DB.Save(&roleModel).Error
}

func (rm *RoleManager) DeleteRoleFromDB(id string) error {
    return db.DB.Delete(&RoleModel{}, "id = ?", id).Error
}

func (rm *RoleManager) CreateRole(role *Role) error {
    rm.mu.Lock()
    rm.roles[role.ID] = role
    rm.mu.Unlock()

    // Save to database (only if it's a custom role)
    if role.Assignable {
        return rm.SaveRoleToDB(role)
    }

    return nil
}

func (rm *RoleManager) UpdateRole(role *Role) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    // Check if role exists
    if _, exists := rm.roles[role.ID]; !exists {
        return fmt.Errorf("role not found")
    }

    // Update the role in memory
    rm.roles[role.ID] = role

    // Save to database
    return rm.SaveRoleToDB(role)
}

func (rm *RoleManager) DeleteRole(id string) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    // Don't allow deletion of default roles
    if id == "owner" {
        return fmt.Errorf("cannot delete default role")
    }

    delete(rm.roles, id)
    return rm.DeleteRoleFromDB(id)
}