package user

import (
	"crypto/ed25519"
	"log"
	"relay-server/internal/db"
)

type User struct {
    Username  string
    Nickname  string
    PublicKey ed25519.PublicKey
    RoleIDs   []string  // Changed from Roles to RoleIDs
    ID        string
}

// GetRoles returns the actual Role objects for this user
func (u *User) GetRoles() []*Role {
    roles := make([]*Role, 0, len(u.RoleIDs))
    for _, roleID := range u.RoleIDs {
        if role, exists := Roles.GetRole(roleID); exists {
            roles = append(roles, role)
        }
    }
    return roles
}

// HasPermission checks if user has a specific permission through any of their roles
func (u *User) HasPermission(permission Permission) bool {
    for _, roleID := range u.RoleIDs {
        if role, exists := Roles.GetRole(roleID); exists {
            if role.HasPermission(permission) {
                return true
            }
        }
    }
    return false
}

// GetHighestRank returns the highest rank among user's roles
func (u *User) GetHighestRank() int {
    highestRank := 0
    for _, roleID := range u.RoleIDs {
        if role, exists := Roles.GetRole(roleID); exists {
            if role.Rank > highestRank {
                highestRank = role.Rank
            }
        }
    }
    return highestRank
}

// HasRole checks if user has a specific role
func (u *User) HasRole(roleID string) bool {
    for _, userRoleID := range u.RoleIDs {
        if userRoleID == roleID {
            return true
        }
    }
    return false
}

// AddRole adds a role to the user
func (u *User) AddRole(roleID string) {
    if !u.HasRole(roleID) {
        u.RoleIDs = append(u.RoleIDs, roleID)
    }
}

// RemoveRole removes a role from the user
func (u *User) RemoveRole(roleID string) {
    for i, userRoleID := range u.RoleIDs {
        if userRoleID == roleID {
            u.RoleIDs = append(u.RoleIDs[:i], u.RoleIDs[i+1:]...)
            break
        }
    }
}

func LoadUsersFromDB() {
    var userModels []UserModel
    if err := db.DB.Find(&userModels).Error; err != nil {
        log.Printf("Error loading users from database: %v", err)
        return
    }

    Mu.Lock()
    defer Mu.Unlock()

    for _, userModel := range userModels {
        Users[userModel.ID] = &User{
            ID:        userModel.ID,
            Username:  userModel.Username,
            Nickname:  userModel.Nickname,
            PublicKey: ed25519.PublicKey(userModel.PublicKey),
            RoleIDs:   []string(userModel.RoleIDs),
        }
    }

    log.Printf("Loaded %d users from database", len(userModels))
}

func SaveUserToDB(user *User) error {
    userModel := UserModel{
        ID:        user.ID,
        Username:  user.Username,
        Nickname:  user.Nickname,
        PublicKey: PublicKeyType(user.PublicKey),
        RoleIDs:   RoleIDsType(user.RoleIDs),
    }

    return db.DB.Save(&userModel).Error
}