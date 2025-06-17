package user

import (
	"crypto/ed25519"
	"log"
	"relay-server/internal/db"
	"sync"
	"time"
)

type User struct {
    Username           string
    Nickname           string
    PublicKey          ed25519.PublicKey
    RoleIDs            []string  // Changed from Roles to RoleIDs
    ID                 string
    ProfilePictureHash string    // Hash of the profile picture
    LastOnline         time.Time // Last time the user was online
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
            ID:                 userModel.ID,
            Username:           userModel.Username,
            Nickname:           userModel.Nickname,
            PublicKey:          ed25519.PublicKey(userModel.PublicKey),
            RoleIDs:            []string(userModel.RoleIDs),
            ProfilePictureHash: userModel.ProfilePictureHash,
            LastOnline:         time.Time(userModel.LastOnline),
        }
    }

    log.Printf("Loaded %d users from database", len(userModels))
}

func SaveUserToDB(user *User) error {
    userModel := UserModel{
        ID:                 user.ID,
        Username:           user.Username,
        Nickname:           user.Nickname,
        PublicKey:          PublicKeyType(user.PublicKey),
        RoleIDs:            RoleIDsType(user.RoleIDs),
        ProfilePictureHash: user.ProfilePictureHash,
        LastOnline:         LastOnlineType(user.LastOnline),
    }

    return db.DB.Save(&userModel).Error
}

// Batch update mechanism for last_online updates
var (
    lastOnlineUpdates      = make(map[string]time.Time)
    lastOnlineUpdatesMu    sync.Mutex
    lastOnlineUpdateTicker *time.Ticker
)

func init() {
    // Initialize batched update ticker
    lastOnlineUpdateTicker = time.NewTicker(10 * time.Second)
    go batchUpdateLastOnline()
}

// batchUpdateLastOnline processes queued last_online updates in batches
func batchUpdateLastOnline() {
    for range lastOnlineUpdateTicker.C {
        lastOnlineUpdatesMu.Lock()
        if len(lastOnlineUpdates) == 0 {
            lastOnlineUpdatesMu.Unlock()
            continue
        }

        // Copy the updates and clear the map
        updates := make(map[string]time.Time)
        for userID, timestamp := range lastOnlineUpdates {
            updates[userID] = timestamp
        }
        lastOnlineUpdates = make(map[string]time.Time)
        lastOnlineUpdatesMu.Unlock()

        // Process updates in batch
        for userID, timestamp := range updates {
            Mu.RLock()
            user, exists := Users[userID]
            Mu.RUnlock()

            if exists {
                Mu.Lock()
                user.LastOnline = timestamp
                Mu.Unlock()

                // Try to save with retry logic
                go saveUserWithRetry(user, 3)
            }
        }
    }
}

// saveUserWithRetry attempts to save user data with retry logic for database locks
func saveUserWithRetry(user *User, maxRetries int) {
    for attempt := 0; attempt < maxRetries; attempt++ {
        if err := SaveUserToDB(user); err != nil {
            if attempt < maxRetries-1 {
                // Wait with exponential backoff before retry
                waitTime := time.Duration(100*(attempt+1)) * time.Millisecond
                log.Printf("Database busy, retrying save for user %s in %v (attempt %d/%d)",
                    user.ID, waitTime, attempt+1, maxRetries)
                time.Sleep(waitTime)
                continue
            } else {
                log.Printf("Failed to save user %s after %d attempts: %v", user.ID, maxRetries, err)
            }
        } else {
            // Success
            break
        }
    }
}

// UpdateLastOnline queues the user's last online time for batched update
func UpdateLastOnline(userID string) {
    lastOnlineUpdatesMu.Lock()
    lastOnlineUpdates[userID] = time.Now()
    lastOnlineUpdatesMu.Unlock()
}

// DeleteUserFromDB removes a user from the database
func DeleteUserFromDB(userID string) error {
    return db.DB.Delete(&UserModel{}, "id = ?", userID).Error
}