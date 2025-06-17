package user

import (
	"log"
	"relay-server/internal/db"
	"sync"
	"time"
)

type Ban struct {
    ID        uint      `gorm:"primaryKey"`
    UserID    string    `gorm:"not null"`
    Username  string    `gorm:"not null"`
    IPAddress string    `gorm:"not null"`
    BannedBy  string    `gorm:"not null"`
    Reason    string    `gorm:"default:''"`
    BannedAt  time.Time `gorm:"not null"`
    ExpiresAt *time.Time // nil for permanent bans
}

// In-memory ban cache for fast lookups
var (
    BannedIPs = make(map[string]*Ban)
    BanMu     sync.RWMutex
)

// LoadBansFromDB loads all active bans into memory
func LoadBansFromDB() {
    var bans []Ban
    if err := db.DB.Where("expires_at IS NULL OR expires_at > ?", time.Now()).Find(&bans).Error; err != nil {
        log.Printf("Error loading bans from database: %v", err)
        return
    }

    BanMu.Lock()
    defer BanMu.Unlock()

    for _, ban := range bans {
        BannedIPs[ban.IPAddress] = &ban
    }

    log.Printf("Loaded %d active bans from database", len(bans))
}

// IsIPBanned checks if an IP address is banned
func IsIPBanned(ipAddress string) (*Ban, bool) {
    BanMu.RLock()
    defer BanMu.RUnlock()

    ban, exists := BannedIPs[ipAddress]
    if !exists {
        return nil, false
    }

    // Check if ban has expired
    if ban.ExpiresAt != nil && time.Now().After(*ban.ExpiresAt) {
        // Remove expired ban
        go func() {
            BanMu.Lock()
            delete(BannedIPs, ipAddress)
            BanMu.Unlock()
            db.DB.Delete(&Ban{}, ban.ID)
        }()
        return nil, false
    }

    return ban, true
}

// CreateBan creates a new ban record
func CreateBan(userID, username, ipAddress, bannedBy, reason string, duration *time.Duration) error {
    ban := Ban{
        UserID:    userID,
        Username:  username,
        IPAddress: ipAddress,
        BannedBy:  bannedBy,
        Reason:    reason,
        BannedAt:  time.Now(),
    }

    if duration != nil {
        expiresAt := time.Now().Add(*duration)
        ban.ExpiresAt = &expiresAt
    }

    // Save to database
    if err := db.DB.Create(&ban).Error; err != nil {
        return err
    }

    // Add to memory cache
    BanMu.Lock()
    BannedIPs[ipAddress] = &ban
    BanMu.Unlock()

    return nil
}

// RemoveBan removes a ban by IP address
func RemoveBan(ipAddress string) error {
    BanMu.Lock()
    ban, exists := BannedIPs[ipAddress]
    if exists {
        delete(BannedIPs, ipAddress)
    }
    BanMu.Unlock()

    if exists {
        return db.DB.Delete(&Ban{}, ban.ID).Error
    }

    return nil
}