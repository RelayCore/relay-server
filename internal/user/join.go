package user

import (
	"crypto/ed25519"
	"log"
	"relay-server/internal/db"
	"sync"
	"time"
)

type JoinChallenge struct {
    Nonce     []byte
    PublicKey ed25519.PublicKey
    Nickname  string // Add nickname to preserve through join process
}

type Invite struct {
    Code      string
    CreatedBy string
    CreatedAt time.Time
    ExpiresAt *time.Time // nil for never expires
    MaxUses   int        // 0 for unlimited
    Uses      int        // current usage count
}

var (
    Users      = make(map[string]*User)
    Challenges = make(map[string]*JoinChallenge)
    Invites    = make(map[string]*Invite) // invite code -> invite
    Mu         sync.RWMutex
)

func LoadInvitesFromDB() {
    var inviteModels []InviteModel
    if err := db.DB.Find(&inviteModels).Error; err != nil {
        log.Printf("Error loading invites from database: %v", err)
        return
    }

    Mu.Lock()
    defer Mu.Unlock()

    if Invites == nil {
        Invites = make(map[string]*Invite)
    }

    for _, inviteModel := range inviteModels {
        Invites[inviteModel.Code] = &Invite{
            Code:      inviteModel.Code,
            CreatedBy: inviteModel.CreatedBy,
            CreatedAt: inviteModel.CreatedAt,
            ExpiresAt: inviteModel.ExpiresAt,
            MaxUses:   inviteModel.MaxUses,
            Uses:      inviteModel.Uses,
        }
    }

    log.Printf("Loaded %d invites from database", len(inviteModels))
}

func SaveInviteToDB(invite *Invite) error {
    inviteModel := InviteModel{
        Code:      invite.Code,
        CreatedBy: invite.CreatedBy,
        CreatedAt: invite.CreatedAt,
        ExpiresAt: invite.ExpiresAt,
        MaxUses:   invite.MaxUses,
        Uses:      invite.Uses,
    }

    return db.DB.Save(&inviteModel).Error
}

func DeleteInviteFromDB(code string) error {
    return db.DB.Delete(&InviteModel{}, "code = ?", code).Error
}