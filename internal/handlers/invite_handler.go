package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"relay-server/internal/user"
)

func CreateInviteHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        CreatedBy string `json:"created_by"` // User ID
        ExpiresIn int    `json:"expires_in"` // Hours, 0 for never
        MaxUses   int    `json:"max_uses"`   // 0 for unlimited
    }
    _ = json.NewDecoder(r.Body).Decode(&req)

    // Generate random invite code
    codeBytes := make([]byte, 16)
    rand.Read(codeBytes)
    code := hex.EncodeToString(codeBytes)

    invite := &user.Invite{
        Code:      code,
        CreatedBy: req.CreatedBy,
        CreatedAt: time.Now(),
        MaxUses:   req.MaxUses,
        Uses:      0,
    }

    if req.ExpiresIn > 0 {
        expiry := time.Now().Add(time.Duration(req.ExpiresIn) * time.Hour)
        invite.ExpiresAt = &expiry
    }

    user.Mu.Lock()
    user.Invites[code] = invite
    user.Mu.Unlock()

    json.NewEncoder(w).Encode(map[string]interface{}{
        "invite_code": code,
        "expires_at":  invite.ExpiresAt,
        "max_uses":    invite.MaxUses,
    })
}

func GetInvitesHandler(w http.ResponseWriter, r *http.Request) {
    user.Mu.RLock()
    defer user.Mu.RUnlock()

    invites := make([]*user.Invite, 0, len(user.Invites))
    for _, invite := range user.Invites {
        invites = append(invites, invite)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "invites": invites,
        "count":   len(invites),
    })
}

// DeleteInviteHandler deletes an invite
func DeleteInviteHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Invite code is required", http.StatusBadRequest)
        return
    }

    user.Mu.Lock()
    defer user.Mu.Unlock()

    if _, exists := user.Invites[code]; !exists {
        http.Error(w, "Invite not found", http.StatusNotFound)
        return
    }

    delete(user.Invites, code)

    // Also delete from database
    if err := user.DeleteInviteFromDB(code); err != nil {
        // Log error but don't fail the request since it's already deleted from memory
        log.Printf("Error deleting invite from database: %v", err)
    }

    json.NewEncoder(w).Encode(map[string]string{
        "message": "Invite deleted successfully",
    })
}
