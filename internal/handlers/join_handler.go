package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"chat-server/internal/config"
	"chat-server/internal/user"
)

func JoinRequestHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username   string `json:"username"`
        Nickname   string `json:"nickname"`
        PublicKey  string `json:"public_key"`
        InviteCode string `json:"invite_code"`
    }
    _ = json.NewDecoder(r.Body).Decode(&req)

    // Validate invite code
    user.Mu.Lock()
    invite, exists := user.Invites[req.InviteCode]
    if !exists {
        user.Mu.Unlock()
        http.Error(w, "Invalid invite code", http.StatusBadRequest)
        return
    }

    // Check if invite is expired
    if invite.ExpiresAt != nil && time.Now().After(*invite.ExpiresAt) {
        delete(user.Invites, req.InviteCode)
        user.Mu.Unlock()
        http.Error(w, "Invite code expired", http.StatusBadRequest)
        return
    }

    // Check if invite has reached max uses
    if invite.MaxUses > 0 && invite.Uses >= invite.MaxUses {
        delete(user.Invites, req.InviteCode)
        user.Mu.Unlock()
        http.Error(w, "Invite code exhausted", http.StatusBadRequest)
        return
    }

    // Increment invite usage
    invite.Uses++
    user.Mu.Unlock()

    pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
    if err != nil || len(pubKey) != ed25519.PublicKeySize {
        http.Error(w, "Invalid public key", http.StatusBadRequest)
        return
    }

    nonce := make([]byte, 32)
    rand.Read(nonce)

    user.Mu.Lock()
    user.Challenges[req.Username] = &user.JoinChallenge{
        Nonce:     nonce,
        PublicKey: pubKey,
        Nickname:  req.Nickname, // Store nickname in challenge
    }
    user.Mu.Unlock()

    // Include server metadata in the response
    json.NewEncoder(w).Encode(map[string]interface{}{
        "challenge": base64.StdEncoding.EncodeToString(nonce),
        "server": map[string]interface{}{
            "name":         config.Conf.Name,
            "description":  config.Conf.Description,
            "allow_invite": config.Conf.AllowInvite,
            "max_users":    config.Conf.MaxUsers,
            "icon":         config.Conf.Icon,
        },
    })
}