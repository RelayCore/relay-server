package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"chat-server/internal/user"
	"crypto/sha256"
)

func AuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username  string `json:"username"`
        Nickname  string `json:"nickname"`
        Signature string `json:"signature"`
    }

    _ = json.NewDecoder(r.Body).Decode(&req)

    user.Mu.RLock()
    challenge, ok := user.Challenges[req.Username]
    user.Mu.RUnlock()
    if !ok {
        http.Error(w, "Challenge not found", http.StatusBadRequest)
        return
    }

    sig, _ := base64.StdEncoding.DecodeString(req.Signature)
    if !ed25519.Verify(challenge.PublicKey, challenge.Nonce, sig) {
        http.Error(w, "Invalid signature", http.StatusUnauthorized)
        return
    }

    id := sha256.Sum256(challenge.PublicKey)
    idHex := hex.EncodeToString(id[:])

    user.Mu.Lock()
    existingUser, exists := user.Users[idHex]
    if exists {
        existingUser.Username = req.Username
        existingUser.Nickname = req.Nickname
        // Save updated user to database
        if err := user.SaveUserToDB(existingUser); err != nil {
            log.Printf("Error saving updated user to database: %v", err)
        }
    } else {
        // Check if this is the first user
        isFirstUser := len(user.Users) == 0

        // New user - assign appropriate role
        roleIDs := []string{"user"}
        if isFirstUser {
            roleIDs = []string{"admin"} // First user gets admin role
        }

        newUser := &user.User{
            Username:  req.Username,
            Nickname:  req.Nickname,
            PublicKey: challenge.PublicKey,
            RoleIDs:   roleIDs,
            ID:        idHex,
        }

        user.Users[idHex] = newUser

        // Save new user to database
        if err := user.SaveUserToDB(newUser); err != nil {
            log.Printf("Error saving new user to database: %v", err)
        }
    }
    delete(user.Challenges, req.Username)
    user.Mu.Unlock()

    json.NewEncoder(w).Encode(map[string]string{
        "message": "Authenticated",
        "user_id": idHex,
    })
}