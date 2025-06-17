package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"relay-server/internal/user"
	"relay-server/internal/websocket"
)

type KickUserRequest struct {
    UserID string `json:"user_id"`
    Reason string `json:"reason,omitempty"`
}

type BanUserRequest struct {
    UserID   string `json:"user_id"`
    Reason   string `json:"reason,omitempty"`
    Duration string `json:"duration,omitempty"` // e.g., "24h", "7d", empty for permanent
}

// KickUserHandler kicks a user from the server
func KickUserHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req KickUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if req.UserID == "" {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    // Get the requesting user from context
    requestingUserID := r.Context().Value("user_id").(string)
    requestingUser := r.Context().Value("user").(*user.User)

    user.Mu.Lock()
    defer user.Mu.Unlock()

    // Check if target user exists
    targetUser, exists := user.Users[req.UserID]
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Prevent self-kick
    if req.UserID == requestingUserID {
        http.Error(w, "Cannot kick yourself", http.StatusBadRequest)
        return
    }

    // Check rank hierarchy - can't kick users with higher or equal rank
    if targetUser.GetHighestRank() >= requestingUser.GetHighestRank() {
        http.Error(w, "Cannot kick users with higher or equal rank", http.StatusForbidden)
        return
    }

    // Prevent kicking the owner
    if targetUser.HasRole("owner") {
        http.Error(w, "Cannot kick the server owner", http.StatusForbidden)
        return
    }

    // Force disconnect the user
    websocket.GlobalHub.DisconnectUser(req.UserID)

    // Delete user from memory and database (same as LeaveServerHandler)
    delete(user.Users, req.UserID)

    if err := user.DeleteUserFromDB(req.UserID); err != nil {
        // Re-add user back to memory if database deletion fails
        user.Users[req.UserID] = targetUser
        http.Error(w, "Failed to kick user", http.StatusInternalServerError)
        return
    }

    reason := req.Reason
    if reason == "" {
        reason = "No reason provided"
    }

    // Broadcast kick event
    go func() {
        websocket.GlobalHub.BroadcastMessage("user_kicked", map[string]interface{}{
            "user_id":    req.UserID,
            "username":   targetUser.Username,
            "nickname":   targetUser.Nickname,
            "kicked_by":  requestingUserID,
            "reason":     reason,
        })
    }()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":  "User kicked successfully",
        "user_id":  req.UserID,
        "username": targetUser.Username,
        "reason":   reason,
    })
}

// BanUserHandler bans a user from the server
func BanUserHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req BanUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if req.UserID == "" {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }

    // Get the requesting user from context
    requestingUserID := r.Context().Value("user_id").(string)
    requestingUser := r.Context().Value("user").(*user.User)

    user.Mu.Lock()
    defer user.Mu.Unlock()

    // Check if target user exists
    targetUser, exists := user.Users[req.UserID]
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Prevent self-ban
    if req.UserID == requestingUserID {
        http.Error(w, "Cannot ban yourself", http.StatusBadRequest)
        return
    }

    // Check rank hierarchy - can't ban users with higher or equal rank
    if targetUser.GetHighestRank() >= requestingUser.GetHighestRank() {
        http.Error(w, "Cannot ban users with higher or equal rank", http.StatusForbidden)
        return
    }

    // Prevent banning the owner
    if targetUser.HasRole("owner") {
        http.Error(w, "Cannot ban the server owner", http.StatusForbidden)
        return
    }

    // Extract IP address from WebSocket connections or use a placeholder
    ipAddress := "unknown"
    if connInfo := websocket.GlobalHub.GetUserConnectionInfo(req.UserID); connInfo != nil {
        ipAddress = connInfo.IPAddress
    }

    // Parse duration if provided
    var duration *time.Duration
    if req.Duration != "" {
        if parsedDuration, err := time.ParseDuration(req.Duration); err == nil {
            duration = &parsedDuration
        } else {
            http.Error(w, "Invalid duration format", http.StatusBadRequest)
            return
        }
    }

    reason := req.Reason
    if reason == "" {
        reason = "No reason provided"
    }

    // Create ban record
    if err := user.CreateBan(req.UserID, targetUser.Username, ipAddress, requestingUserID, reason, duration); err != nil {
        http.Error(w, "Failed to create ban record", http.StatusInternalServerError)
        return
    }

    // Force disconnect the user
    websocket.GlobalHub.DisconnectUser(req.UserID)

    // Delete user from memory and database
    delete(user.Users, req.UserID)

    if err := user.DeleteUserFromDB(req.UserID); err != nil {
        // Re-add user back to memory if database deletion fails
        user.Users[req.UserID] = targetUser
        http.Error(w, "Failed to ban user", http.StatusInternalServerError)
        return
    }

    // Broadcast ban event
    go func() {
        websocket.GlobalHub.BroadcastMessage("user_banned", map[string]interface{}{
            "user_id":   req.UserID,
            "username":  targetUser.Username,
            "nickname":  targetUser.Nickname,
            "banned_by": requestingUserID,
            "reason":    reason,
            "duration":  req.Duration,
        })
    }()

    response := map[string]interface{}{
        "message":  "User banned successfully",
        "user_id":  req.UserID,
        "username": targetUser.Username,
        "reason":   reason,
    }

    if duration != nil {
        response["duration"] = req.Duration
        response["expires_at"] = time.Now().Add(*duration)
    } else {
        response["permanent"] = true
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// UnbanUserHandler removes a ban from a user
func UnbanUserHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    ipAddress := r.URL.Query().Get("ip")
    if ipAddress == "" {
        http.Error(w, "IP address is required", http.StatusBadRequest)
        return
    }

    if err := user.RemoveBan(ipAddress); err != nil {
        http.Error(w, "Failed to remove ban", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "User unbanned successfully",
    })
}

// GetBansHandler returns all active bans
func GetBansHandler(w http.ResponseWriter, r *http.Request) {
    user.BanMu.RLock()
    defer user.BanMu.RUnlock()

    bans := make([]map[string]interface{}, 0, len(user.BannedIPs))
    for _, ban := range user.BannedIPs {
        banInfo := map[string]interface{}{
            "user_id":    ban.UserID,
            "username":   ban.Username,
            "ip_address": ban.IPAddress,
            "banned_by":  ban.BannedBy,
            "reason":     ban.Reason,
            "banned_at":  ban.BannedAt,
            "permanent":  ban.ExpiresAt == nil,
        }

        if ban.ExpiresAt != nil {
            banInfo["expires_at"] = *ban.ExpiresAt
        }

        bans = append(bans, banInfo)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "bans":  bans,
        "count": len(bans),
    })
}