package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"relay-server/internal/middleware"
	"strings"
	"syscall"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/metrics"
	"relay-server/internal/websocket"

	"relay-server/internal/config"
	"relay-server/internal/handlers"
	"relay-server/internal/user"
)

var (
    NoCache        = middleware.CacheControl(0, "no-cache")
    Cache30Sec     = middleware.CacheControl(30*time.Second, "private")
    Cache1Min      = middleware.CacheControl(1*time.Minute, "private")
    Cache2Min      = middleware.CacheControl(2*time.Minute, "private")
    Cache5Min      = middleware.CacheControl(5*time.Minute, "private")
    Cache10Min     = middleware.CacheControl(10*time.Minute, "private")
    Cache1Hour     = middleware.CacheControl(1*time.Hour, "public")
    Cache24Hour    = middleware.CacheControl(24*time.Hour, "public")
    CacheImmutable = middleware.CacheControl(365*24*time.Hour, "immutable")
)

// Fully public
func publicRoute(mux *http.ServeMux, path string, rateLimit *middleware.RateLimitStore, cacheMiddleware func(http.HandlerFunc) http.HandlerFunc, handler http.HandlerFunc) {
    mux.HandleFunc(path, middleware.RateLimitFunc(rateLimit, false)(cacheMiddleware(middleware.TrackOutboundData(handler))))
}

// Require bearer token authentication
func authRoute(mux *http.ServeMux, path string, rateLimit *middleware.RateLimitStore, cacheMiddleware func(http.HandlerFunc) http.HandlerFunc, handler http.HandlerFunc) {
    mux.HandleFunc(path, middleware.RateLimitFunc(rateLimit, true)(cacheMiddleware(middleware.RequireAuth(middleware.TrackOutboundData(handler)))))
}

// Require specific user permissions and bearer token authentication
func permissionRoute(mux *http.ServeMux, path string, rateLimit *middleware.RateLimitStore, permission user.Permission, cacheMiddleware func(http.HandlerFunc) http.HandlerFunc, handler http.HandlerFunc) {
    mux.HandleFunc(path, middleware.RateLimitFunc(rateLimit, true)(cacheMiddleware(middleware.RequirePermission(permission)(middleware.TrackOutboundData(handler)))))
}

func main() {
    config.LoadConfig("config.yaml")
    user.Roles.InitializeDefaultRoles()

    err := db.Init()
    if err != nil {
        log.Fatal("DB init failed:", err)
    }

    db.DB.AutoMigrate(
        &channel.Group{},
        &channel.Channel{},
        &channel.Message{},
		&channel.Attachment{},
        &channel.ChannelPermission{},
        &channel.UserTag{},
        &user.UserModel{},
        &user.InviteModel{},
        &user.RoleModel{},
        &user.Ban{},
        &metrics.MetricsSnapshot{},
        &metrics.MetricsHourly{},
    )

    metricsService := metrics.NewMetricsService()
    handlers.MetricsService = metricsService
    metricsService.Start()

    user.LoadUsersFromDB()
    user.LoadInvitesFromDB()
    user.Roles.LoadRolesFromDB()
    user.LoadBansFromDB()
    createDefaultChannelIfNeeded()

    // Graceful shutdown
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        log.Println("Shutting down server...")
        metricsService.Stop()
        os.Exit(0)
    }()

    go websocket.GlobalHub.Run()

    mux := http.NewServeMux()

    // Public endpoints
    publicRoute(mux, "/join", middleware.AuthRateLimit, NoCache, handlers.JoinRequestHandler)
    publicRoute(mux, "/auth", middleware.AuthRateLimit, NoCache, handlers.AuthChallengeHandler)
    publicRoute(mux, "/server", middleware.GlobalRateLimit, Cache1Hour, handlers.GetServerMetadataHandler)

    // Technical metadata endpoint
    authRoute(mux, "/server/tech", middleware.GlobalRateLimit, Cache5Min, handlers.GetTechnicalMetadataHandler)
    authRoute(mux, "/server/metrics", middleware.GlobalRateLimit, Cache5Min, handlers.GetMetricsHandler)

    // Static file serving for uploads
    mux.Handle("/uploads/", middleware.CacheControl(24*time.Hour, "public")(http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads/"))).ServeHTTP))
    // Server icon endpoint
    publicRoute(mux, "/icon", middleware.GlobalRateLimit, Cache24Hour, handlers.GetServerIconHandler)
    // WebSocket endpoint
    mux.HandleFunc("/ws", websocket.HandleWebSocket)

    // User management endpoints - viewing users should be accessible to all
    authRoute(mux, "/users", middleware.GlobalRateLimit, Cache2Min, handlers.GetUsersHandler)
    authRoute(mux, "/user", middleware.GlobalRateLimit, Cache5Min, handlers.GetUserHandler)
    authRoute(mux, "/user/nickname", middleware.GlobalRateLimit, NoCache, handlers.UpdateNicknameHandler)
    authRoute(mux, "/user/profile-picture", middleware.GlobalRateLimit, NoCache, handlers.UploadProfilePictureHandler)
    authRoute(mux, "/user/leave", middleware.GlobalRateLimit, NoCache, handlers.LeaveServerHandler)
    authRoute(mux, "/user/tags", middleware.GlobalRateLimit, Cache5Min, handlers.GetUserTagsHandler)
    authRoute(mux, "/user/tags/read", middleware.GlobalRateLimit, Cache5Min, handlers.MarkTagAsReadHandler)
    authRoute(mux, "/user/tags/read-all", middleware.GlobalRateLimit, Cache5Min, handlers.MarkAllTagsAsReadHandler)
    authRoute(mux, "/user/tags/unread-count", middleware.GlobalRateLimit, Cache5Min, handlers.GetUnreadTagCountHandler)

    // Role management endpoints
    permissionRoute(mux, "/roles", middleware.GlobalRateLimit, user.PermissionManageRoles, NoCache, handlers.CreateRoleHandler)
    permissionRoute(mux, "/roles/update", middleware.GlobalRateLimit, user.PermissionManageRoles, NoCache, handlers.UpdateRoleHandler)
    permissionRoute(mux, "/roles/delete", middleware.GlobalRateLimit, user.PermissionManageRoles, NoCache, handlers.DeleteRoleHandler)
    authRoute(mux, "/roles/list", middleware.GlobalRateLimit, Cache10Min, handlers.GetRolesHandler)
    permissionRoute(mux, "/roles/assign", middleware.GlobalRateLimit, user.PermissionAssignRoles, NoCache, handlers.AssignRoleHandler)
    permissionRoute(mux, "/roles/remove", middleware.GlobalRateLimit, user.PermissionAssignRoles, NoCache, handlers.RemoveRoleHandler)

    // Channel management endpoints
    authRoute(mux, "/channels", middleware.GlobalRateLimit, Cache2Min, handlers.GetChannelsHandler)
    permissionRoute(mux, "/channels/create", middleware.GlobalRateLimit, user.PermissionCreateChannels, NoCache, handlers.CreateChannelHandler)
    permissionRoute(mux, "/channels/update", middleware.GlobalRateLimit, user.PermissionManageChannels, NoCache, handlers.UpdateChannelHandler)
    permissionRoute(mux, "/channels/delete", middleware.GlobalRateLimit, user.PermissionManageChannels, NoCache, handlers.DeleteChannelHandler)
    authRoute(mux, "/channels/messages", middleware.GlobalRateLimit, Cache30Sec, handlers.GetChannelMessagesHandler)
    authRoute(mux, "/channels/messages/around", middleware.GlobalRateLimit, Cache30Sec, handlers.GetMessagesAroundHandler)
    authRoute(mux, "/attachments", middleware.GlobalRateLimit, Cache1Min, handlers.GetAllAttachmentsHandler)
    authRoute(mux, "/attachments/stats", middleware.GlobalRateLimit, Cache5Min, handlers.GetAttachmentStatsHandler)

    // Channel permission management endpoints
    authRoute(mux, "/channels/permissions", middleware.GlobalRateLimit, Cache5Min, handlers.GetChannelPermissionsHandler)
    authRoute(mux, "/channels/permissions/set", middleware.GlobalRateLimit, NoCache, handlers.SetChannelPermissionHandler)
    authRoute(mux, "/channels/permissions/delete", middleware.GlobalRateLimit, NoCache, handlers.DeleteChannelPermissionHandler)

    permissionRoute(mux, "/groups/create", middleware.GlobalRateLimit, user.PermissionCreateChannels, NoCache, handlers.CreateGroupHandler)

    // Voice endpoints
    authRoute(mux, "/voice/join", middleware.GlobalRateLimit, NoCache, handlers.JoinVoiceHandler)
    authRoute(mux, "/voice/leave", middleware.GlobalRateLimit, NoCache, handlers.LeaveVoiceHandler)
    authRoute(mux, "/voice/state", middleware.GlobalRateLimit, NoCache, handlers.UpdateVoiceStateHandler)
    authRoute(mux, "/voice/participants", middleware.GlobalRateLimit, NoCache, handlers.GetVoiceParticipantsHandler)
    authRoute(mux, "/voice/rooms", middleware.GlobalRateLimit, Cache1Min, handlers.GetVoiceRoomsHandler)

    // Message endpoints with specific message rate limiting
    permissionRoute(mux, "/messages/send", middleware.MessageRateLimit, user.PermissionSendMessages, NoCache, handlers.SendMessageHandler)
    authRoute(mux, "/messages/delete", middleware.GlobalRateLimit, NoCache, handlers.DeleteMessageHandler)
    authRoute(mux, "/messages/edit", middleware.GlobalRateLimit, NoCache, handlers.EditMessageHandler)
    authRoute(mux, "/messages/pin", middleware.GlobalRateLimit, NoCache, handlers.PinMessageHandler)
    authRoute(mux, "/messages/unpin", middleware.GlobalRateLimit, NoCache, handlers.UnpinMessageHandler)
    authRoute(mux, "/messages/pinned", middleware.GlobalRateLimit, Cache1Min, handlers.GetPinnedMessagesHandler)
    authRoute(mux, "/messages/search", middleware.GlobalRateLimit, Cache5Min, handlers.SearchMessagesHandler)
    authRoute(mux, "/messages/replies", middleware.GlobalRateLimit, Cache30Sec, handlers.GetMessageRepliesHandler)

    // Invite management endpoints
    permissionRoute(mux, "/create-invite", middleware.InviteRateLimit, user.PermissionCreateInvites, NoCache, handlers.CreateInviteHandler)
    permissionRoute(mux, "/invites", middleware.GlobalRateLimit, user.PermissionManageInvites, NoCache, handlers.GetInvitesHandler)
    permissionRoute(mux, "/invites/delete", middleware.GlobalRateLimit, user.PermissionManageInvites, NoCache, handlers.DeleteInviteHandler)

    // Server management endpoints
    permissionRoute(mux, "/server/icon", middleware.GlobalRateLimit, user.PermissionManageServer, Cache10Min, handlers.UploadServerIconHandler)
    permissionRoute(mux, "/server/config", middleware.GlobalRateLimit, user.PermissionManageServer, NoCache, handlers.UpdateServerConfigHandler)

    // Moderation endpoints
    permissionRoute(mux, "/moderation/kick", middleware.GlobalRateLimit, user.PermissionKickUsers, NoCache, handlers.KickUserHandler)
    permissionRoute(mux, "/moderation/ban", middleware.GlobalRateLimit, user.PermissionBanUsers, NoCache, handlers.BanUserHandler)
    permissionRoute(mux, "/moderation/unban", middleware.GlobalRateLimit, user.PermissionBanUsers, NoCache, handlers.UnbanUserHandler)
    permissionRoute(mux, "/moderation/bans", middleware.GlobalRateLimit, user.PermissionBanUsers, Cache5Min, handlers.GetBansHandler)

    // Tenor API endpoints
    authRoute(mux, "/tenor/search", middleware.GlobalRateLimit, Cache1Min, handlers.TenorSearchHandler)
    authRoute(mux, "/tenor/trending", middleware.GlobalRateLimit, Cache2Min, handlers.TenorTrendingHandler)
    authRoute(mux, "/tenor/categories", middleware.GlobalRateLimit, Cache10Min, handlers.TenorCategoriesHandler)

    // Check for first-time setup after everything is initialized
    go func() {
        time.Sleep(5 * time.Second) // Give time for any existing auth processes
        user.Mu.RLock()
        userCount := len(user.Users)
        user.Mu.RUnlock()

        if userCount == 0 {
            createFirstTimeInvite()
        }
    }()

    logServerConnectionInfo()

    certFile := "cert.pem"
    keyFile := "key.pem"

    if _, errCert := os.Stat(certFile); errCert == nil {
        if _, errKey := os.Stat(keyFile); errKey == nil {
            log.Printf("Starting HTTPS server on %s", config.Conf.Port)
            log.Fatal(http.ListenAndServeTLS(config.Conf.Port, certFile, keyFile, middleware.CORS(mux)))
        }
    }

    log.Printf("WARNING: TLS certificate or key not found. Starting HTTP server on %s. This is INSECURE and should only be used for development or testing.", config.Conf.Port)
    log.Fatal(http.ListenAndServe(config.Conf.Port, middleware.CORS(mux)))
}

func createDefaultChannelIfNeeded() {
    var groupCount int64
    if err := db.DB.Model(&channel.Group{}).Count(&groupCount).Error; err != nil {
        log.Printf("Failed to count groups: %v", err)
        return
    }

    if groupCount == 0 {
        // Create default group
        defaultGroup := &channel.Group{
            Name: "General",
        }

        if err := db.DB.Create(defaultGroup).Error; err != nil {
            log.Printf("Failed to create default group: %v", err)
            return
        }

        // Create default text channel
        defaultChannel := &channel.Channel{
            Name:        "general",
            Description: "General discussion channel",
            GroupID:     defaultGroup.ID,
            Position:    0,
            Type:        channel.ChannelTypeText,
        }

        if err := db.DB.Create(defaultChannel).Error; err != nil {
            log.Printf("Failed to create default channel: %v", err)
            return
        }

        log.Printf("Created default group '%s' and channel '%s'", defaultGroup.Name, defaultChannel.Name)
    }
}

func logServerConnectionInfo() {
    port := strings.TrimPrefix(config.Conf.Port, ":")
    if port == "" {
        port = "36954" // default fallback
    }

    log.Printf("═══════════════════════════════════════════════════════════════")
    log.Printf("  SERVER CONNECTION INFORMATION")
    log.Printf("───────────────────────────────────────────────────────────────")

    // Local connections
    log.Printf("Local connections:")
    log.Printf("   • http://localhost:%s", port)
    log.Printf("   • http://127.0.0.1:%s", port)

    if config.Conf.Domain != "" {
        scheme := "http"
        certFile := "cert.pem"
        keyFile := "key.pem"
        if _, errCert := os.Stat(certFile); errCert == nil {
            if _, errKey := os.Stat(keyFile); errKey == nil {
                scheme = "https"
            }
        }
        log.Printf("Domain connection:")
        log.Printf("   • %s://%s", scheme, config.Conf.Domain)
    }

    // Network interfaces
    log.Printf("Network connections:")
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        log.Printf("   ⚠️  Could not determine network addresses: %v", err)
    } else {
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                if ipnet.IP.To4() != nil { // IPv4
                    log.Printf("   • http://%s:%s", ipnet.IP.String(), port)
                }
            }
        }
    }

    // Public IP (external)
    resp, err := http.Get("https://api.ipify.org")
    if err == nil {
        defer resp.Body.Close()
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Public (external) address:")
        log.Printf("   • http://%s:%s", strings.TrimSpace(string(body)), port)
    } else {
        log.Printf("   ⚠️  Could not determine public IP: %v", err)
    }

    log.Printf("═══════════════════════════════════════════════════════════════")
}

func createFirstTimeInvite() {
    // Generate temporary invite code for server owner
    codeBytes := make([]byte, 16)
    rand.Read(codeBytes)
    tempInviteCode := hex.EncodeToString(codeBytes)

    // Create temporary invite that expires in 24 hours and can only be used once
    expiry := time.Now().Add(24 * time.Hour)
    tempInvite := &user.Invite{
        Code:      tempInviteCode,
        CreatedBy: "system",
        CreatedAt: time.Now(),
        ExpiresAt: &expiry,
        MaxUses:   1,
        Uses:      0,
    }

    user.Mu.Lock()
    if user.Invites == nil {
        user.Invites = make(map[string]*user.Invite)
    }
    user.Invites[tempInviteCode] = tempInvite
    user.Mu.Unlock()

    log.Printf("\n═══════════════════════════════════════════════════════════════")
    log.Printf("SERVER SETUP - FIRST TIME LAUNCH DETECTED")
    log.Printf("───────────────────────────────────────────────────────────────")
    log.Printf("No users found in the server. A temporary invite has been created")
    log.Printf("for the server owner to join and set up the server.")
    log.Printf("")
    log.Printf("  TEMPORARY INVITE CODE: %s", tempInviteCode)
    log.Printf("  Expires: %s", expiry.Format("2006-01-02 15:04:05"))
    log.Printf("  Max Uses: 1 (single use only)")
    log.Printf("")
    log.Printf("  IMPORTANT:")
    log.Printf("• This invite will expire in 24 hours")
    log.Printf("• It can only be used once")
    log.Printf("• The first user to join will have the 'owner' role")
    log.Printf("═══════════════════════════════════════════════════════════════")
}