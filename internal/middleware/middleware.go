package middleware

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relay-server/internal/user"
)

var (
    TotalBytesOut int64
    TotalRequests int64
)

type RateLimiter struct {
    tokens    int
    capacity  int
    refillRate time.Duration
    lastRefill time.Time
    mutex     sync.Mutex
}

type ResponseWriter struct {
    http.ResponseWriter
    bytesWritten int64
    statusCode   int
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
    n, err := rw.ResponseWriter.Write(b)
    atomic.AddInt64(&rw.bytesWritten, int64(n))
    return n, err
}

func (rw *ResponseWriter) WriteHeader(statusCode int) {
    rw.statusCode = statusCode
    rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *ResponseWriter) BytesWritten() int64 {
    return atomic.LoadInt64(&rw.bytesWritten)
}

func TrackOutboundData(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        rw := &ResponseWriter{ResponseWriter: w, statusCode: 200}

        start := time.Now()
        next.ServeHTTP(rw, r)
        duration := time.Since(start)

        bytesWritten := rw.BytesWritten()
        atomic.AddInt64(&TotalBytesOut, bytesWritten)
        atomic.AddInt64(&TotalRequests, 1)

        if bytesWritten > 0 {
            log.Printf("HTTP %s %s - %d bytes - %d status - %v duration",
                r.Method, r.URL.Path, bytesWritten, rw.statusCode, duration)
        }
    }
}

func GetClientName(r *http.Request) string {
    return r.Header.Get("X-Client-Name")
}

func GetClientVersion(r *http.Request) string {
    return r.Header.Get("X-Client-Version")
}

func GetClientPlatform(r *http.Request) string {
    return r.Header.Get("X-Client-Platform")
}

func GetClientTimestamp(r *http.Request) string {
    return r.Header.Get("X-Client-Timestamp")
}

func GetClientMetadata(r *http.Request) map[string]string {
    return map[string]string{
        "name":      GetClientName(r),
        "version":   GetClientVersion(r),
        "platform":  GetClientPlatform(r),
        "timestamp": GetClientTimestamp(r),
    }
}

func GetClientInfo(r *http.Request) string {
    platform := GetClientPlatform(r)
    version := GetClientVersion(r)

    if platform == "" && version == "" {
        return ""
    }

    var parts []string
    if platform != "" {
        parts = append(parts, platform)
    }
    if version != "" {
        parts = append(parts, version)
    }

    return strings.Join(parts, "/")
}

func CORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if (r.Method != "OPTIONS") {
            logMsg := fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

            if clientInfo := GetClientInfo(r); clientInfo != "" {
                logMsg += fmt.Sprintf(" [%s]", clientInfo)
            }

            log.Print(logMsg)
        }

        clientIP := GetClientIP(r)
        if ban, isBanned := user.IsIPBanned(clientIP); isBanned {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "error":     "Access denied",
                "banned_at": ban.BannedAt,
                "reason":    ban.Reason,
            })
            return
        }

        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-Name, X-Client-Version, X-Client-Platform, X-Client-Timestamp")

        // Handle preflight OPTIONS requests
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func GetClientIP(r *http.Request) string {
    // Check X-Forwarded-For header first (for proxies)
    forwarded := r.Header.Get("X-Forwarded-For")
    if forwarded != "" {
        // Take the first IP if multiple are present
        ips := strings.Split(forwarded, ",")
        return strings.TrimSpace(ips[0])
    }

    // Check X-Real-IP header
    realIP := r.Header.Get("X-Real-IP")
    if realIP != "" {
        return realIP
    }

    // Fallback to RemoteAddr, removing port if present
    ip := r.RemoteAddr
    if colonPos := strings.LastIndex(ip, ":"); colonPos != -1 {
        ip = ip[:colonPos]
    }

    return ip
}

// RequireAuth middleware checks if user is authenticated
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userID := getUserFromAuth(r)
        if userID == "" {
            http.Error(w, "Authentication required", http.StatusUnauthorized)
            return
        }

        user.Mu.RLock()
        userObj, exists := user.Users[userID]
        user.Mu.RUnlock()

        if !exists {
            http.Error(w, "User not found", http.StatusUnauthorized)
            return
        }

        // Add user to request context
        ctx := context.WithValue(r.Context(), "user", userObj)
        ctx = context.WithValue(ctx, "user_id", userID)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

// RequirePermission middleware checks if user has required permission
func RequirePermission(permission user.Permission) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return RequireAuth(func(w http.ResponseWriter, r *http.Request) {
            userObj := r.Context().Value("user").(*user.User)

            if !userObj.HasPermission(permission) {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// RequireRole middleware checks if user has required role
func RequireRole(roleID string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return RequireAuth(func(w http.ResponseWriter, r *http.Request) {
            userObj := r.Context().Value("user").(*user.User)

            if !userObj.HasRole(roleID) {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// RequireMinimumRank middleware checks if user has minimum rank
func RequireMinimumRank(minRank int) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return RequireAuth(func(w http.ResponseWriter, r *http.Request) {
            userObj := r.Context().Value("user").(*user.User)

            if userObj.GetHighestRank() < minRank {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func getUserFromAuth(r *http.Request) string {
    var publicKeyB64 string

    // Try Authorization header first (Bearer token format)
    auth := r.Header.Get("Authorization")
    if auth != "" && strings.HasPrefix(auth, "Bearer ") {
        publicKeyB64 = strings.TrimPrefix(auth, "Bearer ")
    } else {
        // Fallback to cookie
        if cookie, err := r.Cookie("auth_token"); err == nil {
            publicKeyB64 = cookie.Value
        }
    }

    if publicKeyB64 == "" {
        return ""
    }

    // Decode the base64 public key
    publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
    if err != nil {
        // Try URL-safe base64 if standard fails
        publicKeyBytes, err = base64.URLEncoding.DecodeString(publicKeyB64)
        if err != nil {
            return ""
        }
    }

    if len(publicKeyBytes) != ed25519.PublicKeySize {
        return ""
    }

    publicKey := ed25519.PublicKey(publicKeyBytes)

    // Find user by public key
    user.Mu.RLock()
    defer user.Mu.RUnlock()

    for userID, u := range user.Users {
        if string(u.PublicKey) == string(publicKey) {
            return userID
        }
    }

    return ""
}

func NewRateLimiter(capacity int, refillRate time.Duration) *RateLimiter {
    return &RateLimiter{
        tokens:     capacity,
        capacity:   capacity,
        refillRate: refillRate,
        lastRefill: time.Now(),
    }
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow() bool {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()

    now := time.Now()
    elapsed := now.Sub(rl.lastRefill)

    // Refill tokens based on elapsed time
    tokensToAdd := int(elapsed / rl.refillRate)
    if tokensToAdd > 0 {
        rl.tokens += tokensToAdd
        if rl.tokens > rl.capacity {
            rl.tokens = rl.capacity
        }
        rl.lastRefill = now
    }

    // Check if we have tokens available
    if rl.tokens > 0 {
        rl.tokens--
        return true
    }

    return false
}

// RateLimitStore manages rate limiters for different keys (IP addresses, user IDs, etc.)
type RateLimitStore struct {
    limiters map[string]*RateLimiter
    mutex    sync.RWMutex
    capacity int
    refillRate time.Duration
    cleanup  time.Duration
}

// NewRateLimitStore creates a new rate limit store
func NewRateLimitStore(capacity int, refillRate time.Duration) *RateLimitStore {
    store := &RateLimitStore{
        limiters:   make(map[string]*RateLimiter),
        capacity:   capacity,
        refillRate: refillRate,
        cleanup:    time.Minute * 10, // Clean up old limiters every 10 minutes
    }

    // Start cleanup goroutine
    go store.cleanupRoutine()

    return store
}

// GetLimiter gets or creates a rate limiter for a key
func (rls *RateLimitStore) GetLimiter(key string) *RateLimiter {
    rls.mutex.RLock()
    limiter, exists := rls.limiters[key]
    rls.mutex.RUnlock()

    if exists {
        return limiter
    }

    rls.mutex.Lock()
    defer rls.mutex.Unlock()

    // Double-check after acquiring write lock
    if limiter, exists := rls.limiters[key]; exists {
        return limiter
    }

    // Create new limiter
    limiter = NewRateLimiter(rls.capacity, rls.refillRate)
    rls.limiters[key] = limiter
    return limiter
}

// cleanupRoutine removes old, unused rate limiters
func (rls *RateLimitStore) cleanupRoutine() {
    ticker := time.NewTicker(rls.cleanup)
    defer ticker.Stop()

    for range ticker.C {
        rls.mutex.Lock()
        now := time.Now()
        for key, limiter := range rls.limiters {
            limiter.mutex.Lock()
            // Remove limiters that haven't been used for more than the cleanup interval
            if now.Sub(limiter.lastRefill) > rls.cleanup {
                delete(rls.limiters, key)
            }
            limiter.mutex.Unlock()
        }
        rls.mutex.Unlock()
    }
}

// Global rate limit stores for different types of limits
var (
    GlobalRateLimit = NewRateLimitStore(100, time.Minute/100)
    MessageRateLimit = NewRateLimitStore(10, time.Minute/10)
    AuthRateLimit = NewRateLimitStore(5, time.Minute/5)
    InviteRateLimit = NewRateLimitStore(3, time.Minute/10)
)

// getClientKey extracts a client identifier from the request (IP or user ID)
func getClientKey(r *http.Request, useUser bool) string {
    if useUser {
        if userID := getUserFromAuth(r); userID != "" {
            return "user:" + userID
        }
    }

    // Fallback to IP address
    ip := r.Header.Get("X-Forwarded-For")
    if ip == "" {
        ip = r.Header.Get("X-Real-IP")
    }
    if ip == "" {
        ip = r.RemoteAddr
    }
    return "ip:" + ip
}

// RateLimit middleware factory for general rate limiting
func RateLimit(store *RateLimitStore, useUser bool) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            key := getClientKey(r, useUser)
            limiter := store.GetLimiter(key)

            if !limiter.Allow() {
                w.Header().Set("X-RateLimit-Limit", strconv.Itoa(store.capacity))
                w.Header().Set("X-RateLimit-Remaining", "0")
                w.Header().Set("Retry-After", fmt.Sprintf("%.0f", store.refillRate.Seconds()))
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }

            // Add rate limit headers
            limiter.mutex.Lock()
            remaining := limiter.tokens
            limiter.mutex.Unlock()

            w.Header().Set("X-RateLimit-Limit", strconv.Itoa(store.capacity))
            w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

            next.ServeHTTP(w, r)
        })
    }
}

// RateLimitFunc middleware factory for handler functions
func RateLimitFunc(store *RateLimitStore, useUser bool) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            key := getClientKey(r, useUser)
            limiter := store.GetLimiter(key)

            if !limiter.Allow() {
                w.Header().Set("X-RateLimit-Limit", strconv.Itoa(store.capacity))
                w.Header().Set("X-RateLimit-Remaining", "0")
                w.Header().Set("Retry-After", fmt.Sprintf("%.0f", store.refillRate.Seconds()))
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }

            // Add rate limit headers
            limiter.mutex.Lock()
            remaining := limiter.tokens
            limiter.mutex.Unlock()

            w.Header().Set("X-RateLimit-Limit", strconv.Itoa(store.capacity))
            w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

            next.ServeHTTP(w, r)
        }
    }
}

func CacheControl(maxAge time.Duration, cacheType string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            switch cacheType {
            case "no-cache":
                w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
                w.Header().Set("Pragma", "no-cache")
                w.Header().Set("Expires", "0")
            case "private":
                w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(int(maxAge.Seconds())))
            case "public":
                w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
            case "immutable":
                w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds()))+", immutable")
            }

            next(w, r)
        }
    }
}

func NoCache(next http.HandlerFunc) http.HandlerFunc {
    return CacheControl(0, "no-cache")(next)
}

func StaticCache(next http.HandlerFunc) http.HandlerFunc {
    return CacheControl(24*time.Hour, "public")(next)
}

func SecureStaticFileServer(dir string) http.Handler {
    fs := http.FileServer(http.Dir(dir))
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.HasSuffix(r.URL.Path, "/") {
            http.NotFound(w, r)
            return
        }

        if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "%2e%2e") || strings.ContainsRune(r.URL.Path, 0) {
            http.Error(w, "Invalid path", http.StatusBadRequest)
            return
        }

        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Content-Disposition", "attachment")
        fs.ServeHTTP(w, r)
    })
}
