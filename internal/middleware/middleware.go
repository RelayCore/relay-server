package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"relay-server/internal/user"
)

type RateLimiter struct {
    tokens    int
    capacity  int
    refillRate time.Duration
    lastRefill time.Time
    mutex     sync.Mutex
}

func CORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if (r.Method != "OPTIONS") {
            log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
        }

        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Handle preflight OPTIONS requests
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
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

// getUserFromAuth extracts user ID from Authorization header or query param
func getUserFromAuth(r *http.Request) string {
    // Try Authorization header first (Bearer token format)
    auth := r.Header.Get("Authorization")
    if auth != "" && strings.HasPrefix(auth, "Bearer ") {
        return strings.TrimPrefix(auth, "Bearer ")
    }

    // Fallback to query parameter
    return r.URL.Query().Get("user_id")
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
