package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"time"
)

var (
    // Set during build time using ldflags
    Version   = "dev"
    BuildTime = "unknown"
    GitCommit = "unknown"
    GoVersion = runtime.Version()
)

var serverStartTime = time.Now()

type TechnicalMetadata struct {
    Version     string            `json:"version"`
    BuildTime   string            `json:"build_time"`
    GitCommit   string            `json:"git_commit"`
    GoVersion   string            `json:"go_version"`
    OS          string            `json:"os"`
    Arch        string            `json:"arch"`
    Uptime      string            `json:"uptime"`
    UptimeMs    int64             `json:"uptime_ms"`
    StartTime   time.Time         `json:"start_time"`
    Environment map[string]string `json:"environment,omitempty"`
    Runtime     RuntimeInfo       `json:"runtime"`
}

type RuntimeInfo struct {
    NumCPU       int   `json:"num_cpu"`
    NumGoroutine int   `json:"num_goroutine"`
    MemoryMB     int64 `json:"memory_mb"`
    GCCycles     int64 `json:"gc_cycles"`
}

func GetTechnicalMetadataHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    uptime := time.Since(serverStartTime)

    // Get memory stats
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)

    // Get environment variables (filtered for security)
    env := make(map[string]string)
    if os.Getenv("RELAY_DEBUG") == "true" {
        env["RELAY_DEBUG"] = "true"
        env["GO_ENV"] = os.Getenv("GO_ENV")
        env["HOSTNAME"] = os.Getenv("HOSTNAME")
    }

    metadata := TechnicalMetadata{
        Version:     Version,
        BuildTime:   BuildTime,
        GitCommit:   GitCommit,
        GoVersion:   GoVersion,
        OS:          runtime.GOOS,
        Arch:        runtime.GOARCH,
        Uptime:      uptime.String(),
        UptimeMs:    uptime.Milliseconds(),
        StartTime:   serverStartTime,
        Environment: env,
        Runtime: RuntimeInfo{
            NumCPU:       runtime.NumCPU(),
            NumGoroutine: runtime.NumGoroutine(),
            MemoryMB:     int64(memStats.Alloc / 1024 / 1024),
            GCCycles:     int64(memStats.NumGC),
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metadata)
}