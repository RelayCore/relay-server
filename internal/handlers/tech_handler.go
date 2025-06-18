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
    Usage       UsageInfo         `json:"usage"`
}

type RuntimeInfo struct {
    NumCPU       int   `json:"num_cpu"`
    NumGoroutine int   `json:"num_goroutine"`
    MemoryMB     int64 `json:"memory_mb"`
    GCCycles     int64 `json:"gc_cycles"`
}

type UsageInfo struct {
    Memory      MemoryUsage `json:"memory"`
    Goroutines  int         `json:"goroutines"`
    CGoCalls    int64       `json:"cgo_calls"`
    HeapObjects uint64      `json:"heap_objects"`
    GCPause     string      `json:"last_gc_pause"`
    NextGC      uint64      `json:"next_gc_mb"`
}

type MemoryUsage struct {
    AllocMB      uint64  `json:"alloc_mb"`
    TotalAllocMB uint64  `json:"total_alloc_mb"`
    SysMB        uint64  `json:"sys_mb"`
    HeapAllocMB  uint64  `json:"heap_alloc_mb"`
    HeapSysMB    uint64  `json:"heap_sys_mb"`
    HeapIdleMB   uint64  `json:"heap_idle_mb"`
    HeapInUseMB  uint64  `json:"heap_inuse_mb"`
    StackInUseMB uint64  `json:"stack_inuse_mb"`
    GCPercent    float64 `json:"gc_percent"`
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

    // Calculate GC percentage (heap in use vs heap sys)
    var gcPercent float64
    if memStats.HeapSys > 0 {
        gcPercent = float64(memStats.HeapInuse) / float64(memStats.HeapSys) * 100
    }

    // Get environment variables (filtered for security)
    env := make(map[string]string)
    if os.Getenv("RELAY_DEBUG") == "true" {
        env["RELAY_DEBUG"] = "true"
        env["GO_ENV"] = os.Getenv("GO_ENV")
        env["HOSTNAME"] = os.Getenv("HOSTNAME")
    }

    // Format last GC pause
    var lastGCPause string
    if len(memStats.PauseNs) > 0 {
        lastGCPause = time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256]).String()
    } else {
        lastGCPause = "0s"
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
        Usage: UsageInfo{
            Memory: MemoryUsage{
                AllocMB:      memStats.Alloc / 1024 / 1024,
                TotalAllocMB: memStats.TotalAlloc / 1024 / 1024,
                SysMB:        memStats.Sys / 1024 / 1024,
                HeapAllocMB:  memStats.HeapAlloc / 1024 / 1024,
                HeapSysMB:    memStats.HeapSys / 1024 / 1024,
                HeapIdleMB:   memStats.HeapIdle / 1024 / 1024,
                HeapInUseMB:  memStats.HeapInuse / 1024 / 1024,
                StackInUseMB: memStats.StackInuse / 1024 / 1024,
                GCPercent:    gcPercent,
            },
            Goroutines:  runtime.NumGoroutine(),
            CGoCalls:    runtime.NumCgoCall(),
            HeapObjects: memStats.HeapObjects,
            GCPause:     lastGCPause,
            NextGC:      memStats.NextGC / 1024 / 1024,
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metadata)
}