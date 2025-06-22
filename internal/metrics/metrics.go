package metrics

import (
	"log"
	"relay-server/internal/db"
	"relay-server/internal/middleware"
	"sync/atomic"
	"time"
)

type MetricsSnapshot struct {
    ID                uint      `gorm:"primaryKey" json:"id"`
    Timestamp         time.Time `gorm:"index" json:"timestamp"`
    HTTPBytesOut      int64     `gorm:"default:0" json:"http_bytes_out"`
    HTTPRequests      int64     `gorm:"default:0" json:"http_requests"`
    WebSocketBytesOut int64     `gorm:"default:0" json:"websocket_bytes_out"`
    WebSocketMessages int64     `gorm:"default:0" json:"websocket_messages"`
    WebRTCBytesOut    int64     `gorm:"default:0" json:"webrtc_bytes_out"`
    WebRTCPackets     int64     `gorm:"default:0" json:"webrtc_packets"`
    ConnectedClients  int       `gorm:"default:0" json:"connected_clients"`
    CreatedAt         time.Time `json:"created_at"`
    UpdatedAt         time.Time `json:"updated_at"`
}

type MetricsHourly struct {
    ID                uint      `gorm:"primaryKey" json:"id"`
    HourBucket        time.Time `gorm:"uniqueIndex" json:"hour_bucket"`
    HTTPBytesOut      int64     `gorm:"default:0" json:"http_bytes_out"`
    HTTPRequests      int64     `gorm:"default:0" json:"http_requests"`
    WebSocketBytesOut int64     `gorm:"default:0" json:"websocket_bytes_out"`
    WebSocketMessages int64     `gorm:"default:0" json:"websocket_messages"`
    TotalBytesOut     int64     `gorm:"default:0" json:"total_bytes_out"`
    PeakClients       int       `gorm:"default:0" json:"peak_clients"`
    CreatedAt         time.Time `json:"created_at"`
    UpdatedAt         time.Time `json:"updated_at"`
}

func (MetricsSnapshot) TableName() string {
    return "metrics_snapshots"
}

func (MetricsHourly) TableName() string {
    return "metrics_hourly"
}

var (
    WebSocketBytesOut int64
    WebSocketMessages int64
    WebRTCBytesOut    int64
    WebRTCPackets     int64
)

type MetricsService struct {
    snapshotTicker *time.Ticker
    hourlyTicker   *time.Ticker
    cleanupTicker  *time.Ticker
    lastHourBucket time.Time
    done          chan bool
}

func NewMetricsService() *MetricsService {
    return &MetricsService{
        snapshotTicker: time.NewTicker(1 * time.Minute),  // Save snapshot every minute
        hourlyTicker:   time.NewTicker(1 * time.Hour),    // Aggregate hourly
        cleanupTicker:  time.NewTicker(24 * time.Hour),   // Cleanup daily
        done:          make(chan bool),
    }
}

func (ms *MetricsService) Start() {
    log.Println("Starting metrics service...")

    // Initial snapshot
    ms.saveSnapshot()

    go func() {
        for {
            select {
            case <-ms.snapshotTicker.C:
                ms.saveSnapshot()

            case <-ms.hourlyTicker.C:
                ms.aggregateHourlyMetrics()

            case <-ms.cleanupTicker.C:
                ms.cleanup()

            case <-ms.done:
                log.Println("Metrics service stopped")
                return
            }
        }
    }()
}

func (ms *MetricsService) Stop() {
    log.Println("Stopping metrics service...")
    ms.snapshotTicker.Stop()
    ms.hourlyTicker.Stop()
    ms.cleanupTicker.Stop()

    // Save final snapshot
    ms.saveSnapshot()

    // Signal the goroutine to stop
    close(ms.done)
}

func (ms *MetricsService) saveSnapshot() {
    snapshot := MetricsSnapshot{
        Timestamp:         time.Now(),
        HTTPBytesOut:      atomic.LoadInt64(&middleware.TotalBytesOut),
        HTTPRequests:      atomic.LoadInt64(&middleware.TotalRequests),
        WebSocketBytesOut: atomic.LoadInt64(&WebSocketBytesOut),
        WebSocketMessages: atomic.LoadInt64(&WebSocketMessages),
        WebRTCBytesOut:    atomic.LoadInt64(&WebRTCBytesOut),
        WebRTCPackets:     atomic.LoadInt64(&WebRTCPackets),
        ConnectedClients:  0, // You'll need to get this from your WebSocket hub
    }

    if err := db.DB.Create(&snapshot).Error; err != nil {
        log.Printf("Error saving metrics snapshot: %v", err)
        return
    }
}

func (ms *MetricsService) aggregateHourlyMetrics() {
    now := time.Now()
    hourBucket := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())

    // Skip if we already processed this hour
    if hourBucket.Equal(ms.lastHourBucket) {
        return
    }

    httpBytes := atomic.LoadInt64(&middleware.TotalBytesOut)
    httpRequests := atomic.LoadInt64(&middleware.TotalRequests)
    wsBytes := atomic.LoadInt64(&WebSocketBytesOut)
    wsMessages := atomic.LoadInt64(&WebSocketMessages)
    totalBytes := httpBytes + wsBytes + atomic.LoadInt64(&WebRTCBytesOut)
    connectedClients := 0 // Get from WebSocket hub

    hourlyMetrics := MetricsHourly{
        HourBucket:        hourBucket,
        HTTPBytesOut:      httpBytes,
        HTTPRequests:      httpRequests,
        WebSocketBytesOut: wsBytes,
        WebSocketMessages: wsMessages,
        TotalBytesOut:     totalBytes,
        PeakClients:       connectedClients,
    }

    // Use GORM's OnConflict to update if exists
    if err := db.DB.Save(&hourlyMetrics).Error; err != nil {
        log.Printf("Error updating hourly metrics: %v", err)
        return
    }

    ms.lastHourBucket = hourBucket
    log.Printf("Hourly metrics aggregated for %v", hourBucket.Format("2006-01-02 15:00"))
}

func (ms *MetricsService) cleanup() {
    // Keep detailed snapshots for 7 days
    cutoff := time.Now().AddDate(0, 0, -7)

    result := db.DB.Where("timestamp < ?", cutoff).Delete(&MetricsSnapshot{})
    if result.Error != nil {
        log.Printf("Error cleaning up old snapshots: %v", result.Error)
    } else if result.RowsAffected > 0 {
        log.Printf("Cleaned up %d old metrics snapshots", result.RowsAffected)
    }
}

func (ms *MetricsService) GetCurrentMetrics() (MetricsSnapshot, error) {
    snapshot := MetricsSnapshot{
        Timestamp:         time.Now(),
        HTTPBytesOut:      atomic.LoadInt64(&middleware.TotalBytesOut),
        HTTPRequests:      atomic.LoadInt64(&middleware.TotalRequests),
        WebSocketBytesOut: atomic.LoadInt64(&WebSocketBytesOut),
        WebSocketMessages: atomic.LoadInt64(&WebSocketMessages),
        WebRTCBytesOut:    atomic.LoadInt64(&WebRTCBytesOut),
        WebRTCPackets:     atomic.LoadInt64(&WebRTCPackets),
        ConnectedClients:  0, // Get from WebSocket hub
    }

    return snapshot, nil
}

func (ms *MetricsService) GetHourlyMetrics(hours int) ([]MetricsHourly, error) {
    var metrics []MetricsHourly

    cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

    err := db.DB.Where("hour_bucket >= ?", cutoff).
        Order("hour_bucket DESC").
        Find(&metrics).Error

    return metrics, err
}

func (ms *MetricsService) GetSnapshotHistory(minutes int) ([]MetricsSnapshot, error) {
    var snapshots []MetricsSnapshot

    cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)

    err := db.DB.Where("timestamp >= ?", cutoff).
        Order("timestamp DESC").
        Find(&snapshots).Error

    return snapshots, err
}
