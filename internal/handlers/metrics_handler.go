package handlers

import (
	"encoding/json"
	"net/http"
	"relay-server/internal/metrics"
	"relay-server/internal/middleware"
	"strconv"
	"sync/atomic"
)

var MetricsService *metrics.MetricsService

type MetricsResponse struct {
    Current struct {
        HTTP struct {
            TotalBytesOut   int64 `json:"total_bytes_out"`
            TotalRequests   int64 `json:"total_requests"`
            AvgBytesPerReq  int64 `json:"avg_bytes_per_request"`
        } `json:"http"`
        WebSocket struct {
            TotalBytesOut    int64 `json:"total_bytes_out"`
            TotalMessages    int64 `json:"total_messages"`
            AvgBytesPerMsg   int64 `json:"avg_bytes_per_message"`
        } `json:"websocket"`
        WebRTC struct {
            TotalBytesOut int64 `json:"total_bytes_out"`
            TotalPackets  int64 `json:"total_packets"`
        } `json:"webrtc"`
        Total struct {
            TotalBytesOut int64 `json:"total_bytes_out"`
        } `json:"total"`
    } `json:"current"`
    Historical interface{} `json:"historical,omitempty"`
}

func GetMetricsHandler(w http.ResponseWriter, r *http.Request) {
    response := MetricsResponse{}

    // Get current metrics from atomic counters
    httpBytesOut := atomic.LoadInt64(&middleware.TotalBytesOut)
    httpRequests := atomic.LoadInt64(&middleware.TotalRequests)
    wsBytesOut := atomic.LoadInt64(&metrics.WebSocketBytesOut)
    wsMessages := atomic.LoadInt64(&metrics.WebSocketMessages)
    webrtcBytesOut := atomic.LoadInt64(&metrics.WebRTCBytesOut)
    webrtcPackets := atomic.LoadInt64(&metrics.WebRTCPackets)

    // HTTP metrics
    response.Current.HTTP.TotalBytesOut = httpBytesOut
    response.Current.HTTP.TotalRequests = httpRequests
    if httpRequests > 0 {
        response.Current.HTTP.AvgBytesPerReq = httpBytesOut / httpRequests
    }

    // WebSocket metrics
    response.Current.WebSocket.TotalBytesOut = wsBytesOut
    response.Current.WebSocket.TotalMessages = wsMessages
    if wsMessages > 0 {
        response.Current.WebSocket.AvgBytesPerMsg = wsBytesOut / wsMessages
    }

    // WebRTC metrics
    response.Current.WebRTC.TotalBytesOut = webrtcBytesOut
    response.Current.WebRTC.TotalPackets = webrtcPackets

    // Total metrics
    response.Current.Total.TotalBytesOut = httpBytesOut + wsBytesOut + webrtcBytesOut

    // Get historical data if requested
    if hoursParam := r.URL.Query().Get("hours"); hoursParam != "" {
        if hours, err := strconv.Atoi(hoursParam); err == nil && hours > 0 && hours <= 168 { // Max 1 week
            if historical, err := MetricsService.GetHourlyMetrics(hours); err == nil {
                response.Historical = historical
            }
        }
    }

    // Get snapshot history if requested
    if minutesParam := r.URL.Query().Get("minutes"); minutesParam != "" {
        if minutes, err := strconv.Atoi(minutesParam); err == nil && minutes > 0 && minutes <= 1440 { // Max 24 hours
            if snapshots, err := MetricsService.GetSnapshotHistory(minutes); err == nil {
                response.Historical = snapshots
            }
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}