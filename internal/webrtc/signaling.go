package webrtc

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
)

const (
    rtpBufferSize     = 1024
	maxForwardWorkers = 10
    packetTimeout     = 10 * time.Millisecond
)

type SignalingMessage struct {
	Type      string      `json:"type"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	ChannelID uint        `json:"channel_id"`
	Data      interface{} `json:"data"`
}

type PeerConnection struct {
	UserID         string
	ChannelID      uint
	ConnectionID   string
	PC             *webrtc.PeerConnection
	LocalTracks    map[string]*webrtc.TrackLocalStaticRTP
	RemoteTracks   map[string]*webrtc.TrackRemote
	DataChannel    *webrtc.DataChannel
	State          webrtc.PeerConnectionState
	CreatedAt      time.Time
	LastActivity   time.Time
	mu             sync.RWMutex
}

type SignalingServer struct {
	connections map[string]*PeerConnection
	mu          sync.RWMutex
	broadcaster MessageBroadcaster
	api         *webrtc.API
	config      webrtc.Configuration
	packetBuffer    chan rtpPacketBuffer
    forwardWorkers  sync.WaitGroup
    ctx             context.Context
    cancel          context.CancelFunc
    channelConnections map[uint][]*PeerConnection // Cache connections by channel
    channelMu       sync.RWMutex
}

type rtpPacketBuffer struct {
    packet   *rtp.Packet
    kind     webrtc.RTPCodecType
    fromUser string
}

type MessageBroadcaster interface {
	BroadcastMessage(messageType string, data interface{})
	SendMessageToUser(userID string, messageType string, data interface{})
}

var GlobalSignalingServer *SignalingServer

func init() {
    // Create WebRTC API with media engine
    mediaEngine := &webrtc.MediaEngine{}

    // Setup codecs
    if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
        log.Fatal("Failed to register codecs:", err)
    }

    // Create API with media engine
    api := webrtc.NewAPI(webrtc.WithMediaEngine(mediaEngine))

    // STUN servers for NAT traversal
    config := webrtc.Configuration{
        ICEServers: []webrtc.ICEServer{
            {
                URLs: []string{"stun:stun.l.google.com:19302"},
            },
        },
    }

    ctx, cancel := context.WithCancel(context.Background())

    // Initialize GlobalSignalingServer FIRST
    GlobalSignalingServer = &SignalingServer{
        connections:        make(map[string]*PeerConnection),
        channelConnections: make(map[uint][]*PeerConnection),
        api:                api,
        config:             config,
        packetBuffer:       make(chan rtpPacketBuffer, rtpBufferSize),
        ctx:                ctx,
        cancel:             cancel,
    }

    // THEN start the worker goroutines
    for i := 0; i < maxForwardWorkers; i++ {
        go GlobalSignalingServer.packetForwardWorker()
    }

    // Start cleanup routine
    go GlobalSignalingServer.cleanupRoutine()
}

func (s *SignalingServer) packetForwardWorker() {
    s.forwardWorkers.Add(1)
    defer s.forwardWorkers.Done()

    for {
        select {
        case <-s.ctx.Done():
            return
        case packet := <-s.packetBuffer:
            s.forwardPacketToChannel(packet)
        }
    }
}

func (s *SignalingServer) forwardTrackToChannel(fromUserID string, channelID uint, track *webrtc.TrackRemote) {
    // Use a separate goroutine to avoid blocking the main connection
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Panic in forwardTrackToChannel: %v", r)
            }
        }()

        // Create a buffer for batch processing
        packetBatch := make([]*rtp.Packet, 0, 10)
        batchTimer := time.NewTicker(5 * time.Millisecond) // Process batches every 5ms
        defer batchTimer.Stop()

        for {
            select {
            case <-s.ctx.Done():
                return
            case <-batchTimer.C:
                if len(packetBatch) > 0 {
                    // Process batch
                    for _, packet := range packetBatch {
                        s.queuePacketForward(packet, track.Kind(), fromUserID, channelID)
                    }
                    packetBatch = packetBatch[:0] // Reset batch
                }
            default:
                // Try to read a packet with timeout
                done := make(chan bool, 1)
                var rtpPacket *rtp.Packet
                var err error

                go func() {
                    rtpPacket, _, err = track.ReadRTP()
                    done <- true
                }()

                select {
                case <-done:
                    if err != nil {
                        if err == io.EOF {
                            return
                        }
                        log.Printf("Error reading RTP packet: %v", err)
                        continue
                    }
                    packetBatch = append(packetBatch, rtpPacket)

                    // If batch is full, process immediately
                    if len(packetBatch) >= 10 {
                        for _, packet := range packetBatch {
                            s.queuePacketForward(packet, track.Kind(), fromUserID, channelID)
                        }
                        packetBatch = packetBatch[:0]
                    }
                case <-time.After(100 * time.Millisecond):
                    // Timeout - process current batch if any
                    if len(packetBatch) > 0 {
                        for _, packet := range packetBatch {
                            s.queuePacketForward(packet, track.Kind(), fromUserID, channelID)
                        }
                        packetBatch = packetBatch[:0]
                    }
                }
            }
        }
    }()
}

func (s *SignalingServer) queuePacketForward(packet *rtp.Packet, kind webrtc.RTPCodecType, fromUserID string, channelID uint) {
    select {
    case s.packetBuffer <- rtpPacketBuffer{
        packet:   packet,
        kind:     kind,
        fromUser: fromUserID,
    }:
    default:
        // Buffer full, drop packet (better than blocking)
        log.Printf("Packet buffer full, dropping packet from %s", fromUserID)
    }
}

func (s *SignalingServer) forwardPacketToChannel(packetBuffer rtpPacketBuffer) {
    // Get channel connections (cached for performance)
    connections := s.getChannelConnections(packetBuffer.fromUser)

    // Forward to all connections in parallel
    var wg sync.WaitGroup
    for _, pc := range connections {
        if pc.UserID == packetBuffer.fromUser {
            continue // Don't forward to sender
        }

        wg.Add(1)
        go func(conn *PeerConnection) {
            defer wg.Done()
            s.forwardRTPPacketOptimized(conn, packetBuffer.kind, packetBuffer.packet)
        }(pc)
    }
    wg.Wait()
}

func (s *SignalingServer) getChannelConnections(userID string) []*PeerConnection {
    // Get channel ID from user's connection
    s.mu.RLock()
    var channelID uint
    for _, conn := range s.connections {
        if conn.UserID == userID {
            channelID = conn.ChannelID
            break
        }
    }
    s.mu.RUnlock()

    if channelID == 0 {
        return nil
    }

    // Check cached connections first
    s.channelMu.RLock()
    cached, exists := s.channelConnections[channelID]
    s.channelMu.RUnlock()

    if exists && len(cached) > 0 {
        // Validate cache
        valid := true
        for _, conn := range cached {
            conn.mu.RLock()
            if conn.State != webrtc.PeerConnectionStateConnected {
                valid = false
            }
            conn.mu.RUnlock()
            if !valid {
                break
            }
        }

        if valid {
            return cached
        }
    }

    // Rebuild cache
    s.mu.RLock()
    connections := make([]*PeerConnection, 0)
    for _, conn := range s.connections {
        if conn.ChannelID == channelID {
            conn.mu.RLock()
            if conn.State == webrtc.PeerConnectionStateConnected {
                connections = append(connections, conn)
            }
            conn.mu.RUnlock()
        }
    }
    s.mu.RUnlock()

    // Update cache
    s.channelMu.Lock()
    s.channelConnections[channelID] = connections
    s.channelMu.Unlock()

    return connections
}

func (s *SignalingServer) forwardRTPPacketOptimized(pc *PeerConnection, kind webrtc.RTPCodecType, packet *rtp.Packet) {
    // Quick state check without lock if possible
    pc.mu.RLock()
    if pc.State != webrtc.PeerConnectionStateConnected {
        pc.mu.RUnlock()
        return
    }

    // Determine track type
    var trackKey string
    switch kind {
    case webrtc.RTPCodecTypeAudio:
        trackKey = "audio"
    case webrtc.RTPCodecTypeVideo:
        trackKey = "video"
    default:
        pc.mu.RUnlock()
        return
    }

    // Get local track
    localTrack, exists := pc.LocalTracks[trackKey]
    if !exists {
        pc.mu.RUnlock()
        return
    }
    pc.mu.RUnlock()

    // Create packet copy (reuse buffer if possible)
    forwardPacket := &rtp.Packet{
        Header: packet.Header, // Copy header by value
        Payload: make([]byte, len(packet.Payload)),
    }
    copy(forwardPacket.Payload, packet.Payload)

    // Write with timeout to prevent blocking
    done := make(chan error, 1)
    go func() {
        done <- localTrack.WriteRTP(forwardPacket)
    }()

    select {
    case err := <-done:
        if err != nil && err.Error() != "InvalidStateError" {
            log.Printf("Error writing RTP packet to %s track for user %s: %v",
                trackKey, pc.UserID, err)
        } else {
            // Update activity timestamp on successful write
            pc.mu.Lock()
            pc.LastActivity = time.Now()
            pc.mu.Unlock()
        }
    case <-time.After(packetTimeout):
        log.Printf("Timeout writing RTP packet to user %s", pc.UserID)
    }
}

func (s *SignalingServer) invalidateChannelCache(channelID uint) {
    s.channelMu.Lock()
    delete(s.channelConnections, channelID)
    s.channelMu.Unlock()
}

func (s *SignalingServer) SetBroadcaster(broadcaster MessageBroadcaster) {
	s.broadcaster = broadcaster
}

func (s *SignalingServer) HandleSignalingMessage(msg SignalingMessage) error {
	switch msg.Type {
	case "offer":
		return s.handleOffer(msg)
	case "answer":
		return s.handleAnswer(msg)
	case "ice-candidate":
		return s.handleIceCandidate(msg)
	case "peer-connect":
		return s.handlePeerConnect(msg)
	case "peer-disconnect":
		return s.handlePeerDisconnect(msg)
	default:
		log.Printf("Unknown signaling message type: %s", msg.Type)
		return nil
	}
}

func (s *SignalingServer) handleOffer(msg SignalingMessage) error {
	log.Printf("Handling offer from %s in channel %d", msg.From, msg.ChannelID)

	// Create or get peer connection for this user
	connID := fmt.Sprintf("%s-%d", msg.From, msg.ChannelID)
	pc, err := s.getOrCreatePeerConnection(msg.From, msg.ChannelID, connID)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %v", err)
	}

	defer s.invalidateChannelCache(pc.ChannelID)

	// Parse the offer
	offerData, ok := msg.Data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid offer data")
	}

	sdpStr, ok := offerData["sdp"].(string)
	if !ok {
		return fmt.Errorf("missing SDP in offer")
	}

	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdpStr,
	}

	// Set remote description
	if err := pc.PC.SetRemoteDescription(offer); err != nil {
		return fmt.Errorf("failed to set remote description: %v", err)
	}

	// Create answer
	answer, err := pc.PC.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("failed to create answer: %v", err)
	}

	// Set local description
	if err := pc.PC.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("failed to set local description: %v", err)
	}

	// Send answer back to client
	if s.broadcaster != nil {
		s.broadcaster.SendMessageToUser(msg.From, "webrtc_answer", map[string]interface{}{
			"channel_id": msg.ChannelID,
			"answer": map[string]interface{}{
				"type": answer.Type.String(),
				"sdp":  answer.SDP,
			},
		})
	}

	return nil
}

func (s *SignalingServer) handleAnswer(msg SignalingMessage) error {
	log.Printf("Handling answer from %s in channel %d", msg.From, msg.ChannelID)

	connID := fmt.Sprintf("%s-%d", msg.From, msg.ChannelID)
	s.mu.RLock()
	pc, exists := s.connections[connID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("peer connection not found")
	}

	// Parse the answer
	answerData, ok := msg.Data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid answer data")
	}

	sdpStr, ok := answerData["sdp"].(string)
	if !ok {
		return fmt.Errorf("missing SDP in answer")
	}

	answer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdpStr,
	}

	// Set remote description
	if err := pc.PC.SetRemoteDescription(answer); err != nil {
		return fmt.Errorf("failed to set remote description: %v", err)
	}

	return nil
}

func (s *SignalingServer) handleIceCandidate(msg SignalingMessage) error {
	log.Printf("Handling ICE candidate from %s", msg.From)

	connID := fmt.Sprintf("%s-%d", msg.From, msg.ChannelID)
	s.mu.RLock()
	pc, exists := s.connections[connID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("peer connection not found")
	}

	// Parse ICE candidate
	candidateData, ok := msg.Data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid candidate data")
	}

	candidateStr, ok := candidateData["candidate"].(string)
	if !ok {
		return fmt.Errorf("missing candidate string")
	}

	candidate := webrtc.ICECandidateInit{
		Candidate: candidateStr,
	}

	if sdpMid, ok := candidateData["sdpMid"].(string); ok {
		candidate.SDPMid = &sdpMid
	}

	if sdpMLineIndex, ok := candidateData["sdpMLineIndex"].(float64); ok {
		idx := uint16(sdpMLineIndex)
		candidate.SDPMLineIndex = &idx
	}

	// Add ICE candidate
	if err := pc.PC.AddICECandidate(candidate); err != nil {
		return fmt.Errorf("failed to add ICE candidate: %v", err)
	}

	return nil
}

func (s *SignalingServer) getOrCreatePeerConnection(userID string, channelID uint, connID string) (*PeerConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pc, exists := s.connections[connID]; exists {
		return pc, nil
	}

	// Create new peer connection
	pc, err := s.api.NewPeerConnection(s.config)
	if err != nil {
		return nil, err
	}

	peerConn := &PeerConnection{
		UserID:       userID,
		ChannelID:    channelID,
		ConnectionID: connID,
		PC:           pc,
		LocalTracks:  make(map[string]*webrtc.TrackLocalStaticRTP),
		RemoteTracks: make(map[string]*webrtc.TrackRemote),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	// Create local tracks for forwarding audio/video from other users
	audioTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "pion")
	if err != nil {
		return nil, fmt.Errorf("failed to create audio track: %v", err)
	}

	videoTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "video", "pion")
	if err != nil {
		return nil, fmt.Errorf("failed to create video track: %v", err)
	}

	// Add tracks to peer connection
	if _, err = pc.AddTrack(audioTrack); err != nil {
		return nil, fmt.Errorf("failed to add audio track: %v", err)
	}

	if _, err = pc.AddTrack(videoTrack); err != nil {
		return nil, fmt.Errorf("failed to add video track: %v", err)
	}

	peerConn.LocalTracks["audio"] = audioTrack
	peerConn.LocalTracks["video"] = videoTrack

	// Handle incoming tracks
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		log.Printf("Received track from %s: %s", userID, track.Kind().String())

		peerConn.mu.Lock()
		peerConn.RemoteTracks[track.ID()] = track
		peerConn.mu.Unlock()

		// Forward track to other participants in the same channel
		go s.forwardTrackToChannel(userID, channelID, track)
	})

	// Handle connection state changes
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("Connection state changed for %s: %s", userID, state.String())
		peerConn.mu.Lock()
		peerConn.State = state
		peerConn.LastActivity = time.Now()
		peerConn.mu.Unlock()

		// Notify voice system of connection status
		if s.broadcaster != nil {
			connected := state == webrtc.PeerConnectionStateConnected
			s.broadcaster.SendMessageToUser(userID, "webrtc_connection_status", map[string]interface{}{
				"channel_id": channelID,
				"connected":  connected,
				"state":      state.String(),
			})
		}

		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			s.cleanupConnection(connID)
		}
	})

	// Handle ICE candidates
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}

		if s.broadcaster != nil {
			candidateData := map[string]interface{}{
				"candidate":     candidate.ToJSON().Candidate,
				"sdpMid":        candidate.ToJSON().SDPMid,
				"sdpMLineIndex": candidate.ToJSON().SDPMLineIndex,
			}

			s.broadcaster.SendMessageToUser(userID, "webrtc_ice_candidate", map[string]interface{}{
				"channel_id": channelID,
				"candidate":  candidateData,
			})
		}
	})

	// Handle ICE connection state changes for connection quality monitoring
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		var quality string
		switch state {
		case webrtc.ICEConnectionStateConnected:
			quality = "excellent"
		case webrtc.ICEConnectionStateCompleted:
			quality = "excellent"
		case webrtc.ICEConnectionStateChecking:
			quality = "good"
		case webrtc.ICEConnectionStateDisconnected:
			quality = "poor"
		case webrtc.ICEConnectionStateFailed:
			quality = "disconnected"
		case webrtc.ICEConnectionStateClosed:
			quality = "disconnected"
		default:
			quality = "unknown"
		}

		if s.broadcaster != nil {
			s.broadcaster.SendMessageToUser(userID, "connection_quality", map[string]interface{}{
				"channel_id": channelID,
				"quality":    quality,
			})
		}
	})

	s.connections[connID] = peerConn
	return peerConn, nil
}

func (s *SignalingServer) handlePeerConnect(msg SignalingMessage) error {
	log.Printf("Handling peer connect from %s in channel %d", msg.From, msg.ChannelID)

	// This is called when a peer connection is successfully established
	connID := fmt.Sprintf("%s-%d", msg.From, msg.ChannelID)
	s.mu.RLock()
	pc, exists := s.connections[connID]
	s.mu.RUnlock()

	if exists {
		pc.mu.Lock()
		pc.State = webrtc.PeerConnectionStateConnected
		pc.LastActivity = time.Now()
		pc.mu.Unlock()
		log.Printf("Peer connection marked as connected: %s", connID)
	}

	return nil
}

func (s *SignalingServer) handlePeerDisconnect(msg SignalingMessage) error {
	log.Printf("Handling peer disconnect from %s in channel %d", msg.From, msg.ChannelID)

	connID := fmt.Sprintf("%s-%d", msg.From, msg.ChannelID)
	s.cleanupConnection(connID)
	return nil
}

func (s *SignalingServer) CleanupUserConnections(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []string
	for connID, conn := range s.connections {
		if conn.UserID == userID {
			toDelete = append(toDelete, connID)
		}
	}

	for _, connID := range toDelete {
		if pc, exists := s.connections[connID]; exists {
			pc.PC.Close()
			delete(s.connections, connID)
			log.Printf("Cleaned up connection: %s", connID)
		}
	}
}

func (s *SignalingServer) GetActiveConnections(userID string) []*PeerConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var connections []*PeerConnection
	for _, conn := range s.connections {
		if conn.UserID == userID {
			connections = append(connections, conn)
		}
	}

	return connections
}

func (s *SignalingServer) cleanupConnection(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pc, exists := s.connections[connID]; exists {
		pc.PC.Close()
		delete(s.connections, connID)
		log.Printf("Cleaned up peer connection: %s", connID)
		go s.invalidateChannelCache(pc.ChannelID)
	}
}

func (s *SignalingServer) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		var toCleanup []string

		for connID, pc := range s.connections {
			pc.mu.RLock()
			if now.Sub(pc.LastActivity) > 5*time.Minute ||
				pc.State == webrtc.PeerConnectionStateFailed ||
				pc.State == webrtc.PeerConnectionStateClosed {
				toCleanup = append(toCleanup, connID)
			}
			pc.mu.RUnlock()
		}
		s.mu.Unlock()

		for _, connID := range toCleanup {
			s.cleanupConnection(connID)
		}
	}
}
