package webrtc

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
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

	GlobalSignalingServer = &SignalingServer{
		connections: make(map[string]*PeerConnection),
		api:         api,
		config:      config,
	}

	// Start cleanup routine
	go GlobalSignalingServer.cleanupRoutine()
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

func (s *SignalingServer) forwardTrackToChannel(fromUserID string, channelID uint, track *webrtc.TrackRemote) {
	// Read RTP packets from the track
	for {
		rtpPacket, _, err := track.ReadRTP()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading RTP packet: %v", err)
			continue
		}

		// Forward to all other participants in the channel
		s.mu.RLock()
		for _, pc := range s.connections {
			if pc.ChannelID == channelID && pc.UserID != fromUserID {
				s.forwardRTPPacket(pc, track.Kind(), rtpPacket)
			}
		}
		s.mu.RUnlock()
	}
}

func (s *SignalingServer) forwardRTPPacket(pc *PeerConnection, kind webrtc.RTPCodecType, packet *rtp.Packet) {
    pc.mu.RLock()
    defer pc.mu.RUnlock()

    // Skip if peer connection is not in a good state
    if pc.State != webrtc.PeerConnectionStateConnected {
        return
    }

    // Determine track type based on RTPCodecType
    var trackKey string
    switch kind {
		case webrtc.RTPCodecTypeAudio:
			trackKey = "audio"
		case webrtc.RTPCodecTypeVideo:
			trackKey = "video"
		default:
			log.Printf("Unknown RTP codec type: %v", kind)
			return
    }

    // Get the appropriate local track
    localTrack, exists := pc.LocalTracks[trackKey]
    if !exists {
        log.Printf("No local track found for type: %s", trackKey)
        return
    }

    // Validate packet before forwarding
    if packet == nil {
        log.Printf("Received nil RTP packet")
        return
    }

    // Create a copy of the packet to avoid race conditions
    forwardPacket := &rtp.Packet{
        Header: rtp.Header{
            Version:        packet.Header.Version,
            Padding:        packet.Header.Padding,
            Extension:      packet.Header.Extension,
            Marker:         packet.Header.Marker,
            PayloadType:    packet.Header.PayloadType,
            SequenceNumber: packet.Header.SequenceNumber,
            Timestamp:      packet.Header.Timestamp,
            SSRC:           packet.Header.SSRC,
            CSRC:           packet.Header.CSRC,
        },
        Payload: make([]byte, len(packet.Payload)),
    }
    copy(forwardPacket.Payload, packet.Payload)

    // Write RTP packet to the local track with error handling
    if err := localTrack.WriteRTP(forwardPacket); err != nil {
        // Don't log every error as it can be noisy, but track patterns
        if err.Error() != "InvalidStateError" { // Common when connection is closing
            log.Printf("Error writing RTP packet to %s track for user %s: %v",
                trackKey, pc.UserID, err)
        }
        return
    }

    // Update activity timestamp on successful forward
    pc.LastActivity = time.Now()
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
