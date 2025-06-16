package voice

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/webrtc"
)

// MessageBroadcaster interface to avoid import cycle
type MessageBroadcaster interface {
	BroadcastMessage(messageType string, data interface{})
	SendMessageToUser(userID string, messageType string, data interface{})
}

type VoiceParticipant struct {
	UserID            string    `json:"user_id"`
	Username          string    `json:"username"`
	Nickname          string    `json:"nickname"`
	IsMuted           bool      `json:"is_muted"`
	IsDeafened        bool      `json:"is_deafened"`
	IsSpeaking        bool      `json:"is_speaking"`
	JoinedAt          time.Time `json:"joined_at"`
	ProfilePictureURL string    `json:"profile_picture_url"`
	WebRTCConnected   bool      `json:"webrtc_connected"`
	ConnectionQuality string    `json:"connection_quality"` // "excellent", "good", "poor", "disconnected"
}

type VoiceRoom struct {
	ChannelID    uint
	Participants map[string]*VoiceParticipant
	mu           sync.RWMutex
}

var (
	voiceRooms      = make(map[uint]*VoiceRoom)
	voiceRoomsMu    sync.RWMutex
	jsonBroadcaster MessageBroadcaster
)

// SetBroadcaster sets the broadcaster instance for voice events
func SetBroadcaster(b MessageBroadcaster) {
	jsonBroadcaster = b
	webrtc.GlobalSignalingServer.SetBroadcaster(b)
}

func JoinVoiceRoom(r *http.Request, userID string, channelID uint) error {
	voiceRoomsMu.Lock()
	defer voiceRoomsMu.Unlock()

	// Get or create voice room
	room, exists := voiceRooms[channelID]
	if !exists {
		room = &VoiceRoom{
			ChannelID:    channelID,
			Participants: make(map[string]*VoiceParticipant),
		}
		voiceRooms[channelID] = room
	}

	// Get user info
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()
	if !exists {
		return fmt.Errorf("user not found")
	}

	// Check if user is already in this room
	room.mu.Lock()
	if _, alreadyExists := room.Participants[userID]; alreadyExists {
		room.mu.Unlock()
		return fmt.Errorf("user already in voice room")
	}

	profileURL := ""
	if userObj.ProfilePictureHash != "" {
		profileURL = util.GetProfilePictureURL(r, userID)
	}

	// Add participant
	participant := &VoiceParticipant{
		UserID:            userID,
		Username:          userObj.Username,
		Nickname:          userObj.Nickname,
		IsMuted:           false,
		IsDeafened:        false,
		IsSpeaking:        false,
		JoinedAt:          time.Now(),
		ProfilePictureURL: profileURL,
		WebRTCConnected:   false,
		ConnectionQuality: "connecting",
	}
	room.Participants[userID] = participant
	room.mu.Unlock()

	// Get list of existing participants for WebRTC connections
	room.mu.RLock()
	existingParticipants := make([]map[string]interface{}, 0, len(room.Participants))
	for pID, p := range room.Participants {
		if pID != userID {
			existingParticipants = append(existingParticipants, map[string]interface{}{
				"user_id":            p.UserID,
				"username":           p.Username,
				"nickname":           p.Nickname,
				"webrtc_connected":   p.WebRTCConnected,
				"connection_quality": p.ConnectionQuality,
			})
		}
	}
	room.mu.RUnlock()

	// Broadcast user joined voice
	broadcastVoiceUpdate(channelID, "user_joined_voice", map[string]interface{}{
		"user_id":             userID,
		"channel_id":          channelID,
		"participant":         participant,
		"existing_participants": existingParticipants,
	})

	// Send WebRTC configuration to the joining client
	go initiateWebRTCConnection(userID, channelID)

	log.Printf("User %s joined voice channel %d", userID, channelID)
	return nil
}

func LeaveVoiceRoom(userID string, channelID uint) error {
	voiceRoomsMu.Lock()
	defer voiceRoomsMu.Unlock()

	room, exists := voiceRooms[channelID]
	if !exists {
		return fmt.Errorf("voice room not found")
	}

	// Remove participant
	room.mu.Lock()
	delete(room.Participants, userID)
	participantCount := len(room.Participants)
	room.mu.Unlock()

	// Clean up WebRTC connections
	webrtc.GlobalSignalingServer.CleanupUserConnections(userID)

	// If no participants left, clean up room
	if participantCount == 0 {
		delete(voiceRooms, channelID)
	}

	// Broadcast user left voice
	broadcastVoiceUpdate(channelID, "user_left_voice", map[string]interface{}{
		"user_id":    userID,
		"channel_id": channelID,
	})

	log.Printf("User %s left voice channel %d", userID, channelID)
	return nil
}

func UpdateVoiceState(userID string, channelID uint, isMuted, isDeafened bool) error {
	voiceRoomsMu.RLock()
	room, exists := voiceRooms[channelID]
	voiceRoomsMu.RUnlock()

	if !exists {
		return fmt.Errorf("voice room not found")
	}

	room.mu.Lock()
	participant, exists := room.Participants[userID]
	if !exists {
		room.mu.Unlock()
		return fmt.Errorf("participant not found")
	}

	participant.IsMuted = isMuted
	participant.IsDeafened = isDeafened
	room.mu.Unlock()

	// Broadcast voice state update
	broadcastVoiceUpdate(channelID, "voice_state_update", map[string]interface{}{
		"user_id":     userID,
		"channel_id":  channelID,
		"is_muted":    isMuted,
		"is_deafened": isDeafened,
	})

	return nil
}

func UpdateSpeakingStatus(userID string, channelID uint, isSpeaking bool) error {
	voiceRoomsMu.RLock()
	room, exists := voiceRooms[channelID]
	voiceRoomsMu.RUnlock()

	if !exists {
		return fmt.Errorf("voice room not found")
	}

	room.mu.Lock()
	participant, exists := room.Participants[userID]
	if !exists {
		room.mu.Unlock()
		return fmt.Errorf("participant not found")
	}

	if participant.IsSpeaking != isSpeaking {
		participant.IsSpeaking = isSpeaking
		room.mu.Unlock()

		// Broadcast speaking status change
		broadcastVoiceUpdate(channelID, "speaking_update", map[string]interface{}{
			"user_id":     userID,
			"channel_id":  channelID,
			"is_speaking": isSpeaking,
		})
	} else {
		room.mu.Unlock()
	}

	return nil
}

func UpdateWebRTCConnectionStatus(userID string, channelID uint, connected bool) error {
	voiceRoomsMu.RLock()
	room, exists := voiceRooms[channelID]
	voiceRoomsMu.RUnlock()

	if !exists {
		return fmt.Errorf("voice room not found")
	}

	room.mu.Lock()
	participant, exists := room.Participants[userID]
	if !exists {
		room.mu.Unlock()
		return fmt.Errorf("participant not found")
	}

	participant.WebRTCConnected = connected
	if connected {
		participant.ConnectionQuality = "good"
	} else {
		participant.ConnectionQuality = "disconnected"
	}
	room.mu.Unlock()

	// Broadcast WebRTC connection status change
	broadcastVoiceUpdate(channelID, "webrtc_connection_update", map[string]interface{}{
		"user_id":            userID,
		"channel_id":         channelID,
		"webrtc_connected":   connected,
		"connection_quality": participant.ConnectionQuality,
	})

	return nil
}

func UpdateConnectionQuality(userID string, channelID uint, quality string) error {
	voiceRoomsMu.RLock()
	room, exists := voiceRooms[channelID]
	voiceRoomsMu.RUnlock()

	if !exists {
		return fmt.Errorf("voice room not found")
	}

	room.mu.Lock()
	participant, exists := room.Participants[userID]
	if !exists {
		room.mu.Unlock()
		return fmt.Errorf("participant not found")
	}

	participant.ConnectionQuality = quality
	room.mu.Unlock()

	// Broadcast connection quality change
	broadcastVoiceUpdate(channelID, "connection_quality_update", map[string]interface{}{
		"user_id":            userID,
		"channel_id":         channelID,
		"connection_quality": quality,
	})

	return nil
}

func GetVoiceParticipants(channelID uint) []*VoiceParticipant {
	voiceRoomsMu.RLock()
	room, exists := voiceRooms[channelID]
	voiceRoomsMu.RUnlock()

	if !exists {
		return []*VoiceParticipant{}
	}

	room.mu.RLock()
	participants := make([]*VoiceParticipant, 0, len(room.Participants))
	for _, participant := range room.Participants {
		participants = append(participants, participant)
	}
	room.mu.RUnlock()

	return participants
}

func GetAllVoiceRooms() []map[string]interface{} {
	voiceRoomsMu.RLock()
	defer voiceRoomsMu.RUnlock()

	roomResponses := make([]map[string]interface{}, 0)
	for channelID, room := range voiceRooms {
		// Get channel information
		var ch channel.Channel
		if err := db.DB.First(&ch, channelID).Error; err != nil {
			continue
		}

		if ch.Type != channel.ChannelTypeVoice {
			continue
		}

		room.mu.RLock()
		participants := make([]map[string]interface{}, 0, len(room.Participants))
		for _, participant := range room.Participants {
			participants = append(participants, map[string]interface{}{
				"user_id":            participant.UserID,
				"username":           participant.Username,
				"nickname":           participant.Nickname,
				"is_muted":           participant.IsMuted,
				"is_deafened":        participant.IsDeafened,
				"is_speaking":        participant.IsSpeaking,
				"webrtc_connected":   participant.WebRTCConnected,
				"joined_at":          participant.JoinedAt,
				"profile_picture_url": participant.ProfilePictureURL,
			})
		}
		room.mu.RUnlock()

		roomResponses = append(roomResponses, map[string]interface{}{
			"channel_id":   channelID,
			"channel_name": ch.Name,
			"is_active":    true,
			"participants": participants,
			"created_at":   time.Now(),
		})
	}

	return roomResponses
}

func DisconnectUserFromAllVoiceRooms(userID string) {
	voiceRoomsMu.Lock()
	defer voiceRoomsMu.Unlock()

	var roomsToCleanup []uint

	for channelID, room := range voiceRooms {
		room.mu.Lock()
		if _, exists := room.Participants[userID]; exists {
			delete(room.Participants, userID)
			log.Printf("User %s disconnected from voice room %d", userID, channelID)

			// Clean up WebRTC connections
			webrtc.GlobalSignalingServer.CleanupUserConnections(userID)

			// Broadcast disconnect
			if jsonBroadcaster != nil {
				go func(cID uint, uID string) {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Panic in voice disconnect broadcast: %v", r)
						}
					}()

					time.Sleep(100 * time.Millisecond)
					jsonBroadcaster.BroadcastMessage("user_left_voice", map[string]interface{}{
						"user_id":    uID,
						"channel_id": cID,
					})
				}(channelID, userID)
			}

			if len(room.Participants) == 0 {
				roomsToCleanup = append(roomsToCleanup, channelID)
			}
		}
		room.mu.Unlock()
	}

	// Clean up empty rooms
	for _, channelID := range roomsToCleanup {
		if room, exists := voiceRooms[channelID]; exists {
			room.mu.Lock()
			if len(room.Participants) == 0 {
				room.mu.Unlock()
				delete(voiceRooms, channelID)
				log.Printf("Voice room %d cleaned up", channelID)
			} else {
				room.mu.Unlock()
			}
		}
	}
}

func broadcastVoiceUpdate(channelID uint, eventType string, data interface{}) {
	if jsonBroadcaster != nil {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("broadcastVoiceUpdate: Panic recovered during broadcast: %v", r)
				}
			}()
			log.Printf("Broadcasting %s for channel %d with data: %v", eventType, channelID, data)
			jsonBroadcaster.BroadcastMessage(eventType, data)
		}()
	}
}

func initiateWebRTCConnection(userID string, channelID uint) {
	// Send WebRTC configuration and initiate connection
	if jsonBroadcaster != nil {
		config := map[string]interface{}{
			"iceServers": []map[string]interface{}{
				{
					"urls": []string{"stun:stun.l.google.com:19302"},
				},
			},
		}

		jsonBroadcaster.SendMessageToUser(userID, "webrtc_config", map[string]interface{}{
			"channel_id": channelID,
			"config":     config,
		})

		// Tell client to create offer
		jsonBroadcaster.SendMessageToUser(userID, "create_webrtc_offer", map[string]interface{}{
			"channel_id": channelID,
		})
	}
}

// HandleSignalingMessage processes WebRTC signaling messages
func HandleSignalingMessage(userID string, msgType string, data map[string]interface{}) error {
	signalingMsg := webrtc.SignalingMessage{
		Type: msgType,
		From: userID,
		Data: data,
	}

	// Extract channel from data if available
	if channelID, ok := data["channel_id"].(float64); ok {
		signalingMsg.ChannelID = uint(channelID)
	}

	return webrtc.GlobalSignalingServer.HandleSignalingMessage(signalingMsg)
}
