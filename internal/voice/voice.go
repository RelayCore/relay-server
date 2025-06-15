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
)

// MessageBroadcaster interface to avoid import cycle
type MessageBroadcaster interface {
    BroadcastMessage(messageType string, data interface{})
}

type VoiceParticipant struct {
    UserID     string    `json:"user_id"`
    Username   string    `json:"username"`
    Nickname   string    `json:"nickname"`
    IsMuted    bool      `json:"is_muted"`
    IsDeafened bool      `json:"is_deafened"`
    IsSpeaking bool      `json:"is_speaking"`
    JoinedAt   time.Time `json:"joined_at"`
    ProfilePictureURL string `json:"profile_picture_url"`
}

type VoiceRoom struct {
    ChannelID    uint
    Participants map[string]*VoiceParticipant
    AudioMixer   *AudioMixer
    mu           sync.RWMutex
}

type AudioFrame struct {
    UserID    string
    ChannelID uint
    Data      []byte
    Timestamp time.Time
}

type AudioMixer struct {
    inputChan    chan AudioFrame
    outputChan   chan AudioFrame
    participants map[string]chan AudioFrame
    speakingTimeout map[string]*time.Timer
    mu           sync.RWMutex
}

var (
    voiceRooms   = make(map[uint]*VoiceRoom)
    voiceRoomsMu sync.RWMutex
    broadcaster  MessageBroadcaster
)

// SetMessageBroadcaster sets the broadcaster instance
func SetMessageBroadcaster(b MessageBroadcaster) {
    broadcaster = b
}

func init() {
    // Start voice processing goroutine
    go processVoiceData()
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
            AudioMixer:   NewAudioMixer(),
        }
        voiceRooms[channelID] = room

        // Start audio mixer in a separate goroutine with proper error handling
        go func() {
            defer func() {
                if r := recover(); r != nil {
                    log.Printf("AudioMixer.Run() panic recovered: %v", r)
                }
            }()
            room.AudioMixer.Run()
        }()
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
    if userObj, exists := user.Users[userID]; exists && userObj.ProfilePictureHash != "" {
        profileURL = util.GetProfilePictureURL(r, userID)
    }

    // Add participant
    room.Participants[userID] = &VoiceParticipant{
        UserID:     userID,
        Username:   userObj.Username,
        Nickname:   userObj.Nickname,
        IsMuted:    false,
        IsDeafened: false,
        IsSpeaking: false,
        JoinedAt:   time.Now(),
        ProfilePictureURL: profileURL,
    }
    room.mu.Unlock()

    // Add participant to audio mixer
    room.AudioMixer.AddParticipant(userID)

    // Broadcast user joined voice
    broadcastVoiceUpdate(channelID, "user_joined_voice", map[string]interface{}{
        "user_id":    userID,
        "channel_id": channelID,
        "participant": room.Participants[userID],
    })

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

    // Remove from audio mixer
    room.AudioMixer.RemoveParticipant(userID)

    // If no participants left, clean up room
    if participantCount == 0 {
        room.AudioMixer.Stop()
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
        "user_id":      userID,
        "channel_id":   channelID,
        "is_muted":     isMuted,
        "is_deafened":  isDeafened,
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

func ProcessAudioData(userID string, channelID uint, audioData []byte) error {
    voiceRoomsMu.RLock()
    room, exists := voiceRooms[channelID]
    voiceRoomsMu.RUnlock()

    if !exists {
        return fmt.Errorf("voice room not found")
    }

    // Check if user is muted
    room.mu.RLock()
    participant, exists := room.Participants[userID]
    if !exists || participant.IsMuted {
        room.mu.RUnlock()
        return nil
    }
    room.mu.RUnlock()

    // Send audio to mixer
    frame := AudioFrame{
        UserID:    userID,
        ChannelID: channelID,
        Data:      audioData,
        Timestamp: time.Now(),
    }

    select {
    case room.AudioMixer.inputChan <- frame:
    default:
        // Channel full, drop frame
    }

    return nil
}

func NewAudioMixer() *AudioMixer {
    return &AudioMixer{
        inputChan:       make(chan AudioFrame, 100),
        outputChan:      make(chan AudioFrame, 100),
        participants:    make(map[string]chan AudioFrame),
        speakingTimeout: make(map[string]*time.Timer),
    }
}

func (am *AudioMixer) Run() {
    for frame := range am.inputChan {
        // Simple audio mixing: broadcast to all other participants
        am.mu.RLock()
        for participantID, outputChan := range am.participants {
            if participantID != frame.UserID {
                select {
                case outputChan <- frame:
                default:
                    // Channel full, skip this participant
                }
            }
        }
        am.mu.RUnlock()

        // Update speaking status to true
        updateSpeakingStatus(frame.UserID, frame.ChannelID, true)

        // Reset or create speaking timeout timer
        am.mu.Lock()
        if timer, exists := am.speakingTimeout[frame.UserID]; exists {
            timer.Stop()
        }
        am.speakingTimeout[frame.UserID] = time.AfterFunc(1*time.Second, func() {
            updateSpeakingStatus(frame.UserID, frame.ChannelID, false)
            am.mu.Lock()
            delete(am.speakingTimeout, frame.UserID)
            am.mu.Unlock()
        })
        am.mu.Unlock()
    }
}

func (am *AudioMixer) AddParticipant(userID string) {
    am.mu.Lock()
    am.participants[userID] = make(chan AudioFrame, 50)
    am.mu.Unlock()
}

func (am *AudioMixer) RemoveParticipant(userID string) {
    am.mu.Lock()
    if ch, exists := am.participants[userID]; exists {
        close(ch)
        delete(am.participants, userID)
    }
    // Clean up speaking timeout timer
    if timer, exists := am.speakingTimeout[userID]; exists {
        timer.Stop()
        delete(am.speakingTimeout, userID)
    }
    am.mu.Unlock()
}

func (am *AudioMixer) Stop() {
    close(am.inputChan)
    am.mu.Lock()
    for _, ch := range am.participants {
        close(ch)
    }
    // Stop all speaking timeout timers
    for _, timer := range am.speakingTimeout {
        timer.Stop()
    }
    am.participants = make(map[string]chan AudioFrame)
    am.speakingTimeout = make(map[string]*time.Timer)
    am.mu.Unlock()
}

func (am *AudioMixer) GetOutputChannel(userID string) <-chan AudioFrame {
    am.mu.RLock()
    defer am.mu.RUnlock()
    return am.participants[userID]
}

func processVoiceData() {
    // This goroutine handles voice data processing
    // In a real implementation, you might want to do audio processing here
    // like noise reduction, echo cancellation, etc.
}

func updateSpeakingStatus(userID string, channelID uint, isSpeaking bool) {
    voiceRoomsMu.RLock()
    room, exists := voiceRooms[channelID]
    voiceRoomsMu.RUnlock()

    if !exists {
        return
    }

    room.mu.Lock()
    participant, exists := room.Participants[userID]
    if exists && participant.IsSpeaking != isSpeaking {
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
}

// GetAllVoiceRooms returns all active voice rooms with their participants
func GetAllVoiceRooms() []map[string]interface{} {
    voiceRoomsMu.RLock()
    defer voiceRoomsMu.RUnlock()

    roomResponses := make([]map[string]interface{}, 0)
    for channelID, room := range voiceRooms {
        // Get channel information
        var ch channel.Channel
        if err := db.DB.First(&ch, channelID).Error; err != nil {
            continue // Skip if channel not found
        }

        // Only include voice channels
        if ch.Type != channel.ChannelTypeVoice {
            continue
        }

        room.mu.RLock()
        participants := make([]map[string]interface{}, 0, len(room.Participants))
        for _, participant := range room.Participants {
            participants = append(participants, map[string]interface{}{
                "user_id":     participant.UserID,
                "username":    participant.Username,
                "nickname":    participant.Nickname,
                "is_muted":    participant.IsMuted,
                "is_deafened": participant.IsDeafened,
                "is_speaking": participant.IsSpeaking,
                "joined_at":   participant.JoinedAt,
            })
        }
        room.mu.RUnlock()

        roomResponses = append(roomResponses, map[string]interface{}{
            "channel_id":    channelID,
            "channel_name":  ch.Name,
            "is_active":     true,
            "participants":  participants,
            "created_at":    time.Now(), // Since we don't track creation time in memory
        })
    }

    return roomResponses
}

func broadcastVoiceUpdate(channelID uint, eventType string, data interface{}) {
    if broadcaster != nil {
        // Make broadcast non-blocking
        go func() {
            defer func() {
                if r := recover(); r != nil {
                    log.Printf("broadcastVoiceUpdate: Panic recovered during broadcast: %v", r)
                }
            }()
			log.Printf("Broadcasting %s for channel %d with data: %v", eventType, channelID, data)
            broadcaster.BroadcastMessage(eventType, data)
        }()
    }
}

// DisconnectUserFromAllVoiceRooms removes a user from all voice rooms they're participating in
// This is called when a user's WebSocket connection is lost
func DisconnectUserFromAllVoiceRooms(userID string) {
    voiceRoomsMu.Lock()
    defer voiceRoomsMu.Unlock()

    var roomsToCleanup []uint

    // Find all rooms the user is in and remove them
    for channelID, room := range voiceRooms {
        room.mu.Lock()
        if _, exists := room.Participants[userID]; exists {
            // Remove participant from room
            delete(room.Participants, userID)

            log.Printf("User %s automatically disconnected from voice room %d", userID, channelID)

            // Remove from audio mixer
            room.AudioMixer.RemoveParticipant(userID)

            // Broadcast user left voice room
            if broadcaster != nil {
                go func(cID uint, uID string) {
                    defer func() {
                        if r := recover(); r != nil {
                            log.Printf("DisconnectUserFromAllVoiceRooms: Panic recovered during broadcast: %v", r)
                        }
                    }()
                    broadcaster.BroadcastMessage("user_left_voice", map[string]interface{}{
                        "user_id":    uID,
                        "channel_id": cID,
                    })
                }(channelID, userID)
            }

            // Mark room for cleanup if empty
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
                room.AudioMixer.Stop()
                room.mu.Unlock()
                delete(voiceRooms, channelID)
                log.Printf("Voice room %d cleaned up due to no participants", channelID)
            } else {
                room.mu.Unlock()
            }
        }
    }
}