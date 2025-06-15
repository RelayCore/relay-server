package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"relay-server/internal/channel"
	"relay-server/internal/db"
	"relay-server/internal/user"
	"relay-server/internal/util"
	"relay-server/internal/voice"
)

type JoinVoiceRequest struct {
	ChannelID uint `json:"channel_id"`
}

type LeaveVoiceRequest struct {
	ChannelID uint `json:"channel_id"`
}

type VoiceStateRequest struct {
	ChannelID  uint `json:"channel_id"`
	IsMuted    bool `json:"is_muted"`
	IsDeafened bool `json:"is_deafened"`
}

type VoiceRoomResponse struct {
	ID          uint                       `json:"id"`
	ChannelID   uint                       `json:"channel_id"`
	ChannelName string                     `json:"channel_name"`
	IsActive    bool                       `json:"is_active"`
	Participants []VoiceParticipantResponse `json:"participants"`
	CreatedAt   time.Time                  `json:"created_at"`
}

type VoiceParticipantResponse struct {
	ID         uint      `json:"id"`
	UserID     string    `json:"user_id"`
	Username   string    `json:"username"`
	Nickname   string    `json:"nickname"`
	IsMuted    bool      `json:"is_muted"`
	IsDeafened bool      `json:"is_deafened"`
	IsSpeaking bool      `json:"is_speaking"`
	JoinedAt   time.Time `json:"joined_at"`
	ProfilePictureURL string `json:"profile_picture_url"`
}

func JoinVoiceHandler(w http.ResponseWriter, r *http.Request) {
	var req JoinVoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := r.Context().Value("user_id").(string)
	userObj := r.Context().Value("user").(*user.User)

	// Check permission
	if !userObj.HasPermission(user.PermissionJoinVoice) {
		http.Error(w, "No permission to join voice channels", http.StatusForbidden)
		return
	}

	// Verify channel exists and is a voice channel
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow joining voice channels
	if ch.Type != channel.ChannelTypeVoice {
		http.Error(w, "Can only join voice channels", http.StatusBadRequest)
		return
	}

	// Join voice room
	if err := voice.JoinVoiceRoom(r, userID, req.ChannelID); err != nil {
		http.Error(w, "Failed to join voice room", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "joined",
		"message": "Successfully joined voice channel",
	})
}

func LeaveVoiceHandler(w http.ResponseWriter, r *http.Request) {
	var req LeaveVoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := r.Context().Value("user_id").(string)

	// Verify channel exists and is a voice channel
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow leaving voice channels
	if ch.Type != channel.ChannelTypeVoice {
		http.Error(w, "Can only leave voice channels", http.StatusBadRequest)
		return
	}

	// Leave voice room
	if err := voice.LeaveVoiceRoom(userID, req.ChannelID); err != nil {
		http.Error(w, "Failed to leave voice room", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "left",
		"message": "Successfully left voice channel",
	})
}

func UpdateVoiceStateHandler(w http.ResponseWriter, r *http.Request) {
	var req VoiceStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID := r.Context().Value("user_id").(string)

	// Verify channel exists and is a voice channel
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow updating voice state for voice channels
	if ch.Type != channel.ChannelTypeVoice {
		http.Error(w, "Can only update voice state for voice channels", http.StatusBadRequest)
		return
	}

	// Update voice state
	if err := voice.UpdateVoiceState(userID, req.ChannelID, req.IsMuted, req.IsDeafened); err != nil {
		http.Error(w, "Failed to update voice state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updated",
		"message": "Voice state updated successfully",
	})
}

func GetVoiceParticipantsHandler(w http.ResponseWriter, r *http.Request) {
	channelIDStr := r.URL.Query().Get("channel_id")
	if channelIDStr == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channelID, err := strconv.ParseUint(channelIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	// Verify channel exists and is a voice channel
	var ch channel.Channel
	if err := db.DB.First(&ch, uint(channelID)).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	// Only allow getting participants for voice channels
	if ch.Type != channel.ChannelTypeVoice {
		http.Error(w, "Can only get participants for voice channels", http.StatusBadRequest)
		return
	}

	participants := voice.GetVoiceParticipants(uint(channelID))

	// Convert to response format with profile picture URLs
	participantResponses := make([]VoiceParticipantResponse, 0, len(participants))
	for _, participant := range participants {
		profileURL := ""
		user.Mu.RLock()
		if userObj, exists := user.Users[participant.UserID]; exists && userObj.ProfilePictureHash != "" {
			profileURL = util.GetProfilePictureURL(r, participant.UserID)
		}
		user.Mu.RUnlock()

		participantResponses = append(participantResponses, VoiceParticipantResponse{
			UserID:            participant.UserID,
			Username:          participant.Username,
			Nickname:          participant.Nickname,
			IsMuted:           participant.IsMuted,
			IsDeafened:        participant.IsDeafened,
			IsSpeaking:        participant.IsSpeaking,
			JoinedAt:          participant.JoinedAt,
			ProfilePictureURL: profileURL,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"participants": participantResponses,
		"count":        len(participantResponses),
	})
}

// GetVoiceRoomsHandler returns all active voice rooms (only for voice channels)
func GetVoiceRoomsHandler(w http.ResponseWriter, r *http.Request) {
	roomData := voice.GetAllVoiceRooms()

	// Convert to response format with profile picture URLs
	roomResponses := make([]map[string]interface{}, 0, len(roomData))
	for _, room := range roomData {
		participants, ok := room["participants"].([]map[string]interface{})
		if !ok {
			continue
		}

		// Add profile picture URLs to participants
		for i, participant := range participants {
			if userID, ok := participant["user_id"].(string); ok {
				profileURL := ""
				user.Mu.RLock()
				if userObj, exists := user.Users[userID]; exists && userObj.ProfilePictureHash != "" {
					profileURL = util.GetProfilePictureURL(r, userID)
				}
				user.Mu.RUnlock()
				participants[i]["profile_picture_url"] = profileURL
			}
		}

		roomResponses = append(roomResponses, room)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"voice_rooms": roomResponses,
	})
}

// JoinVoiceRoomHandler allows a user to join a voice room
func JoinVoiceRoomHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChannelID uint `json:"channel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ChannelID == 0 {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	// Verify channel exists and is a voice channel
	var ch channel.Channel
	if err := db.DB.First(&ch, req.ChannelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return
	}

	if ch.Type != channel.ChannelTypeVoice {
		http.Error(w, "Can only join voice channels", http.StatusBadRequest)
		return
	}

	// Join voice room
	if err := voice.JoinVoiceRoom(r, userID, req.ChannelID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get participant info for response
	participants := voice.GetVoiceParticipants(req.ChannelID)
	var participant *voice.VoiceParticipant
	for _, p := range participants {
		if p.UserID == userID {
			participant = p
			break
		}
	}

	if participant == nil {
		http.Error(w, "Failed to join voice room", http.StatusInternalServerError)
		return
	}

	profileURL := ""
	user.Mu.RLock()
	if userObj, exists := user.Users[participant.UserID]; exists && userObj.ProfilePictureHash != "" {
		profileURL = util.GetProfilePictureURL(r, participant.UserID)
	}
	user.Mu.RUnlock()

	response := VoiceParticipantResponse{
		UserID:            participant.UserID,
		Username:          participant.Username,
		Nickname:          participant.Nickname,
		IsMuted:           participant.IsMuted,
		IsDeafened:        participant.IsDeafened,
		IsSpeaking:        participant.IsSpeaking,
		JoinedAt:          participant.JoinedAt,
		ProfilePictureURL: profileURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// LeaveVoiceRoomHandler allows a user to leave a voice room
func LeaveVoiceRoomHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	if userID == "" {
		http.Error(w, "User ID not found", http.StatusUnauthorized)
		return
	}

	channelIDStr := r.URL.Query().Get("channel_id")
	if channelIDStr == "" {
		http.Error(w, "Channel ID is required", http.StatusBadRequest)
		return
	}

	channelID, err := strconv.ParseUint(channelIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	// Leave voice room
	if err := voice.LeaveVoiceRoom(userID, uint(channelID)); err != nil {
		// Don't error if user wasn't in room
		log.Printf("Leave voice room warning: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Left voice room successfully",
	})
}