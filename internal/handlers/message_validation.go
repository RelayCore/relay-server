package handlers

import (
	"net/http"

	"chat-server/internal/channel"
	"chat-server/internal/db"
)

// ValidateTextChannelForMessages validates that a channel exists and is a text channel for message operations
func ValidateTextChannelForMessages(w http.ResponseWriter, channelID uint) (*channel.Channel, bool) {
	var ch channel.Channel
	if err := db.DB.First(&ch, channelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return nil, false
	}

	// Only allow message operations on text channels
	if ch.Type == channel.ChannelTypeVoice {
		http.Error(w, "Cannot send messages to voice channels", http.StatusBadRequest)
		return nil, false
	}

	return &ch, true
}

// ValidateVoiceChannelForVoice validates that a channel exists and is a voice channel for voice operations
func ValidateVoiceChannelForVoice(w http.ResponseWriter, channelID uint) (*channel.Channel, bool) {
	var ch channel.Channel
	if err := db.DB.First(&ch, channelID).Error; err != nil {
		http.Error(w, "Channel not found", http.StatusNotFound)
		return nil, false
	}

	// Only allow voice operations on voice channels
	if ch.Type == channel.ChannelTypeText {
		http.Error(w, "Cannot perform voice operations on text channels", http.StatusBadRequest)
		return nil, false
	}

	return &ch, true
}
