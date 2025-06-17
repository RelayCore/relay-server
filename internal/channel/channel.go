package channel

import (
	"time"

	"gorm.io/gorm"
)

type ChannelType string

const (
	ChannelTypeText  ChannelType = "text"
	ChannelTypeVoice ChannelType = "voice"
)

type Channel struct {
	gorm.Model
	Name          string
	Description   string
	GroupID       uint
	Position      int
	Type          ChannelType `gorm:"default:'text'"`
	LastMessageAt *time.Time  `json:"last_message_at,omitempty"`
	// Messages only exist for text channels - voice channels have no messages
	Messages    []Message `gorm:"constraint:OnDelete:CASCADE;"`
	Pinned      []Message `gorm:"many2many:channel_pins;constraint:OnDelete:CASCADE;"`
	Permissions []ChannelPermission `gorm:"constraint:OnDelete:CASCADE;"`
}

// IsVoiceChannel returns true if this is a voice channel
func (c *Channel) IsVoiceChannel() bool {
	return c.Type == ChannelTypeVoice
}

// IsTextChannel returns true if this is a text channel
func (c *Channel) IsTextChannel() bool {
	return c.Type == ChannelTypeText
}

// CanHaveMessages returns true if this channel type can have messages
func (c *Channel) CanHaveMessages() bool {
	return c.Type == ChannelTypeText
}

type Message struct {
	gorm.Model
	ChannelID uint
	AuthorID  string // link to user.ID
	Content   string // Text content (can be empty if only attachments)

	// Attachments - each message can have multiple files
	Attachments []Attachment `gorm:"foreignKey:MessageID"`
}

type AttachmentType string

const (
	AttachmentTypeFile  AttachmentType = "file"
	AttachmentTypeImage AttachmentType = "image"
	AttachmentTypeVideo AttachmentType = "video"
	AttachmentTypeAudio AttachmentType = "audio"
)

type Attachment struct {
	gorm.Model
	MessageID     uint
	Type          AttachmentType
	FileName      string
	FileSize      int64
	FilePath      string
	MimeType      string
	FileHash      string  `gorm:"index"` // For deduplication
	ThumbnailPath *string `json:"thumbnail_path,omitempty"`
}

type VoiceRoom struct {
	gorm.Model
	ChannelID uint
	IsActive  bool
	VoiceParticipants []VoiceParticipant `gorm:"foreignKey:VoiceRoomID"`
}

type VoiceParticipant struct {
	gorm.Model
	VoiceRoomID uint
	UserID      string
	IsMuted     bool
	IsDeafened  bool
	IsSpeaking  bool
	JoinedAt    time.Time
	VoiceRoom   VoiceRoom `gorm:"foreignKey:VoiceRoomID"`
}
