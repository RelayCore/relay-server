package channel

import "gorm.io/gorm"

type ChannelPermission struct {
    gorm.Model
    ChannelID uint

    // Target: either UserID or RoleName
    UserID   *string `gorm:"index"` // Nullable
    RoleName *string `gorm:"index"` // Nullable

    // Permissions
    CanRead  bool
    CanWrite bool
    CanPin   bool
    IsAdmin  bool
}
