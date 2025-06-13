package channel

import (
	"chat-server/internal/db"
	"chat-server/internal/user"
)

// CanUserAccessChannel checks if a user can read a channel
func CanUserAccessChannel(userID string, channelID uint) bool {
	// Get user's roles
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		return false
	}

	// Server admins can access everything
	if userObj.HasPermission(user.PermissionManageServer) {
		return true
	}

	// Check specific user permissions
	var userPermission ChannelPermission
	if err := db.DB.Where("channel_id = ? AND user_id = ?", channelID, userID).First(&userPermission).Error; err == nil {
		return userPermission.CanRead
	}

	// Check role-based permissions
	for _, roleID := range userObj.RoleIDs {
		var rolePermission ChannelPermission
		if err := db.DB.Where("channel_id = ? AND role_name = ?", channelID, roleID).First(&rolePermission).Error; err == nil {
			if rolePermission.CanRead {
				return true
			}
		}
	}

	// Default: allow access if no explicit permissions are set
	var permissionCount int64
	db.DB.Model(&ChannelPermission{}).Where("channel_id = ?", channelID).Count(&permissionCount)
	return permissionCount == 0
}

// CanUserWriteToChannel checks if a user can write to a channel
func CanUserWriteToChannel(userID string, channelID uint) bool {
	// Get user's roles
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		return false
	}

	// Server admins can write to everything
	if userObj.HasPermission(user.PermissionManageServer) {
		return true
	}

	// Check specific user permissions
	var userPermission ChannelPermission
	if err := db.DB.Where("channel_id = ? AND user_id = ?", channelID, userID).First(&userPermission).Error; err == nil {
		return userPermission.CanWrite
	}

	// Check role-based permissions
	for _, roleID := range userObj.RoleIDs {
		var rolePermission ChannelPermission
		if err := db.DB.Where("channel_id = ? AND role_name = ?", channelID, roleID).First(&rolePermission).Error; err == nil {
			if rolePermission.CanWrite {
				return true
			}
		}
	}

	// Default: allow writing if no explicit permissions are set
	var permissionCount int64
	db.DB.Model(&ChannelPermission{}).Where("channel_id = ?", channelID).Count(&permissionCount)
	return permissionCount == 0
}

// CanUserManageChannel checks if a user can manage a channel
func CanUserManageChannel(userID string, channelID uint) bool {
	// Get user's roles
	user.Mu.RLock()
	userObj, exists := user.Users[userID]
	user.Mu.RUnlock()

	if !exists {
		return false
	}

	// Server admins can manage everything
	if userObj.HasPermission(user.PermissionManageServer) {
		return true
	}

	// Check if user has channel management permission
	if userObj.HasPermission(user.PermissionManageChannels) {
		return true
	}

	// Check specific user permissions
	var userPermission ChannelPermission
	if err := db.DB.Where("channel_id = ? AND user_id = ?", channelID, userID).First(&userPermission).Error; err == nil {
		return userPermission.IsAdmin
	}

	// Check role-based permissions
	for _, roleID := range userObj.RoleIDs {
		var rolePermission ChannelPermission
		if err := db.DB.Where("channel_id = ? AND role_name = ?", channelID, roleID).First(&rolePermission).Error; err == nil {
			if rolePermission.IsAdmin {
				return true
			}
		}
	}

	return false
}
