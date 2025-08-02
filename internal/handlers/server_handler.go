package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"relay-server/internal/config"
	"relay-server/internal/user"
	"relay-server/internal/websocket"
)

// ServerMetadataResponse represents the server metadata response
type ServerMetadataResponse struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	AllowInvite    bool   `json:"allow_invite"`
	MaxUsers       int    `json:"max_users"`
	CurrentUsers   int    `json:"current_users"`
	MaxFileSize    int64  `json:"max_file_size"`
	MaxAttachments int    `json:"max_attachments"`
	Icon           string `json:"icon,omitempty"`
	TenorEnabled   bool   `json:"tenor_enabled"`
}

// GetServerMetadataHandler returns server metadata information
func GetServerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	iconPath := ""
	if config.Conf.Icon != "" {
		// Check if icon file actually exists
		if _, err := os.Stat(config.Conf.Icon); err == nil {
			// Build the full URL using the request's host
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			iconPath = fmt.Sprintf("%s://%s/icon", scheme, r.Host)
		}
	}

	currentUsers := getCurrentUserCount()
	metadata := ServerMetadataResponse{
		Name:           config.Conf.Name,
		Description:    config.Conf.Description,
		AllowInvite:    config.Conf.AllowInvite,
		MaxUsers:       config.Conf.MaxUsers,
		CurrentUsers:   currentUsers,
		MaxFileSize:    config.Conf.MaxFileSize,
		MaxAttachments: config.Conf.MaxAttachments,
		Icon:           iconPath,
		TenorEnabled:   config.Conf.TenorAPIKey != "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// UploadServerIconHandler handles server icon uploads
func UploadServerIconHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form with 10MB max memory
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("icon")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	if !isValidImageType(contentType) {
		http.Error(w, "Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP are allowed", http.StatusBadRequest)
		return
	}

	// Validate file size (max 5MB)
	if header.Size > 5<<20 {
		http.Error(w, "File too large. Maximum size is 5MB", http.StatusBadRequest)
		return
	}

	// Remove existing icon file if it exists
	removeExistingIcon()

	// Generate filename with extension
	ext := getFileExtension(contentType)
	filename := fmt.Sprintf("icon%s", ext)

	// Create the file in root directory
	dst, err := os.Create(filename)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy file content
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Update configuration
	config.Conf.Icon = filename

	// Save configuration to file
	err = config.SaveConfig("config.yaml")
	if err != nil {
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Broadcast server icon update
	go func() {
		websocket.GlobalHub.BroadcastMessage("server_icon_updated", map[string]interface{}{
			"icon_url": filename,
		})
	}()

	// Return success response
	response := map[string]string{
		"message":  "Server icon uploaded successfully",
		"icon_url": filename,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetServerIconHandler serves the server icon file
func GetServerIconHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if icon is configured
	if config.Conf.Icon == "" {
		http.Error(w, "No server icon configured", http.StatusNotFound)
		return
	}

	// Check if icon file exists
	if _, err := os.Stat(config.Conf.Icon); os.IsNotExist(err) {
		http.Error(w, "Server icon file not found", http.StatusNotFound)
		return
	}

	// Open the icon file
	file, err := os.Open(config.Conf.Icon)
	if err != nil {
		http.Error(w, "Failed to open icon file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get file info for content type
	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, "Failed to get file info", http.StatusInternalServerError)
		return
	}

	// Set content type based on file extension
	contentType := getContentTypeFromFilename(config.Conf.Icon)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	// Set content length
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Serve the file
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Failed to serve icon file", http.StatusInternalServerError)
		return
	}
}

// removeExistingIcon removes any existing icon file in the root directory
func removeExistingIcon() {
	extensions := []string{".png", ".jpg", ".jpeg", ".gif", ".webp"}

	for _, ext := range extensions {
		filename := fmt.Sprintf("icon%s", ext)
		if _, err := os.Stat(filename); err == nil {
			os.Remove(filename)
		}
	}
}

// isValidImageType checks if the content type is a valid image
func isValidImageType(contentType string) bool {
	validTypes := []string{
		"image/png",
		"image/jpg",
		"image/jpeg",
		"image/gif",
		"image/webp",
	}

	for _, validType := range validTypes {
		if strings.EqualFold(contentType, validType) {
			return true
		}
	}
	return false
}

// getFileExtension returns the appropriate file extension for the content type
func getFileExtension(contentType string) string {
	switch strings.ToLower(contentType) {
	case "image/png":
		return ".png"
	case "image/jpg", "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		return ".png"
	}
}

// getContentTypeFromFilename determines content type from filename extension
func getContentTypeFromFilename(filename string) string {
	ext := strings.ToLower(filename[strings.LastIndex(filename, "."):])
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	default:
		return "image/png"
	}
}

// getCurrentUserCount returns the current number of users in the server
func getCurrentUserCount() int {
	user.Mu.Lock()
	defer user.Mu.Unlock()
	return len(user.Users)
}

type UpdateServerConfigRequest struct {
	Name           *string `json:"name,omitempty"`
	Description    *string `json:"description,omitempty"`
	AllowInvite    *bool   `json:"allow_invite,omitempty"`
	MaxUsers       *int    `json:"max_users,omitempty"`
	MaxFileSize    *int64  `json:"max_file_size,omitempty"`    // In Bytes
	MaxAttachments *int    `json:"max_attachments,omitempty"`
	TenorEnabled   *bool   `json:"tenor_enabled,omitempty"`
}

// UpdateServerConfigHandler handles server configuration updates
func UpdateServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateServerConfigRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Update configuration fields if provided
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			http.Error(w, "Server name cannot be empty", http.StatusBadRequest)
			return
		}
		config.Conf.Name = strings.TrimSpace(*req.Name)
	}

	if req.Description != nil {
		config.Conf.Description = strings.TrimSpace(*req.Description)
	}

	if req.AllowInvite != nil {
		config.Conf.AllowInvite = *req.AllowInvite
	}

	if req.MaxUsers != nil {
        if *req.MaxUsers < 1 {
            http.Error(w, "Max users must be at least 1", http.StatusBadRequest)
            return
        }

        // Check if new max users is at least the current number of users
        currentUsers := getCurrentUserCount()
        if *req.MaxUsers < currentUsers {
            http.Error(w, fmt.Sprintf("Max users cannot be less than current users (%d)", currentUsers), http.StatusBadRequest)
            return
        }

        config.Conf.MaxUsers = *req.MaxUsers
    }

	if req.MaxAttachments != nil {
		if *req.MaxAttachments < 1 || *req.MaxAttachments > 100 {
			http.Error(w, "Max attachments must be between 1 and 100", http.StatusBadRequest)
			return
		}
		config.Conf.MaxAttachments = *req.MaxAttachments
	}

	// Save configuration to file
	err = config.SaveConfig("config.yaml")
	if err != nil {
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// Return updated configuration
	response := map[string]interface{}{
		"message":         "Server configuration updated successfully",
		"name":            config.Conf.Name,
		"description":     config.Conf.Description,
		"allow_invite":    config.Conf.AllowInvite,
		"max_users":       config.Conf.MaxUsers,
		"max_file_size":   config.Conf.MaxFileSize,
		"max_attachments": config.Conf.MaxAttachments,
		"tenor_enabled":   config.Conf.TenorAPIKey != "",
	}

	// Broadcast server configuration update
	go func() {
		websocket.GlobalHub.BroadcastMessage("server_config_updated", map[string]interface{}{
			"name":            config.Conf.Name,
			"description":     config.Conf.Description,
			"allow_invite":    config.Conf.AllowInvite,
			"max_users":       config.Conf.MaxUsers,
			"max_attachments": config.Conf.MaxAttachments,
			"max_file_size":   config.Conf.MaxFileSize,
			"tenor_enabled":   config.Conf.TenorAPIKey != "",
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
