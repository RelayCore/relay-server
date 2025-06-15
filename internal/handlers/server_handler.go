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
	"relay-server/internal/util"
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
}

// GetServerMetadataHandler returns server metadata information
func GetServerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	// Convert bytes back to MB for the response
	maxFileSizeMB := config.Conf.MaxFileSize / (1024 * 1024)

	// Set icon path to the full URL if icon exists, empty if not
	iconPath := ""
	if config.Conf.Icon != "" {
		iconPath = util.GetFullURL(r, config.Conf.Icon)
	}

	currentUsers := getCurrentUserCount()
	metadata := ServerMetadataResponse{
		Name:           config.Conf.Name,
		Description:    config.Conf.Description,
		AllowInvite:    config.Conf.AllowInvite,
		MaxUsers:       config.Conf.MaxUsers,
		CurrentUsers:   currentUsers,
		MaxFileSize:    maxFileSizeMB,
		MaxAttachments: config.Conf.MaxAttachments,
		Icon:           iconPath,
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
