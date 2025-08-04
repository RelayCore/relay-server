package util

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"relay-server/internal/config"
)

func GetFullURL(r *http.Request, path string) string {
    scheme := "http"
    if r.TLS != nil {
        scheme = "https"
    }

    if path != "" && path[0] != '/' {
        path = "/" + path
    }

    host := r.Host
    if config.Conf.Domain != "" {
        _, port, err := net.SplitHostPort(r.Host)
        if err == nil && port != "" {
            host = fmt.Sprintf("%s:%s", config.Conf.Domain, port)
        } else {
            host = config.Conf.Domain
        }
    }

    return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func GetProfilePictureURL(r *http.Request, userID string) string {
	if userID == "" {
		return ""
	}

	// Check if profile picture file exists
	iconsDir := filepath.Join("uploads", "icons")
	matches, err := filepath.Glob(filepath.Join(iconsDir, userID+".*"))
	if err != nil || len(matches) == 0 {
		return ""
	}

	// Check if file actually exists
	if _, err := os.Stat(matches[0]); os.IsNotExist(err) {
		return ""
	}

	filename := filepath.Base(matches[0])
	return GetFullURL(r, fmt.Sprintf("uploads/icons/%s", filename))
}
