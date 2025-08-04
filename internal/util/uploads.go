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
    defaultPort := "80"
    if r.TLS != nil {
        scheme = "https"
        defaultPort = "443"
    }

    if path != "" && path[0] != '/' {
        path = "/" + path
    }

    var host string
    var port string

    if config.Conf.Domain != "" {
        host = config.Conf.Domain
        port = config.Conf.Port
    } else {
        host, port, _ = net.SplitHostPort(r.Host)
        if host == "" {
            host = r.Host
        }
        if port == "" {
            port = config.Conf.Port
        }
    }

    if len(port) > 0 && port[0] == ':' {
        port = port[1:]
    }

    if port != "" && port != defaultPort {
        host = fmt.Sprintf("%s:%s", host, port)
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
