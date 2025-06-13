package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ServerConfig struct {
	Name           string `yaml:"name"`
	Description    string `yaml:"description"`
	AllowInvite    bool   `yaml:"allow_invite"`
	MaxUsers       int    `yaml:"max_users"`
	MaxFileSize    int64  `yaml:"max_file_size"`    // Max file size in MB
	MaxAttachments int    `yaml:"max_attachments"`  // Max number of attachments per message
	Icon           string `yaml:"icon,omitempty"`
	Port           string `yaml:"port,omitempty"`   // Server port, e.g. ":8080"
}

var Conf ServerConfig

func LoadConfig(path string) {
	f, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	yaml.Unmarshal(f, &Conf)

	// Set default max file size if not specified (50MB)
	if Conf.MaxFileSize == 0 {
		Conf.MaxFileSize = 50
	}

	// Set default max attachments if not specified
	if Conf.MaxAttachments == 0 {
		Conf.MaxAttachments = 10
	}

	// Convert MB to bytes for internal use
	Conf.MaxFileSize = Conf.MaxFileSize * 1024 * 1024

	// Set default port if not specified
	if Conf.Port == "" {
		Conf.Port = ":8080"
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig(path string) error {
	// Create a copy of the config with file size in MB for saving
	configCopy := Conf
	configCopy.MaxFileSize = configCopy.MaxFileSize / (1024 * 1024)

	data, err := yaml.Marshal(&configCopy)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}