package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type ServerConfig struct {
	Name           string `yaml:"name"`
	Description    string `yaml:"description"`
	AllowInvite    bool   `yaml:"allow_invite"`
	MaxUsers       int    `yaml:"max_users"`
	MaxFileSize    int64  `yaml:"max_file_size"`
	MaxImageSize   int    `yaml:"max_image_size,omitempty"`
	MaxAttachments int    `yaml:"max_attachments"`
	Icon           string `yaml:"icon,omitempty"`
	Port           string `yaml:"port,omitempty"`
	TenorAPIKey    string `yaml:"tenor_api_key,omitempty"`
	Domain         string `yaml:"domain,omitempty"`
}

var Conf ServerConfig

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig(path string) error {
	defaultConfig := ServerConfig{
		Name:           "Relay Server",
		Description:    "A real-time communication server",
		AllowInvite:    true,
		MaxUsers:       100,
		MaxFileSize:    52428800,
		MaxImageSize:   2000,
		MaxAttachments: 10,
		Icon:           "",
		Port:           ":36954",
		TenorAPIKey:    "",
		Domain:         "",
	}

	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func LoadConfig(path string) {
	// Check if config file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Config file '%s' not found, creating default configuration...", path)
		if err := CreateDefaultConfig(path); err != nil {
			log.Printf("Failed to create default config: %v", err)
			panic(err)
		}
		log.Printf("Default configuration created at '%s'", path)
	}

	f, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	yaml.Unmarshal(f, &Conf)
	log.Printf("Loaded config: %+v", Conf)

	if Conf.MaxFileSize == 0 {
		Conf.MaxFileSize = 52428800
	}

	if Conf.MaxImageSize == 0 {
        Conf.MaxImageSize = 2000
    }

	if Conf.MaxAttachments == 0 {
		Conf.MaxAttachments = 10
	}

	if Conf.Port == "" {
		Conf.Port = ":36954"
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig(path string) error {
	configCopy := Conf

	data, err := yaml.Marshal(&configCopy)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}