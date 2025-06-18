package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"relay-server/internal/config"
	"strconv"
	"strings"
	"time"
)

// TenorResponse represents the main response from Tenor API
type TenorResponse struct {
    Results []GIF    `json:"results"`
    Next    string   `json:"next"`
}

// GIF represents a single GIF from Tenor
type GIF struct {
    ID               string                      `json:"id"`
    Title            string                      `json:"title"`
    ContentDesc      string                      `json:"content_description"`
    Created          float64                     `json:"created"`
    ItemURL          string                      `json:"itemurl"`
    URL              string                      `json:"url"`
    Tags             []string                    `json:"tags"`
    MediaFormats     map[string]MediaObject      `json:"media_formats"`
    HasAudio         bool                        `json:"hasaudio"`
    HasCaption       bool                        `json:"hascaption"`
    Flags            []string                    `json:"flags"`  // Changed from string to []string
    BgColor          string                      `json:"bg_color"`
}

// MediaObject represents the media format details
type MediaObject struct {
    URL      string    `json:"url"`
    Dims     []int     `json:"dims"`
    Duration float64   `json:"duration"`
    Size     int       `json:"size"`
}

// Client wraps the Tenor API
type Client struct {
    APIKey     string
    BaseURL    string
    ClientKey  string
    HTTPClient *http.Client
}

// NewClient creates a new Tenor API client
func NewClient() *Client {
    apiKey := strings.TrimSpace(config.Conf.TenorAPIKey)
    if apiKey == "" {
        return nil // Return nil if no API key is configured
    }

    // Simplify server name using regex
    serverName := simplifyServerName(config.Conf.Name)
    clientKey := fmt.Sprintf("relay-server-%s", serverName)

    return &Client{
        APIKey:    apiKey,
        BaseURL:   "https://tenor.googleapis.com/v2",
        ClientKey: clientKey,
        HTTPClient: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

func simplifyServerName(name string) string {
    if name == "" {
        return "default"
    }

    simplified := strings.ToLower(name)
    reg := regexp.MustCompile(`[^a-z0-9]+`)
    simplified = reg.ReplaceAllString(simplified, "-")
    simplified = strings.Trim(simplified, "-")

    // If empty after cleanup, use default
    if simplified == "" {
        return "default"
    }

    return simplified
}

// SearchOptions represents options for searching GIFs
type SearchOptions struct {
    Query         string // Search term
    Limit         int    // Number of results (1-50, default 20)
    Pos           string // Position for pagination
    Locale        string // Language/locale (default "en_US")
    ContentFilter string // Content filter level: "off", "low", "medium", "high"
}

// Search searches for GIFs based on a query
func (c *Client) Search(opts SearchOptions) (*TenorResponse, error) {
    if c == nil {
        return nil, fmt.Errorf("tenor client not initialized - API key may be missing")
    }

    params := url.Values{}
    params.Set("key", c.APIKey)
    params.Set("client_key", c.ClientKey)
    params.Set("q", opts.Query)

    // Add strongly recommended parameters
    params.Set("country", "US")
    params.Set("locale", "en_US")
    params.Set("contentfilter", "medium")

    // Add media_filter to reduce response size and get the formats we want
    params.Set("media_filter", "gif,mp4,tinygif,tinymp4,preview")

    if opts.Limit > 0 {
        if opts.Limit > 50 {
            opts.Limit = 50
        }
        params.Set("limit", strconv.Itoa(opts.Limit))
    } else {
        params.Set("limit", "20")
    }

    if opts.Pos != "" {
        params.Set("pos", opts.Pos)
    }

    if opts.Locale != "" {
        params.Set("locale", opts.Locale)
    }

    if opts.ContentFilter != "" {
        params.Set("contentfilter", opts.ContentFilter)
    }

    searchURL := fmt.Sprintf("%s/search?%s", c.BaseURL, params.Encode())

    resp, err := c.HTTPClient.Get(searchURL)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("tenor API returned status %d", resp.StatusCode)
    }

    var tenorResp TenorResponse
    if err := json.NewDecoder(resp.Body).Decode(&tenorResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &tenorResp, nil
}

// GetTrending gets featured GIFs (using the Featured API endpoint)
func (c *Client) GetTrending(limit int, pos string) (*TenorResponse, error) {
    if c == nil {
        return nil, fmt.Errorf("tenor client not initialized - API key may be missing")
    }

    params := url.Values{}
    params.Set("key", c.APIKey)
    params.Set("client_key", c.ClientKey)

    // Add strongly recommended parameters
    params.Set("country", "US")
    params.Set("locale", "en_US")
    params.Set("contentfilter", "medium")
    params.Set("ar_range", "all")

    // Add media_filter to reduce response size and get the formats we want
    params.Set("media_filter", "gif,mp4,tinygif,tinymp4,preview")

    if limit > 0 {
        if limit > 50 {
            limit = 50
        }
        params.Set("limit", strconv.Itoa(limit))
    } else {
        params.Set("limit", "20")
    }

    if pos != "" {
        params.Set("pos", pos)
    }

    // Use the Featured endpoint instead of trending
    featuredURL := fmt.Sprintf("%s/featured?%s", c.BaseURL, params.Encode())

    resp, err := c.HTTPClient.Get(featuredURL)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("tenor API returned status %d", resp.StatusCode)
    }

    var tenorResp TenorResponse
    if err := json.NewDecoder(resp.Body).Decode(&tenorResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &tenorResp, nil
}

// GetCategories gets featured GIF categories
func (c *Client) GetCategories() ([]string, error) {
    if c == nil {
        return nil, fmt.Errorf("tenor client not initialized - API key may be missing")
    }

    params := url.Values{}
    params.Set("key", c.APIKey)
    params.Set("client_key", c.ClientKey)
    params.Set("country", "US")
    params.Set("locale", "en_US")
    params.Set("contentfilter", "medium")

    categoriesURL := fmt.Sprintf("%s/categories?%s", c.BaseURL, params.Encode())

    resp, err := c.HTTPClient.Get(categoriesURL)
    if err != nil {
        return nil, fmt.Errorf("failed to make request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("tenor API returned status %d", resp.StatusCode)
    }

    var categoriesResp struct {
        Tags []struct {
            SearchTerm string `json:"searchterm"`
            Path       string `json:"path"`
            Image      string `json:"image"`
            Name       string `json:"name"`
        } `json:"tags"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&categoriesResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    categories := make([]string, len(categoriesResp.Tags))
    for i, tag := range categoriesResp.Tags {
        categories[i] = tag.Name
    }

    return categories, nil
}

// GetBestMediaURL returns the best media URL for a GIF based on preference
// Preference order: mp4 -> gif -> tinymp4 -> tinygif
func (gif *GIF) GetBestMediaURL() string {
    if gif.MediaFormats == nil {
        return ""
    }

    // For mobile/web, MP4 is usually better than GIF (smaller file size, better quality)
    if media, exists := gif.MediaFormats["mp4"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to GIF
    if media, exists := gif.MediaFormats["gif"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to smaller MP4
    if media, exists := gif.MediaFormats["tinymp4"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to smaller GIF
    if media, exists := gif.MediaFormats["tinygif"]; exists && media.URL != "" {
        return media.URL
    }

    return ""
}

// GetPreviewURL returns a preview/thumbnail URL
func (gif *GIF) GetPreviewURL() string {
    if gif.MediaFormats == nil {
        return ""
    }

    // Try preview first
    if media, exists := gif.MediaFormats["preview"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to nano formats
    if media, exists := gif.MediaFormats["nanogif"]; exists && media.URL != "" {
        return media.URL
    }

    if media, exists := gif.MediaFormats["nanomp4"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to tiny formats
    if media, exists := gif.MediaFormats["tinygif"]; exists && media.URL != "" {
        return media.URL
    }

    if media, exists := gif.MediaFormats["tinymp4"]; exists && media.URL != "" {
        return media.URL
    }

    return ""
}

// GetMobileURL returns the best URL for mobile devices (smaller file sizes)
func (gif *GIF) GetMobileURL() string {
    if gif.MediaFormats == nil {
        return ""
    }

    // For mobile, prefer smaller formats
    if media, exists := gif.MediaFormats["tinymp4"]; exists && media.URL != "" {
        return media.URL
    }

    if media, exists := gif.MediaFormats["tinygif"]; exists && media.URL != "" {
        return media.URL
    }

    // Fall back to nano formats
    if media, exists := gif.MediaFormats["nanomp4"]; exists && media.URL != "" {
        return media.URL
    }

    if media, exists := gif.MediaFormats["nanogif"]; exists && media.URL != "" {
        return media.URL
    }

    // Last resort - full size
    return gif.GetBestMediaURL()
}

// HasFlag checks if the GIF has a specific flag
func (gif *GIF) HasFlag(flag string) bool {
    for _, f := range gif.Flags {
        if f == flag {
            return true
        }
    }
    return false
}

// IsSticker returns true if this is a sticker
func (gif *GIF) IsSticker() bool {
    return gif.HasFlag("sticker")
}

// IsStatic returns true if this is a static image
func (gif *GIF) IsStatic() bool {
    return gif.HasFlag("static")
}