package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dockerguard/dockerguard/internal/dockerfile"
)

// Client handles communication with Docker registries
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient creates a new registry client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://registry-1.docker.io/v2",
	}
}

// CheckBaseImage fetches the base image and converts it to a Dockerfile struct
func (c *Client) CheckBaseImage(image string) (*dockerfile.Dockerfile, error) {
	name, tag, err := c.parseImage(image)
	if err != nil {
		return nil, err
	}

	// 1. Authenticate
	if err := c.Authenticate(name); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// 2. Get Image Manifest to find Config Digest
	manifest, err := c.GetManifest(name, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	// 3. Get Image Config (History)
	config, err := c.GetImageConfig(name, manifest.Config.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to get image config: %w", err)
	}

	// 4. Convert History to "Virtual Dockerfile"
	var historyItems []dockerfile.HistoryItem
	for _, item := range config.History {
		historyItems = append(historyItems, dockerfile.HistoryItem{
			CreatedBy: item.CreatedBy,
		})
	}

	return dockerfile.FromHistory(historyItems), nil
}

// Authenticate obtains a bearer token
func (c *Client) Authenticate(repository string) error {
	// Check for env vars
	username := os.Getenv("DOCKER_USERNAME")
	password := os.Getenv("DOCKER_PASSWORD")

	// Construct auth URL
	// Default to anonymous pull if no creds, but still need token
	service := "registry.docker.io"
	scope := fmt.Sprintf("repository:%s:pull", repository)
	authURL := fmt.Sprintf("https://auth.docker.io/token?service=%s&scope=%s", service, scope)

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return err
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	c.token = tokenResp.Token
	return nil
}

// Manifest represents a Docker Image Manifest V2 or Manifest List
type Manifest struct {
	MediaType string `json:"mediaType"`
	// For V2 Manifest
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	// For Manifest List
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			Os           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}

// GetManifest fetches the image manifest
func (c *Client) GetManifest(name, tag string) (*Manifest, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", c.baseURL, name, tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	// Accept V2 manifests and Manifest Lists
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get manifest: %d - %s", resp.StatusCode, string(body))
	}

	var manifest Manifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	// If it's a manifest list, find the linux/amd64 manifest and fetch that
	if len(manifest.Manifests) > 0 {
		for _, m := range manifest.Manifests {
			if m.Platform.Architecture == "amd64" && m.Platform.Os == "linux" {
				// Fetch the specific manifest for this digest
				return c.GetManifest(name, m.Digest)
			}
		}
		// Fallback to first if no match found
		return c.GetManifest(name, manifest.Manifests[0].Digest)
	}

	return &manifest, nil
}

// ImageConfig represents the image configuration JSON
type ImageConfig struct {
	Architecture string `json:"architecture"`
	Os           string `json:"os"`
	History      []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// GetImageConfig fetches the image configuration blob
func (c *Client) GetImageConfig(name, digest string) (*ImageConfig, error) {
	url := fmt.Sprintf("%s/%s/blobs/%s", c.baseURL, name, digest)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get config: %d", resp.StatusCode)
	}

	var config ImageConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// parseImage parses an image reference into name and tag
func (c *Client) parseImage(image string) (name, tag string, err error) {
	parts := strings.Split(image, ":")
	imageName := parts[0]
	tag = "latest"
	if len(parts) > 1 {
		tag = parts[1]
	}

	// Handle library images (e.g. ubuntu -> library/ubuntu)
	if !strings.Contains(imageName, "/") {
		imageName = "library/" + imageName
	}

	return imageName, tag, nil
}
