package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dockerguard/internal/dockerfile"
)

// Client handles communication with Docker registries
type Client struct {
	httpClient *http.Client
	baseURL    string
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

	// Parse image name and tag from base image passed in from analyzer
	name, tag, err := c.parseImage(image)
	if err != nil {
		return nil, err
	}

	// Get Image Manifest to find Config Digest
	manifest, err := c.GetManifest(name, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	// Get image Config (history)
	// Docker image config is a JSON blob that contains the history of the image, which has the Dockerfile instructions
	config, err := c.GetImageConfig(name, manifest.Config.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to get image config: %w", err)
	}

	// Convert history to dockerfile
	var historyItems []dockerfile.HistoryItem
	for _, item := range config.History {
		historyItems = append(historyItems, dockerfile.HistoryItem{
			CreatedBy: item.CreatedBy,
		})
	}

	return dockerfile.FromHistory(historyItems), nil
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

// GetManifest fetches the image manifest, returns the manifest object
func (c *Client) GetManifest(name, tag string) (*Manifest, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", c.baseURL, name, tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

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
	// Decode the response body into a manifest object
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	// If it's a manifest list, just pick the first one
	// Maybe not the best approach, but simpler and easier, and gets at the heart of the actual Security concerns
	if len(manifest.Manifests) > 0 {
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

	// Format url and make request
	url := fmt.Sprintf("%s/%s/blobs/%s", c.baseURL, name, digest)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get config: %d", resp.StatusCode)
	}

	// Decode the response body into an image config object
	var config ImageConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// parses an image reference into name and tag
func (c *Client) parseImage(image string) (name, tag string, err error) {
	parts := strings.Split(image, ":")
	imageName := parts[0]
	tag = "latest" // default tag
	if len(parts) > 1 {
		tag = parts[1]
	}

	// Handle library images (e.g. ubuntu -> library/ubuntu)
	if !strings.Contains(imageName, "/") {
		imageName = "library/" + imageName
	}

	return imageName, tag, nil
}
