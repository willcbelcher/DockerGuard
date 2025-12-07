package registry

import (
	"dockerguard/internal/dockerfile"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Manifest represents a Docker Image Manifest V2 or Manifest List
type Manifest struct {
	MediaType string `json:"mediaType"`
	// For V2 Manifest
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	// Handles manifest lists
	Digest string `json:"digest"`
}

// GetBaseImage fetches the base image and converts it to a Dockerfile struct
func GetBaseImage(image string) (*dockerfile.Dockerfile, error) {

	//parse the image name and tag from base image passed in from analyzer
	name, tag, err := parseImage(image)
	if err != nil {
		return nil, err
	}

	// Get token to be able to fetch manifest
	token, err := getToken(name)
	if err != nil {
		return nil, err
	}

	// Get docker manifest. The manifest is what contains the digest with the image history to assemble the base image commands
	manifest, err := GetManifest(name, tag, token)
	if err != nil {
		return nil, err
	}

	// Get image Config from the manifest digest
	var imageConfig *ImageConfig
	if manifest.Config.Digest != "" {
		imageConfig, err = GetImageConfig(name, manifest.Config.Digest, token)
		if err != nil {
			return nil, err
		}
	} else {
		imageConfig, err = GetImageConfig(name, manifest.Digest, token)
		if err != nil {
			return nil, err
		}
	}

	// Convert history to dockerfile struct
	var historyItems []dockerfile.HistoryItem
	for _, item := range imageConfig.History {
		historyItems = append(historyItems, dockerfile.HistoryItem{
			CreatedBy: item.CreatedBy,
		})
	}

	return dockerfile.FromHistory(historyItems), nil

}

// GetManifest fetches the image manifest, returns the manifest object
func GetManifest(name, tag, token string) (*Manifest, error) {
	url := "https://registry-1.docker.io/v2/" + name + "/manifests/" + tag
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Accept V2 manifests and Manifest Lists
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get manifest: %d - %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	// fmt.Println("body: ", string(body))

	// Some docker registry images have multiple manifests to handle different architectures
	// If the response body is a manifest list, parse out the first one and put it into a manifest struct
	// This is a simple if unelegant solution to just checking the base image static vulnerabilities
	if strings.Contains(string(body), "manifests") {
		var manifestList struct {
			Manifests []Manifest `json:"manifests"`
		}
		err = json.Unmarshal(body, &manifestList)
		if err != nil {
			return nil, err
		}

		// Recursively call GetManifest with the first manifest
		return GetManifest(name, manifestList.Manifests[0].Digest, token)
	}

	var manifest Manifest
	// Decode the response body into a manifest object
	err = json.Unmarshal(body, &manifest)
	if err != nil {
		return nil, err
	}

	return &manifest, nil
}

// ImageConfig represents the image configuration JSON
type ImageConfig struct {
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// GetImageConfig fetches the image configuration blob
func GetImageConfig(name, digest, token string) (*ImageConfig, error) {
	// Format url and make request
	url := "https://registry-1.docker.io/v2/" + name + "/blobs/" + digest
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get config: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// We care about the history of the image, which contains the Dockerfile instructions
	var config ImageConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// parses an image reference into name and tag
func parseImage(image string) (name, tag string, err error) {
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

// getToken fetches an anonymous token for the given repository
func getToken(name string) (string, error) {

	client := &http.Client{}

	// Need to get anonymous token to fetch image data
	tokenUrl := "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + name + ":pull"
	req, err := http.NewRequest("GET", tokenUrl, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	type tokenResp struct {
		Token string `json:"token"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var token tokenResp
	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}

	return token.Token, nil
}
