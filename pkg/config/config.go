package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// Config holds application configuration
type Config struct {
	Port              string `json:"port"`
	DataDir           string `json:"dataDir"`
	ProcessedDir      string `json:"processedDir"`
	RawDir            string `json:"rawDir"`
	BloomFilterPath   string `json:"bloomFilterPath"`
	IPsPath           string `json:"ipsPath"`
	CIDRsPath         string `json:"cidrsPath"`
	UpdateIntervalMin int    `json:"updateIntervalMin"`
}

// DefaultConfig creates a default configuration
func DefaultConfig() *Config {
	// Determine base directory
	execPath, err := os.Executable()
	if err != nil {
		execPath = "."
	}
	baseDir := filepath.Dir(execPath)

	// Define data directories
	dataDir := filepath.Join(baseDir, "..", "data")
	processedDir := filepath.Join(dataDir, "processed")
	rawDir := filepath.Join(dataDir, "raw")

	// Create default config
	config := &Config{
		Port:              "8080",
		DataDir:           dataDir,
		ProcessedDir:      processedDir,
		RawDir:            rawDir,
		BloomFilterPath:   filepath.Join(processedDir, "bloom-filter.json"),
		IPsPath:           filepath.Join(processedDir, "all-ips.json"),
		CIDRsPath:         filepath.Join(processedDir, "all-cidrs.json"),
		UpdateIntervalMin: 60, // Update every hour by default
	}

	// Override with environment variables if provided
	config.loadFromEnv()

	return config
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Override with environment variables
	config.loadFromEnv()

	return config, nil
}

// loadFromEnv overrides configuration with environment variables
func (c *Config) loadFromEnv() {
	if port := os.Getenv("PORT"); port != "" {
		c.Port = port
	}

	if dataDir := os.Getenv("DATA_DIR"); dataDir != "" {
		c.DataDir = dataDir
	}

	if processedDir := os.Getenv("PROCESSED_DIR"); processedDir != "" {
		c.ProcessedDir = processedDir
	}

	if rawDir := os.Getenv("RAW_DIR"); rawDir != "" {
		c.RawDir = rawDir
	}

	if bloomFilterPath := os.Getenv("BLOOM_FILTER_PATH"); bloomFilterPath != "" {
		c.BloomFilterPath = bloomFilterPath
	}

	if ipsPath := os.Getenv("IPS_PATH"); ipsPath != "" {
		c.IPsPath = ipsPath
	}

	if cidrsPath := os.Getenv("CIDRS_PATH"); cidrsPath != "" {
		c.CIDRsPath = cidrsPath
	}

	if updateIntervalStr := os.Getenv("UPDATE_INTERVAL_MIN"); updateIntervalStr != "" {
		if updateInterval, err := strconv.Atoi(updateIntervalStr); err == nil && updateInterval > 0 {
			c.UpdateIntervalMin = updateInterval
		}
	}
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// EnsureDirectories ensures all required directories exist
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.DataDir,
		c.ProcessedDir,
		c.RawDir,
		filepath.Join(c.RawDir, "vpn"),
		filepath.Join(c.RawDir, "proxy"),
		filepath.Join(c.RawDir, "tor"),
		filepath.Join(c.RawDir, "hosting"),
		filepath.Join(c.RawDir, "malicious"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}
