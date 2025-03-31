package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byigitt/check-ip/pkg/api"
	"github.com/byigitt/check-ip/pkg/bloom"
	"github.com/byigitt/check-ip/pkg/config"
	"github.com/byigitt/check-ip/pkg/logger"
	"github.com/byigitt/check-ip/pkg/scripts"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file if present
	loadEnvFile()

	// Load configuration
	cfg := config.DefaultConfig()
	logger.Init("configuration loaded")

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		logger.Error("failed to create required directories", err)
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Create stop channel for graceful shutdown
	stopCh := make(chan struct{})

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal, stopping services")
		close(stopCh)
	}()

	// Initialize the IP bloom filter
	var filter *bloom.IPBloomFilter
	var err error

	// Try to load existing filter
	logger.Info("attempting to load ip filter from disk")
	filter, err = bloom.LoadFromFile(
		cfg.BloomFilterPath,
		cfg.IPsPath,
		cfg.CIDRsPath,
	)

	if err != nil {
		logger.Warning(fmt.Sprintf("could not load existing filter: %v", err))
		logger.Init("creating new ip filter and updating vpn ip lists")

		// Create empty filter
		filter = bloom.New(1000000, 0.01)

		// Update IP lists and filter
		if err := scripts.Update(cfg, filter); err != nil {
			logger.Error("failed to update ip lists", err)
			log.Fatalf("Failed to update IP lists: %v", err)
		}

		// No need to load the filter again since it was updated in-place
	}

	// Start scheduled updates
	updateInterval := time.Duration(cfg.UpdateIntervalMin) * time.Minute
	scripts.StartScheduledUpdates(cfg, updateInterval, stopCh)
	logger.Success(fmt.Sprintf("vpn ip filter ready with %d ips and %d cidrs",
		filter.GetStats().ElementCount, len(filter.GetCIDRs())))

	// Create and start the API
	apiService := api.New(cfg, filter)
	logger.Init(fmt.Sprintf("starting server on port %s", cfg.Port))

	// Run the server
	if err := apiService.Run(); err != nil {
		logger.Error("failed to start server", err)
		log.Fatalf("Failed to start server: %v", err)
	}
}

// loadEnvFile loads environment variables from .env files
func loadEnvFile() {
	// Try to load from current directory first
	if err := godotenv.Load(); err == nil {
		logger.Success("loaded environment from .env file")
		return
	}

	// Try to load from parent directory (project root)
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	parentDir := filepath.Dir(filepath.Dir(exePath))
	envPath := filepath.Join(parentDir, ".env")

	if err := godotenv.Load(envPath); err == nil {
		logger.Success(fmt.Sprintf("loaded environment from %s", envPath))
	} else {
		logger.Info("no .env file found, using default configuration")
	}
}

// printBanner prints the application banner
func printBanner() {
	banner := `
    _____ _____    ____  _______ _   _       _____ _    _ ______ _____ _  ________ _____  
   / ____|  __ \  / __ \|__   __| \ | |     / ____| |  | |  ____/ ____| |/ /  ____|  __ \ 
  | |  __| |  | || |  | |  | |  |  \| |    | |    | |__| | |__ | |    | ' /| |__  | |__) |
  | | |_ | |  | || |  | |  | |  | . ' |    | |    |  __  |  __|| |    |  < |  __| |  _  / 
  | |__| | |__| || |__| |  | |  | |\  |    | |____| |  | | |___| |____| . \| |____| | \ \ 
   \_____|_____/  \____/   |_|  |_| \_|     \_____|_|  |_|______\_____|_|\_\______|_|  \_\
                                                                                          
                                                                        v1.0.0
`
	fmt.Println(banner)
	logger.Init("initializing ip vpn checker")
}
