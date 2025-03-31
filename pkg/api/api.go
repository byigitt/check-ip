package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/byigitt/check-ip/pkg/bloom"
	"github.com/byigitt/check-ip/pkg/config"
	"github.com/byigitt/check-ip/pkg/logger"
	"github.com/gin-gonic/gin"
)

// Service is the main API service
type Service struct {
	Router *gin.Engine
	Config *config.Config
	Filter *bloom.IPBloomFilter
	Server *http.Server
}

// CheckResult represents the result of an IP check
type CheckResult struct {
	IP        string    `json:"ip"`
	IsVPN     bool      `json:"isVpn"`
	CheckedAt time.Time `json:"checkedAt"`
}

// StatsResult represents bloom filter statistics
type StatsResult struct {
	ElementCount   uint32    `json:"elementCount"`
	FalsePositives float64   `json:"falsePositiveRate"`
	FilterSize     uint      `json:"filterSize"`
	HashFunctions  uint      `json:"hashFunctions"`
	LastUpdated    time.Time `json:"lastUpdated"`
	CIDRCount      int       `json:"cidrCount"`
}

// New creates a new API service
func New(cfg *config.Config, filter *bloom.IPBloomFilter) *Service {
	// Set Gin to release mode in production
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.Default()

	// Create service
	service := &Service{
		Router: router,
		Config: cfg,
		Filter: filter,
	}

	// Create HTTP server
	service.Server = &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	// Set up routes
	service.setupRoutes()

	logger.Success("API routes configured successfully")

	return service
}

// setupRoutes defines the API routes
func (s *Service) setupRoutes() {
	// Root route
	s.Router.GET("/", s.handleRoot)

	// Health check
	s.Router.GET("/health", s.handleHealth)

	// API group
	api := s.Router.Group("/api")
	{
		// IP checking endpoint
		api.GET("/check/:ip", s.handleCheckIP)
		api.POST("/check", s.handleCheckIPPost)
		api.GET("/check", s.handleCheckIPHelp)

		// Bloom filter stats
		api.GET("/stats", s.handleStats)
	}
}

// handleRoot handles the root route
func (s *Service) handleRoot(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "IP VPN Checker API",
		"version":   "1.0.0",
		"endpoints": []string{"/api/check/:ip", "/api/check", "/api/stats", "/health"},
	})
}

// handleHealth handles the health check route
func (s *Service) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now(),
	})
}

// handleCheckIPHelp handles GET requests to /api/check without an IP
func (s *Service) handleCheckIPHelp(c *gin.Context) {
	logger.Info("showing help for check endpoint")
	c.JSON(http.StatusBadRequest, gin.H{
		"error":    "missing ip address parameter",
		"usage":    "use GET /api/check/1.2.3.4 to check a specific IP, or POST to /api/check with {\"ip\": \"1.2.3.4\"} in the request body",
		"examples": []string{"GET /api/check/8.8.8.8", "POST /api/check with {\"ip\": \"8.8.8.8\"}"},
	})
}

// handleCheckIP handles the GET IP check route
func (s *Service) handleCheckIP(c *gin.Context) {
	// Get IP from URL param
	ip := c.Param("ip")

	// Validate IP
	if net.ParseIP(ip) == nil {
		logger.Warning(fmt.Sprintf("Invalid IP address received: %s", ip))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IP address",
		})
		return
	}

	// Check if IP is a VPN
	isVPN := s.Filter.Check(ip)

	// Log the check
	if isVPN {
		logger.Info(fmt.Sprintf("IP %s identified as VPN/proxy", ip))
	} else {
		logger.Info(fmt.Sprintf("IP %s is not identified as VPN/proxy", ip))
	}

	// Return result
	c.JSON(http.StatusOK, CheckResult{
		IP:        ip,
		IsVPN:     isVPN,
		CheckedAt: time.Now(),
	})
}

// IPCheckRequest is the request body for the POST IP check
type IPCheckRequest struct {
	IP string `json:"ip" binding:"required"`
}

// handleCheckIPPost handles the POST IP check route
func (s *Service) handleCheckIPPost(c *gin.Context) {
	// Parse request body
	var req IPCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warning("Invalid request body received")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	// Validate IP
	if net.ParseIP(req.IP) == nil {
		logger.Warning(fmt.Sprintf("Invalid IP address received: %s", req.IP))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IP address",
		})
		return
	}

	// Check if IP is a VPN
	isVPN := s.Filter.Check(req.IP)

	// Log the check
	if isVPN {
		logger.Info(fmt.Sprintf("IP %s identified as VPN/proxy", req.IP))
	} else {
		logger.Info(fmt.Sprintf("IP %s is not identified as VPN/proxy", req.IP))
	}

	// Return result
	c.JSON(http.StatusOK, CheckResult{
		IP:        req.IP,
		IsVPN:     isVPN,
		CheckedAt: time.Now(),
	})
}

// handleStats handles the bloom filter stats route
func (s *Service) handleStats(c *gin.Context) {
	stats := s.Filter.GetStats()

	c.JSON(http.StatusOK, StatsResult{
		ElementCount:   stats.ElementCount,
		FalsePositives: stats.FalsePositives,
		FilterSize:     stats.FilterSize,
		HashFunctions:  stats.HashFunctions,
		LastUpdated:    stats.Timestamp,
		CIDRCount:      len(s.Filter.GetCIDRs()),
	})

	logger.Info(fmt.Sprintf("Stats request: %d IPs, %d CIDRs, %.5f%% false positive rate",
		stats.ElementCount, len(s.Filter.GetCIDRs()), stats.FalsePositives*100))
}

// Run starts the API server with graceful shutdown support
func (s *Service) Run() error {
	// Start server in a goroutine so it doesn't block
	go func() {
		logger.Info(fmt.Sprintf("server listening on port %s", s.Config.Port))
		if err := s.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", err)
		}
	}()

	// Return nil to unblock main thread
	return nil
}

// Shutdown gracefully stops the server
func (s *Service) Shutdown(ctx context.Context) error {
	logger.Info("shutting down server...")
	return s.Server.Shutdown(ctx)
}
