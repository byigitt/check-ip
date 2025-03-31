package bloom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/byigitt/check-ip/pkg/logger"
)

// IPBloomFilter wraps the bloom filter implementation with functionality for IP checking
type IPBloomFilter struct {
	filter    *bloom.BloomFilter
	ipSet     map[string]struct{} // For exact verification
	cidrList  []string            // For CIDR range checks
	timestamp time.Time
	mu        sync.RWMutex // Mutex for thread-safe operations
}

// FilterStats contains statistics about the bloom filter
type FilterStats struct {
	ElementCount   uint32
	FalsePositives float64
	FilterSize     uint
	HashFunctions  uint
	Timestamp      time.Time
}

// New creates a new bloom filter with optimal size for IP checking
func New(capacity int, falsePositiveRate float64) *IPBloomFilter {
	// Create a new bloom filter
	filter := bloom.NewWithEstimates(uint(capacity), falsePositiveRate)
	logger.Init(fmt.Sprintf("Created new bloom filter with capacity %d and false positive rate %.4f", capacity, falsePositiveRate))

	// Pre-allocate the map with expected capacity
	ipSet := make(map[string]struct{}, capacity)

	return &IPBloomFilter{
		filter:    filter,
		ipSet:     ipSet,
		cidrList:  make([]string, 0, 100), // Pre-allocate with reasonable size
		timestamp: time.Now(),
	}
}

// Add adds an IP address to the bloom filter and exact match set
func (b *IPBloomFilter) Add(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.filter.Add([]byte(ip))
	b.ipSet[ip] = struct{}{}
}

// AddCIDR adds a CIDR range to the list
func (b *IPBloomFilter) AddCIDR(cidr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.cidrList = append(b.cidrList, cidr)
}

// Check checks if an IP is in the bloom filter and verifies with exact match
func (b *IPBloomFilter) Check(ip string) bool {
	// First check with bloom filter (fast negative check)
	if !b.filter.Test([]byte(ip)) {
		return false
	}

	// Verify with exact match (eliminates false positives)
	b.mu.RLock()
	_, exists := b.ipSet[ip]
	b.mu.RUnlock()

	return exists
}

// GetStats returns statistics about the bloom filter
func (b *IPBloomFilter) GetStats() FilterStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Calculate false positive rate based on current element count and parameters
	falsePositiveRate := 0.0
	if count := b.filter.ApproximatedSize(); count > 0 {
		// Approximated calculation for false positive rate
		falsePositiveRate = 0.01 * float64(count) / float64(b.filter.Cap())
		if falsePositiveRate > 1.0 {
			falsePositiveRate = 1.0
		}
	}

	return FilterStats{
		ElementCount:   b.filter.ApproximatedSize(),
		FalsePositives: falsePositiveRate,
		FilterSize:     b.filter.Cap(),
		HashFunctions:  b.filter.K(),
		Timestamp:      b.timestamp,
	}
}

// SaveToFile saves the bloom filter, IP set, and CIDR list to files
func (b *IPBloomFilter) SaveToFile(bloomPath, ipsPath, cidrPath string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Ensure parent directories exist
	for _, path := range []string{bloomPath, ipsPath, cidrPath} {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error(fmt.Sprintf("Failed to create directory for %s", path), err)
			return fmt.Errorf("failed to create directory for %s: %w", path, err)
		}
	}

	// Save bloom filter - custom marshaling for BloomFilter
	bloomJSON := map[string]interface{}{
		"capacity":        b.filter.Cap(),
		"hashFunctions":   b.filter.K(),
		"approximateSize": b.filter.ApproximatedSize(),
	}

	bloomData, err := json.Marshal(bloomJSON)
	if err != nil {
		logger.Error("Failed to marshal bloom filter data", err)
		return fmt.Errorf("failed to marshal bloom filter data: %w", err)
	}
	if err := os.WriteFile(bloomPath, bloomData, 0644); err != nil {
		logger.Error(fmt.Sprintf("Failed to save bloom filter to %s", bloomPath), err)
		return fmt.Errorf("failed to save bloom filter to %s: %w", bloomPath, err)
	}

	// Save IP set - pre-allocate slice for better performance
	ipList := make([]string, 0, len(b.ipSet))
	for ip := range b.ipSet {
		ipList = append(ipList, ip)
	}
	ipsJSON, err := json.Marshal(ipList)
	if err != nil {
		logger.Error("Failed to marshal IP list data", err)
		return fmt.Errorf("failed to marshal IP list data: %w", err)
	}
	if err := os.WriteFile(ipsPath, ipsJSON, 0644); err != nil {
		logger.Error(fmt.Sprintf("Failed to save IP list to %s", ipsPath), err)
		return fmt.Errorf("failed to save IP list to %s: %w", ipsPath, err)
	}

	// Save CIDR list
	cidrJSON, err := json.Marshal(b.cidrList)
	if err != nil {
		logger.Error("Failed to marshal CIDR list data", err)
		return fmt.Errorf("failed to marshal CIDR list data: %w", err)
	}
	if err := os.WriteFile(cidrPath, cidrJSON, 0644); err != nil {
		logger.Error(fmt.Sprintf("Failed to save CIDR list to %s", cidrPath), err)
		return fmt.Errorf("failed to save CIDR list to %s: %w", cidrPath, err)
	}

	logger.Success(fmt.Sprintf("Saved bloom filter data to disk: %d IPs, %d CIDRs", len(ipList), len(b.cidrList)))
	return nil
}

// LoadFromFile loads the bloom filter, IP set, and CIDR list from files
func LoadFromFile(bloomPath, ipsPath, cidrPath string) (*IPBloomFilter, error) {
	// Check if all required files exist
	for _, path := range []string{ipsPath, cidrPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("required file %s does not exist - filter needs initialization", path)
		}
	}

	// Load IP set first to get capacity
	ipsData, err := os.ReadFile(ipsPath)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to read IP list from %s", ipsPath), err)
		return nil, fmt.Errorf("failed to read IP list from %s: %w", ipsPath, err)
	}

	var ipList []string
	if err := json.Unmarshal(ipsData, &ipList); err != nil {
		logger.Error("Failed to unmarshal IP list data", err)
		return nil, fmt.Errorf("failed to unmarshal IP list data: %w", err)
	}

	// Pre-allocate the map with expected capacity for better performance
	ipSet := make(map[string]struct{}, len(ipList))
	for _, ip := range ipList {
		ipSet[ip] = struct{}{}
	}

	// Load CIDR list
	cidrData, err := os.ReadFile(cidrPath)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to read CIDR list from %s", cidrPath), err)
		return nil, fmt.Errorf("failed to read CIDR list from %s: %w", cidrPath, err)
	}

	var cidrList []string
	if err := json.Unmarshal(cidrData, &cidrList); err != nil {
		logger.Error("Failed to unmarshal CIDR list data", err)
		return nil, fmt.Errorf("failed to unmarshal CIDR list data: %w", err)
	}

	// Create new bloom filter with optimal size and add all IPs
	filter := bloom.NewWithEstimates(uint(len(ipList)+10000), 0.01)
	for _, ip := range ipList {
		filter.Add([]byte(ip))
	}

	logger.Success(fmt.Sprintf("Loaded bloom filter from disk: %d IPs, %d CIDRs", len(ipList), len(cidrList)))

	return &IPBloomFilter{
		filter:    filter,
		ipSet:     ipSet,
		cidrList:  cidrList,
		timestamp: time.Now(),
	}, nil
}

// GetCIDRs returns the list of CIDR ranges
func (b *IPBloomFilter) GetCIDRs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Return a copy to prevent race conditions
	result := make([]string, len(b.cidrList))
	copy(result, b.cidrList)
	return result
}

// BatchAdd adds multiple IP addresses to the filter in one operation
func (b *IPBloomFilter) BatchAdd(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ip := range ips {
		b.filter.Add([]byte(ip))
		b.ipSet[ip] = struct{}{}
	}
}

// BatchAddCIDR adds multiple CIDR ranges to the filter in one operation
func (b *IPBloomFilter) BatchAddCIDR(cidrs []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Pre-allocate to avoid multiple slice expansions
	if cap(b.cidrList)-len(b.cidrList) < len(cidrs) {
		newCIDRList := make([]string, len(b.cidrList), len(b.cidrList)+len(cidrs))
		copy(newCIDRList, b.cidrList)
		b.cidrList = newCIDRList
	}

	b.cidrList = append(b.cidrList, cidrs...)
}
