package scripts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/byigitt/check-ip/pkg/bloom"
	"github.com/byigitt/check-ip/pkg/config"
	"github.com/byigitt/check-ip/pkg/logger"
)

// IPSource defines a source of VPN/proxy IPs
type IPSource struct {
	Name   string
	URL    string
	Parser func(data []byte) []string
}

// Sources defines all the IP sources by category
var Sources = map[string][]IPSource{
	"vpn": {
		{
			Name:   "x4bnet-vpn-list",
			URL:    "https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/ipv4.txt",
			Parser: parseTextList,
		},
		{
			Name:   "x4bnet-vpn-specific",
			URL:    "https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/output/vpn/ipv4.txt",
			Parser: parseTextList,
		},
		{
			Name:   "youngjun-chang-vpn-ipv4",
			URL:    "https://raw.githubusercontent.com/youngjun-chang/VPNs/master/vpn-ipv4.txt",
			Parser: parseTextList,
		},
		{
			Name:   "josephrocca-vpn-datacenter",
			URL:    "https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv4-ranges.txt",
			Parser: parseTextList,
		},
		{
			Name:   "az0-vpn-ips",
			URL:    "https://raw.githubusercontent.com/az0/vpn_ip/refs/heads/main/data/output/ip.txt",
			Parser: parseTextList,
		},
		{
			Name:   "firehol-anonymous",
			URL:    "https://iplists.firehol.org/files/firehol_anonymous.netset",
			Parser: parseTextList,
		},
	},
	"proxy": {
		{
			Name:   "clarketm-proxy-list",
			URL:    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt",
			Parser: parseProxyList,
		},
		{
			Name:   "speedx-proxy-list",
			URL:    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			Parser: parseTextList,
		},
		{
			Name:   "firehol-proxies",
			URL:    "https://iplists.firehol.org/files/firehol_proxies.netset",
			Parser: parseTextList,
		},
		{
			Name:   "proxylists",
			URL:    "https://iplists.firehol.org/files/proxylists.ipset",
			Parser: parseTextList,
		},
		{
			Name:   "proxz",
			URL:    "https://iplists.firehol.org/files/proxz.ipset",
			Parser: parseTextList,
		},
		{
			Name:   "ri-connect-proxies",
			URL:    "https://iplists.firehol.org/files/ri_connect_proxies.ipset",
			Parser: parseTextList,
		},
		{
			Name:   "sslproxies",
			URL:    "https://iplists.firehol.org/files/sslproxies.ipset",
			Parser: parseTextList,
		},
	},
	"tor": {
		{
			Name:   "tor-exit-nodes",
			URL:    "https://check.torproject.org/exit-addresses",
			Parser: parseTorExitNodes,
		},
	},
	"hosting": {
		{
			Name:   "aws-ip-ranges",
			URL:    "https://ip-ranges.amazonaws.com/ip-ranges.json",
			Parser: parseAwsIpRanges,
		},
		{
			Name:   "digitalocean-ip-ranges",
			URL:    "https://www.digitalocean.com/geo/google.csv",
			Parser: parseDigitalOceanIpRanges,
		},
		{
			Name:   "google-cloud-ip-ranges",
			URL:    "https://www.gstatic.com/ipranges/cloud.json",
			Parser: parseGoogleCloudIpRanges,
		},
		{
			Name:   "cloudflare-ipv4-ranges",
			URL:    "https://www.cloudflare.com/ips-v4",
			Parser: parseTextList,
		},
		{
			Name:   "oracle-cloud-ip-ranges",
			URL:    "https://docs.oracle.com/iaas/tools/public_ip_ranges.json",
			Parser: parseOracleCloudIpRanges,
		},
		{
			Name:   "linode-ip-ranges",
			URL:    "https://geoip.linode.com/",
			Parser: parseLinodeIpRanges,
		},
		{
			Name:   "pushing-inertia-blocklist",
			URL:    "https://raw.githubusercontent.com/pushinginertia/ip-blacklist/master/ip_blacklist.conf",
			Parser: parsePushingInertiaBlocklist,
		},
	},
	"malicious": {
		{
			Name:   "stamparm-ipsum-level3",
			URL:    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
			Parser: parseTextList,
		},
		{
			Name:   "firehol-level1",
			URL:    "https://iplists.firehol.org/files/firehol_level1.netset",
			Parser: parseTextList,
		},
	},
}

// Update downloads IP lists from sources and updates the bloom filter
func Update(cfg *config.Config, filter *bloom.IPBloomFilter) error {
	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		logger.Error("Failed to create required directories", err)
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Download and process sources
	allIPs := make(map[string]struct{})
	allCIDRs := make([]string, 0)

	var wg sync.WaitGroup
	resultsChan := make(chan *downloadResult, 100) // Allow for larger buffer

	// Process all sources from all categories concurrently
	totalSources := 0
	for _, sources := range Sources {
		totalSources += len(sources)
	}

	logger.Init(fmt.Sprintf("starting update of %d ip sources across %d categories", totalSources, len(Sources)))

	// Process each category
	for category, sources := range Sources {
		for _, source := range sources {
			wg.Add(1)
			go downloadSource(category, source, cfg.RawDir, &wg, resultsChan)
		}
	}

	// Wait for all downloads to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	var successful, failed int
	for result := range resultsChan {
		if result.err != nil {
			logger.Warning(fmt.Sprintf("failed to process source %s from category %s", result.source.Name, result.category))
			failed++
			continue
		}

		successful++

		// Add IPs to the set
		for _, ip := range result.ips {
			if isCIDR(ip) {
				allCIDRs = append(allCIDRs, ip)
			} else {
				allIPs[ip] = struct{}{}
			}
		}
	}

	logger.Info(fmt.Sprintf("download summary: %d successful, %d failed", successful, failed))

	// Use the provided filter instead of creating a new one
	if filter == nil {
		// Create a new filter only if one wasn't provided
		filter = bloom.New(len(allIPs)+10000, 0.01) // Add some buffer
	}

	// Add all IPs to the bloom filter
	for ip := range allIPs {
		filter.Add(ip)
	}

	// Add all CIDRs to the bloom filter
	for _, cidr := range allCIDRs {
		filter.AddCIDR(cidr)
	}

	// Save the bloom filter and IP lists
	err := filter.SaveToFile(
		cfg.BloomFilterPath,
		cfg.IPsPath,
		cfg.CIDRsPath,
	)
	if err != nil {
		logger.Error("failed to save ip data to disk", err)
		return fmt.Errorf("failed to save IP data: %w", err)
	}

	logger.Success(fmt.Sprintf("update complete. processed %d unique ips and %d cidr ranges", len(allIPs), len(allCIDRs)))
	return nil
}

type downloadResult struct {
	category string
	source   IPSource
	ips      []string
	err      error
}

// downloadSource downloads and processes a single source
func downloadSource(category string, source IPSource, rawDir string, wg *sync.WaitGroup, results chan<- *downloadResult) {
	defer wg.Done()

	result := &downloadResult{
		category: category,
		source:   source,
	}

	logger.Info(fmt.Sprintf("Downloading source: %s (%s)", source.Name, category))

	// Download the source
	resp, err := http.Get(source.URL)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to download %s", source.Name), err)
		result.err = err
		results <- result
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP status %d", resp.StatusCode)
		logger.Error(fmt.Sprintf("Failed to download %s", source.Name), err)
		result.err = err
		results <- result
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to read response body for %s", source.Name), err)
		result.err = err
		results <- result
		return
	}

	// Create category subdirectory if needed
	categoryDir := filepath.Join(rawDir, category)
	if err := os.MkdirAll(categoryDir, 0755); err != nil {
		logger.Error(fmt.Sprintf("Failed to create directory for category %s", category), err)
		result.err = err
		results <- result
		return
	}

	// Save raw data
	rawPath := filepath.Join(categoryDir, fmt.Sprintf("%s-raw.txt", source.Name))
	if err := os.WriteFile(rawPath, body, 0644); err != nil {
		logger.Error(fmt.Sprintf("Failed to save raw data for %s", source.Name), err)
		result.err = err
		results <- result
		return
	}

	// Parse IPs
	ips := source.Parser(body)

	// Save parsed IPs
	parsedPath := filepath.Join(categoryDir, fmt.Sprintf("%s.json", source.Name))
	parsedData, err := json.Marshal(ips)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to marshal parsed data for %s", source.Name), err)
		result.err = err
		results <- result
		return
	}

	if err := os.WriteFile(parsedPath, parsedData, 0644); err != nil {
		logger.Error(fmt.Sprintf("Failed to save parsed data for %s", source.Name), err)
		result.err = err
		results <- result
		return
	}

	logger.Success(fmt.Sprintf("Successfully processed %s (%s): %d IPs", source.Name, category, len(ips)))
	result.ips = ips
	results <- result
}

// isCIDR checks if a string is in CIDR notation
func isCIDR(s string) bool {
	return strings.Contains(s, "/")
}

// Parser functions for different formats

func parseTextList(data []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Handle lines with comments after the IP
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		ips = append(ips, line)
	}
	return ips
}

func parseProxyList(data []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		if lineCount <= 4 {
			// Skip header lines
			continue
		}

		line := scanner.Text()
		re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+):`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			ips = append(ips, matches[1])
		}
	}

	return ips
}

func parseTorExitNodes(data []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ExitAddress ") {
			parts := strings.Split(line, " ")
			if len(parts) > 1 {
				ips = append(ips, parts[1])
			}
		}
	}

	return ips
}

// Additional parser functions for hosting IP ranges

func parseAwsIpRanges(data []byte) []string {
	var awsData struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &awsData); err != nil {
		logger.Warning(fmt.Sprintf("Error parsing AWS IP ranges: %v", err))
		return nil
	}

	var results []string
	for _, prefix := range awsData.Prefixes {
		if prefix.IPPrefix != "" {
			results = append(results, prefix.IPPrefix)
		}
	}

	return results
}

func parseDigitalOceanIpRanges(data []byte) []string {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var results []string
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		if lineCount == 1 {
			// Skip header
			continue
		}

		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				results = append(results, ip)
			}
		}
	}

	return results
}

func parseGoogleCloudIpRanges(data []byte) []string {
	var googleData struct {
		Prefixes []struct {
			IPV4Prefix string `json:"ipv4Prefix,omitempty"`
			IPV6Prefix string `json:"ipv6Prefix,omitempty"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &googleData); err != nil {
		logger.Warning(fmt.Sprintf("Error parsing Google Cloud IP ranges: %v", err))
		return nil
	}

	var results []string
	for _, prefix := range googleData.Prefixes {
		if prefix.IPV4Prefix != "" {
			results = append(results, prefix.IPV4Prefix)
		}
		if prefix.IPV6Prefix != "" {
			results = append(results, prefix.IPV6Prefix)
		}
	}

	return results
}

func parseOracleCloudIpRanges(data []byte) []string {
	var oracleData struct {
		Regions []struct {
			CIDRs []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}

	if err := json.Unmarshal(data, &oracleData); err != nil {
		logger.Warning(fmt.Sprintf("Error parsing Oracle Cloud IP ranges: %v", err))
		return nil
	}

	var results []string
	for _, region := range oracleData.Regions {
		for _, cidr := range region.CIDRs {
			if cidr.CIDR != "" {
				results = append(results, cidr.CIDR)
			}
		}
	}

	return results
}

func parseLinodeIpRanges(data []byte) []string {
	// Try to parse as JSON first
	var jsonData []string
	if err := json.Unmarshal(data, &jsonData); err == nil {
		return jsonData
	}

	// If not JSON, parse as text
	return parseTextList(data)
}

func parsePushingInertiaBlocklist(data []byte) []string {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var results []string
	re := regexp.MustCompile(`ipset=(?:[^,]+),([0-9./]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			results = append(results, matches[1])
		}
	}

	return results
}

// StartScheduledUpdates starts a goroutine to periodically update the IP lists
func StartScheduledUpdates(cfg *config.Config, interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	logger.Init(fmt.Sprintf("Starting scheduled IP list updates every %v", interval))

	go func() {
		for {
			select {
			case <-ticker.C:
				logger.Info("Starting scheduled update of IP lists")
				if err := Update(cfg, nil); err != nil {
					logger.Error("Error during scheduled update", err)
				}
			case <-stopCh:
				ticker.Stop()
				logger.Info("Stopping scheduled updates")
				return
			}
		}
	}()
}
