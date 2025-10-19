package analyzer

import (
	"strings"

	"github.com/google/gopacket/layers"
)

// OSFingerprinter performs OS fingerprinting
type OSFingerprinter struct {
	results map[string]*OSInfo
}

// OSInfo holds OS detection information
type OSInfo struct {
	OSType     string
	Confidence float64
	Signals    []string
}

// NewOSFingerprinter creates a new OS fingerprinter
func NewOSFingerprinter() *OSFingerprinter {
	return &OSFingerprinter{
		results: make(map[string]*OSInfo),
	}
}

// AnalyzeTCP analyzes TCP characteristics for OS fingerprinting
func (o *OSFingerprinter) AnalyzeTCP(srcIP string, tcp *layers.TCP, ipv4 *layers.IPv4) {
	if _, exists := o.results[srcIP]; !exists {
		o.results[srcIP] = &OSInfo{
			OSType:     "Unknown",
			Confidence: 0,
			Signals:    make([]string, 0),
		}
	}

	info := o.results[srcIP]

	// Analyze TCP window size
	windowSize := tcp.Window

	// Windows typically uses specific window sizes
	if windowSize == 8192 || windowSize == 64240 || windowSize == 65535 {
		info.Signals = append(info.Signals, "tcp_window_windows")
		if info.OSType == "Unknown" {
			info.OSType = "Windows"
			info.Confidence = 40
		} else if info.OSType == "Windows" {
			info.Confidence += 10
		}
	}

	// Linux typically uses specific window sizes
	if windowSize == 5840 || windowSize == 14600 || windowSize == 29200 {
		info.Signals = append(info.Signals, "tcp_window_linux")
		if info.OSType == "Unknown" {
			info.OSType = "Linux"
			info.Confidence = 40
		} else if info.OSType == "Linux" {
			info.Confidence += 10
		}
	}

	// Analyze TTL
	ttl := ipv4.TTL
	if ttl <= 64 && ttl > 32 {
		info.Signals = append(info.Signals, "ttl_linux")
		if info.OSType == "Unknown" || info.OSType == "Linux" {
			info.OSType = "Linux"
			info.Confidence += 5
		}
	} else if ttl <= 128 && ttl > 64 {
		info.Signals = append(info.Signals, "ttl_windows")
		if info.OSType == "Unknown" || info.OSType == "Windows" {
			info.OSType = "Windows"
			info.Confidence += 5
		}
	}
}

// AnalyzeHTTP analyzes HTTP User-Agent for OS fingerprinting
func (o *OSFingerprinter) AnalyzeHTTP(srcIP string, payload string) {
	if _, exists := o.results[srcIP]; !exists {
		o.results[srcIP] = &OSInfo{
			OSType:     "Unknown",
			Confidence: 0,
			Signals:    make([]string, 0),
		}
	}

	info := o.results[srcIP]

	// Look for User-Agent header
	if !strings.Contains(payload, "User-Agent:") {
		return
	}

	userAgent := strings.ToLower(payload)

	// Windows detection
	if strings.Contains(userAgent, "windows nt") || strings.Contains(userAgent, "win64") || strings.Contains(userAgent, "wow64") {
		info.Signals = append(info.Signals, "http_ua_windows")
		info.OSType = "Windows"
		info.Confidence = 90

		// Identify Windows version
		if strings.Contains(userAgent, "windows nt 10.0") {
			info.OSType = "Windows 10/11"
			info.Confidence = 95
		} else if strings.Contains(userAgent, "windows nt 6.3") {
			info.OSType = "Windows 8.1"
			info.Confidence = 95
		} else if strings.Contains(userAgent, "windows nt 6.2") {
			info.OSType = "Windows 8"
			info.Confidence = 95
		} else if strings.Contains(userAgent, "windows nt 6.1") {
			info.OSType = "Windows 7"
			info.Confidence = 95
		}
	}

	// Linux detection
	if strings.Contains(userAgent, "linux") && !strings.Contains(userAgent, "android") {
		info.Signals = append(info.Signals, "http_ua_linux")
		info.OSType = "Linux"
		info.Confidence = 90

		// Check for specific distributions
		if strings.Contains(userAgent, "ubuntu") {
			info.OSType = "Linux (Ubuntu)"
			info.Confidence = 95
		} else if strings.Contains(userAgent, "fedora") {
			info.OSType = "Linux (Fedora)"
			info.Confidence = 95
		} else if strings.Contains(userAgent, "debian") {
			info.OSType = "Linux (Debian)"
			info.Confidence = 95
		}
	}

	// macOS detection
	if strings.Contains(userAgent, "macintosh") || strings.Contains(userAgent, "mac os x") {
		info.Signals = append(info.Signals, "http_ua_macos")
		info.OSType = "macOS"
		info.Confidence = 90
	}

	// Android detection
	if strings.Contains(userAgent, "android") {
		info.Signals = append(info.Signals, "http_ua_android")
		info.OSType = "Android"
		info.Confidence = 90
	}

	// iOS detection
	if strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ipad") {
		info.Signals = append(info.Signals, "http_ua_ios")
		info.OSType = "iOS"
		info.Confidence = 90
	}
}

// AnalyzeSSH analyzes SSH banner for OS fingerprinting
func (o *OSFingerprinter) AnalyzeSSH(srcIP string, payload string) {
	if _, exists := o.results[srcIP]; !exists {
		o.results[srcIP] = &OSInfo{
			OSType:     "Unknown",
			Confidence: 0,
			Signals:    make([]string, 0),
		}
	}

	info := o.results[srcIP]

	// Look for SSH banner
	if !strings.HasPrefix(payload, "SSH-") {
		return
	}

	banner := strings.ToLower(payload)

	// Ubuntu detection
	if strings.Contains(banner, "ubuntu") {
		info.Signals = append(info.Signals, "ssh_ubuntu")
		info.OSType = "Linux (Ubuntu)"
		info.Confidence = 85
	}

	// Debian detection
	if strings.Contains(banner, "debian") {
		info.Signals = append(info.Signals, "ssh_debian")
		info.OSType = "Linux (Debian)"
		info.Confidence = 85
	}

	// Generic Linux
	if strings.Contains(banner, "openssh") && info.OSType == "Unknown" {
		info.Signals = append(info.Signals, "ssh_linux")
		info.OSType = "Linux"
		info.Confidence = 70
	}
}

// AnalyzeDHCP analyzes DHCP packets for OS fingerprinting
func (o *OSFingerprinter) AnalyzeDHCP(srcIP string, payload []byte) {
	if _, exists := o.results[srcIP]; !exists {
		o.results[srcIP] = &OSInfo{
			OSType:     "Unknown",
			Confidence: 0,
			Signals:    make([]string, 0),
		}
	}

	info := o.results[srcIP]

	// DHCP fingerprinting is complex and would require parsing DHCP options
	// For simplicity, we'll just mark that we saw DHCP traffic
	if len(payload) > 0 {
		info.Signals = append(info.Signals, "dhcp_seen")
		info.Confidence += 5
	}
}

// GetResults returns the OS fingerprinting results
func (o *OSFingerprinter) GetResults() map[string]*OSInfo {
	// Cap confidence at 100
	for _, info := range o.results {
		if info.Confidence > 100 {
			info.Confidence = 100
		}
	}
	return o.results
}
