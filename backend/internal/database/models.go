// Copyright 2026 Kedar Kulkarni
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package database

import (
	"time"
)

// User represents a user account
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Session represents a user session
type Session struct {
	SessionID string    `json:"session_id"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Analysis represents a PCAP analysis job
type Analysis struct {
	ID          int        `json:"id"`
	UserID      int        `json:"user_id"`
	Filename    string     `json:"filename"`
	Status      string     `json:"status"` // pending, processing, completed, failed
	ErrorMsg    string     `json:"error_msg,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Asset represents a discovered asset (source IP)
type Asset struct {
	ID            int     `json:"id"`
	AnalysisID    int     `json:"analysis_id"`
	IPAddress     string  `json:"ip_address"`
	OSType        string  `json:"os_type"`        // Windows, Linux, macOS, Unknown
	OSConfidence  float64 `json:"os_confidence"`  // 0-100
	MACAddress    string  `json:"mac_address,omitempty"`
}

// Target represents a destination IP
type Target struct {
	ID         int    `json:"id"`
	AnalysisID int    `json:"analysis_id"`
	IPAddress  string `json:"ip_address"`
	Label      string `json:"label"` // public, local
}

// TCPConnection represents a TCP connection
type TCPConnection struct {
	ID            int     `json:"id"`
	AnalysisID    int     `json:"analysis_id"`
	SrcIP         string  `json:"src_ip"`
	DstIP         string  `json:"dst_ip"`
	SrcPort       int     `json:"src_port"`
	DstPort       int     `json:"dst_port"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
	Protocol      string  `json:"protocol"` // TCP
	DurationMs    int64   `json:"duration_ms"`
	Service       string  `json:"service"` // http, https, ssh, ftp, torrent, unknown
	StartTime     string  `json:"start_time"`
	EndTime       string  `json:"end_time"`
}

// OtherConnection represents non-TCP connections (UDP, ICMP)
type OtherConnection struct {
	ID            int     `json:"id"`
	AnalysisID    int     `json:"analysis_id"`
	SrcIP         string  `json:"src_ip"`
	DstIP         string  `json:"dst_ip"`
	SrcPort       int     `json:"src_port,omitempty"`
	DstPort       int     `json:"dst_port,omitempty"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
	Protocol      string  `json:"protocol"` // UDP, ICMP
	DurationMs    int64   `json:"duration_ms"`
	Service       string  `json:"service"` // dns, dhcp, ntp, icmp, unknown
	StartTime     string  `json:"start_time"`
	EndTime       string  `json:"end_time"`
}

// AnalysisResults aggregates all analysis data
type AnalysisResults struct {
	Analysis         Analysis          `json:"analysis"`
	AssetCount       int               `json:"asset_count"`
	TargetCount      int               `json:"target_count"`
	PublicTargets    int               `json:"public_targets"`
	LocalTargets     int               `json:"local_targets"`
	Assets           []Asset           `json:"assets"`
	Targets          []Target          `json:"targets"`
	TCPConnections   []TCPConnection   `json:"tcp_connections"`
	OtherConnections []OtherConnection `json:"other_connections"`
}
