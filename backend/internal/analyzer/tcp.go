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

package analyzer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPTracker tracks TCP connections
type TCPTracker struct {
	streams     map[string]*TCPStream
	Connections []TCPConnectionInfo
}

// TCPStream represents a TCP connection stream
type TCPStream struct {
	SrcIP         string
	DstIP         string
	SrcPort       int
	DstPort       int
	BytesSent     int64
	BytesReceived int64
	StartTime     time.Time
	EndTime       time.Time
	Service       string
	SYNSeen       bool
	FINSeen       bool
	RSTSeen       bool
}

// TCPConnectionInfo holds information about a TCP connection
type TCPConnectionInfo struct {
	SrcIP         string
	DstIP         string
	SrcPort       int
	DstPort       int
	BytesSent     int64
	BytesReceived int64
	DurationMs    int64
	Service       string
	StartTime     time.Time
	EndTime       time.Time
}

// NewTCPTracker creates a new TCP tracker
func NewTCPTracker() *TCPTracker {
	return &TCPTracker{
		streams:     make(map[string]*TCPStream),
		Connections: make([]TCPConnectionInfo, 0),
	}
}

// ProcessPacket processes a TCP packet
func (t *TCPTracker) ProcessPacket(srcIP, dstIP string, tcp *layers.TCP, timestamp time.Time, appLayer gopacket.ApplicationLayer) {
	// Create stream key (bidirectional)
	key := t.getStreamKey(srcIP, dstIP, int(tcp.SrcPort), int(tcp.DstPort))

	stream, exists := t.streams[key]
	if !exists {
		// New connection
		stream = &TCPStream{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   int(tcp.SrcPort),
			DstPort:   int(tcp.DstPort),
			StartTime: timestamp,
			EndTime:   timestamp,
			Service:   identifyService(int(tcp.DstPort)),
		}
		t.streams[key] = stream
	}

	// Update end time
	stream.EndTime = timestamp

	// Check for SYN
	if tcp.SYN && !tcp.ACK {
		stream.SYNSeen = true
	}

	// Check for FIN or RST
	if tcp.FIN {
		stream.FINSeen = true
	}
	if tcp.RST {
		stream.RSTSeen = true
	}

	// Count bytes
	packetSize := int64(len(tcp.Payload))
	if appLayer != nil {
		packetSize = int64(len(appLayer.Payload()))
	}

	// Determine direction
	if srcIP == stream.SrcIP && int(tcp.SrcPort) == stream.SrcPort {
		stream.BytesSent += packetSize
	} else {
		stream.BytesReceived += packetSize
	}
}

// Finalize processes all streams and creates connection records
func (t *TCPTracker) Finalize() {
	for _, stream := range t.streams {
		duration := stream.EndTime.Sub(stream.StartTime)
		durationMs := duration.Milliseconds()

		conn := TCPConnectionInfo{
			SrcIP:         stream.SrcIP,
			DstIP:         stream.DstIP,
			SrcPort:       stream.SrcPort,
			DstPort:       stream.DstPort,
			BytesSent:     stream.BytesSent,
			BytesReceived: stream.BytesReceived,
			DurationMs:    durationMs,
			Service:       stream.Service,
			StartTime:     stream.StartTime,
			EndTime:       stream.EndTime,
		}

		t.Connections = append(t.Connections, conn)
	}
}

// getStreamKey creates a unique key for a TCP stream (bidirectional)
func (t *TCPTracker) getStreamKey(srcIP, dstIP string, srcPort, dstPort int) string {
	// Normalize the key so that both directions use the same key
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}
