package analyzer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UDPTracker tracks UDP connections
type UDPTracker struct {
	flows       map[string]*UDPFlow
	Connections []UDPConnectionInfo
}

// UDPFlow represents a UDP flow
type UDPFlow struct {
	SrcIP         string
	DstIP         string
	SrcPort       int
	DstPort       int
	BytesSent     int64
	BytesReceived int64
	StartTime     time.Time
	EndTime       time.Time
	Service       string
}

// UDPConnectionInfo holds information about a UDP connection
type UDPConnectionInfo struct {
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

// NewUDPTracker creates a new UDP tracker
func NewUDPTracker() *UDPTracker {
	return &UDPTracker{
		flows:       make(map[string]*UDPFlow),
		Connections: make([]UDPConnectionInfo, 0),
	}
}

// ProcessPacket processes a UDP packet
func (u *UDPTracker) ProcessPacket(srcIP, dstIP string, udp *layers.UDP, timestamp time.Time, appLayer gopacket.ApplicationLayer) {
	// Create flow key (bidirectional)
	key := u.getFlowKey(srcIP, dstIP, int(udp.SrcPort), int(udp.DstPort))

	flow, exists := u.flows[key]
	if !exists {
		// New flow
		service := identifyService(int(udp.DstPort))
		if service == "unknown" {
			service = identifyService(int(udp.SrcPort))
		}

		flow = &UDPFlow{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   int(udp.SrcPort),
			DstPort:   int(udp.DstPort),
			StartTime: timestamp,
			EndTime:   timestamp,
			Service:   service,
		}
		u.flows[key] = flow
	}

	// Update end time
	flow.EndTime = timestamp

	// Count bytes
	packetSize := int64(len(udp.Payload))
	if appLayer != nil {
		packetSize = int64(len(appLayer.Payload()))
	}

	// Determine direction
	if srcIP == flow.SrcIP && int(udp.SrcPort) == flow.SrcPort {
		flow.BytesSent += packetSize
	} else {
		flow.BytesReceived += packetSize
	}
}

// Finalize processes all flows and creates connection records
func (u *UDPTracker) Finalize() {
	for _, flow := range u.flows {
		duration := flow.EndTime.Sub(flow.StartTime)
		durationMs := duration.Milliseconds()

		conn := UDPConnectionInfo{
			SrcIP:         flow.SrcIP,
			DstIP:         flow.DstIP,
			SrcPort:       flow.SrcPort,
			DstPort:       flow.DstPort,
			BytesSent:     flow.BytesSent,
			BytesReceived: flow.BytesReceived,
			DurationMs:    durationMs,
			Service:       flow.Service,
			StartTime:     flow.StartTime,
			EndTime:       flow.EndTime,
		}

		u.Connections = append(u.Connections, conn)
	}
}

// getFlowKey creates a unique key for a UDP flow (bidirectional)
func (u *UDPTracker) getFlowKey(srcIP, dstIP string, srcPort, dstPort int) string {
	// Normalize the key so that both directions use the same key
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}

// ICMPTracker tracks ICMP messages
type ICMPTracker struct {
	flows       map[string]*ICMPFlow
	Connections []ICMPConnectionInfo
}

// ICMPFlow represents an ICMP flow
type ICMPFlow struct {
	SrcIP     string
	DstIP     string
	BytesSent int64
	StartTime time.Time
	EndTime   time.Time
}

// ICMPConnectionInfo holds information about ICMP traffic
type ICMPConnectionInfo struct {
	SrcIP      string
	DstIP      string
	BytesSent  int64
	DurationMs int64
	StartTime  time.Time
	EndTime    time.Time
}

// NewICMPTracker creates a new ICMP tracker
func NewICMPTracker() *ICMPTracker {
	return &ICMPTracker{
		flows:       make(map[string]*ICMPFlow),
		Connections: make([]ICMPConnectionInfo, 0),
	}
}

// ProcessPacket processes an ICMP packet
func (i *ICMPTracker) ProcessPacket(srcIP, dstIP string, icmp *layers.ICMPv4, timestamp time.Time) {
	// Create flow key
	key := fmt.Sprintf("%s-%s", srcIP, dstIP)

	flow, exists := i.flows[key]
	if !exists {
		flow = &ICMPFlow{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			StartTime: timestamp,
			EndTime:   timestamp,
		}
		i.flows[key] = flow
	}

	// Update end time
	flow.EndTime = timestamp

	// Count bytes (ICMP header + payload)
	packetSize := int64(8) // ICMP header is 8 bytes
	flow.BytesSent += packetSize
}

// Finalize processes all flows and creates connection records
func (i *ICMPTracker) Finalize() {
	for _, flow := range i.flows {
		duration := flow.EndTime.Sub(flow.StartTime)
		durationMs := duration.Milliseconds()

		conn := ICMPConnectionInfo{
			SrcIP:      flow.SrcIP,
			DstIP:      flow.DstIP,
			BytesSent:  flow.BytesSent,
			DurationMs: durationMs,
			StartTime:  flow.StartTime,
			EndTime:    flow.EndTime,
		}

		i.Connections = append(i.Connections, conn)
	}
}
