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
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
)

// AnalyzePCAP analyzes a PCAP file and stores results in the database
func AnalyzePCAP(analysisID int, pcapPath string) error {
	log.Printf("Starting analysis for ID %d, file: %s", analysisID, pcapPath)

	// Update status to processing
	err := database.UpdateAnalysisStatus(analysisID, "processing", "")
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Open PCAP file
	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		database.UpdateAnalysisStatus(analysisID, "failed", err.Error())
		return fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	// Initialize tracking structures
	tcpTracker := NewTCPTracker()
	udpTracker := NewUDPTracker()
	icmpTracker := NewICMPTracker()
	osFingerprinter := NewOSFingerprinter()
	assetMap := make(map[string]*AssetInfo)
	targetMap := make(map[string]bool)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp

		// Get network layer
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		var srcIP, dstIP string
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			srcIP = ipv4.SrcIP.String()
			dstIP = ipv4.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			srcIP = ipv6.SrcIP.String()
			dstIP = ipv6.DstIP.String()
		} else {
			continue
		}

		// Track assets (source IPs)
		if _, exists := assetMap[srcIP]; !exists {
			assetMap[srcIP] = &AssetInfo{
				IPAddress: srcIP,
				OSType:    "Unknown",
			}
		}

		// Track targets (destination IPs)
		targetMap[dstIP] = true

		// Get Ethernet layer for MAC address
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			assetMap[srcIP].MACAddress = eth.SrcMAC.String()
		}

		// Process TCP packets
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			tcpTracker.ProcessPacket(srcIP, dstIP, tcp, timestamp, packet.ApplicationLayer())

			// OS fingerprinting from TCP
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, _ := ipv4Layer.(*layers.IPv4)
				osFingerprinter.AnalyzeTCP(srcIP, tcp, ipv4)
			}

			// Check for HTTP User-Agent
			if tcp.DstPort == 80 || tcp.SrcPort == 80 {
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					payload := string(appLayer.Payload())
					osFingerprinter.AnalyzeHTTP(srcIP, payload)
				}
			}

			// Check for SSH banner
			if tcp.DstPort == 22 || tcp.SrcPort == 22 {
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					payload := string(appLayer.Payload())
					osFingerprinter.AnalyzeSSH(srcIP, payload)
				}
			}
		}

		// Process UDP packets
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			udpTracker.ProcessPacket(srcIP, dstIP, udp, timestamp, packet.ApplicationLayer())

			// Check for DHCP
			if udp.DstPort == 67 || udp.SrcPort == 67 {
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					osFingerprinter.AnalyzeDHCP(srcIP, appLayer.Payload())
				}
			}
		}

		// Process ICMP packets
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			icmpTracker.ProcessPacket(srcIP, dstIP, icmp, timestamp)
		}
	}

	// Finalize all trackers
	tcpTracker.Finalize()
	udpTracker.Finalize()
	icmpTracker.Finalize()

	// Apply OS fingerprinting results to assets
	osResults := osFingerprinter.GetResults()
	for ip, osInfo := range osResults {
		if asset, exists := assetMap[ip]; exists {
			asset.OSType = osInfo.OSType
			asset.OSConfidence = osInfo.Confidence
		}
	}

	// Save assets to database
	for _, asset := range assetMap {
		dbAsset := &database.Asset{
			AnalysisID:   analysisID,
			IPAddress:    asset.IPAddress,
			OSType:       asset.OSType,
			OSConfidence: asset.OSConfidence,
			MACAddress:   asset.MACAddress,
		}
		if err := database.SaveAsset(dbAsset); err != nil {
			log.Printf("Failed to save asset %s: %v", asset.IPAddress, err)
		}
	}

	// Save targets to database
	for ip := range targetMap {
		label := "local"
		if isPublicIP(ip) {
			label = "public"
		}
		target := &database.Target{
			AnalysisID: analysisID,
			IPAddress:  ip,
			Label:      label,
		}
		if err := database.SaveTarget(target); err != nil {
			log.Printf("Failed to save target %s: %v", ip, err)
		}
	}

	// Save TCP connections
	for _, conn := range tcpTracker.Connections {
		dbConn := &database.TCPConnection{
			AnalysisID:    analysisID,
			SrcIP:         conn.SrcIP,
			DstIP:         conn.DstIP,
			SrcPort:       conn.SrcPort,
			DstPort:       conn.DstPort,
			BytesSent:     conn.BytesSent,
			BytesReceived: conn.BytesReceived,
			Protocol:      "TCP",
			DurationMs:    conn.DurationMs,
			Service:       conn.Service,
			StartTime:     conn.StartTime.Format(time.RFC3339),
			EndTime:       conn.EndTime.Format(time.RFC3339),
		}
		if err := database.SaveTCPConnection(dbConn); err != nil {
			log.Printf("Failed to save TCP connection: %v", err)
		}
	}

	// Save UDP connections
	for _, conn := range udpTracker.Connections {
		dbConn := &database.OtherConnection{
			AnalysisID:    analysisID,
			SrcIP:         conn.SrcIP,
			DstIP:         conn.DstIP,
			SrcPort:       conn.SrcPort,
			DstPort:       conn.DstPort,
			BytesSent:     conn.BytesSent,
			BytesReceived: conn.BytesReceived,
			Protocol:      "UDP",
			DurationMs:    conn.DurationMs,
			Service:       conn.Service,
			StartTime:     conn.StartTime.Format(time.RFC3339),
			EndTime:       conn.EndTime.Format(time.RFC3339),
		}
		if err := database.SaveOtherConnection(dbConn); err != nil {
			log.Printf("Failed to save UDP connection: %v", err)
		}
	}

	// Save ICMP connections
	for _, conn := range icmpTracker.Connections {
		dbConn := &database.OtherConnection{
			AnalysisID: analysisID,
			SrcIP:      conn.SrcIP,
			DstIP:      conn.DstIP,
			BytesSent:  conn.BytesSent,
			Protocol:   "ICMP",
			DurationMs: conn.DurationMs,
			Service:    "icmp",
			StartTime:  conn.StartTime.Format(time.RFC3339),
			EndTime:    conn.EndTime.Format(time.RFC3339),
		}
		if err := database.SaveOtherConnection(dbConn); err != nil {
			log.Printf("Failed to save ICMP connection: %v", err)
		}
	}

	// Update status to completed
	err = database.UpdateAnalysisStatus(analysisID, "completed", "")
	if err != nil {
		return fmt.Errorf("failed to update final status: %w", err)
	}

	log.Printf("Analysis %d completed successfully", analysisID)
	return nil
}

// isPublicIP checks if an IP address is public (not in private ranges)
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for private IP ranges (RFC1918)
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 private
		"fe80::/10",       // IPv6 link-local
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}

	return true
}

// AssetInfo holds information about an asset
type AssetInfo struct {
	IPAddress    string
	OSType       string
	OSConfidence float64
	MACAddress   string
}

// identifyService identifies the service based on port number
func identifyService(port int) string {
	services := map[int]string{
		20:  "ftp-data",
		21:  "ftp",
		22:  "ssh",
		23:  "telnet",
		25:  "smtp",
		53:  "dns",
		67:  "dhcp",
		68:  "dhcp",
		80:  "http",
		110: "pop3",
		143: "imap",
		443: "https",
		445: "smb",
		3389: "rdp",
		3306: "mysql",
		5432: "postgresql",
		6881: "torrent",
		6882: "torrent",
		6883: "torrent",
		6884: "torrent",
		6885: "torrent",
		6886: "torrent",
		6887: "torrent",
		6888: "torrent",
		6889: "torrent",
		6969: "torrent",
	}

	if service, exists := services[port]; exists {
		return service
	}

	// Check for torrent range
	if port >= 6881 && port <= 6889 {
		return "torrent"
	}

	return "unknown"
}
