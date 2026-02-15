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
	"database/sql"
	"fmt"
	"time"
)

// GetUserByUsername retrieves a user by username
func GetUserByUsername(username string) (*User, error) {
	user := &User{}
	err := DB.QueryRow(
		"SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CreateSession creates a new session for a user
func CreateSession(sessionID string, userID int, expiresAt time.Time) error {
	_, err := DB.Exec(
		"INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, userID, expiresAt,
	)
	return err
}

// GetSession retrieves a session by ID
func GetSession(sessionID string) (*Session, error) {
	session := &Session{}
	err := DB.QueryRow(
		"SELECT session_id, user_id, expires_at FROM sessions WHERE session_id = ? AND expires_at > ?",
		sessionID, time.Now(),
	).Scan(&session.SessionID, &session.UserID, &session.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return session, nil
}

// DeleteSession removes a session
func DeleteSession(sessionID string) error {
	_, err := DB.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
	return err
}

// CreateAnalysis creates a new analysis record
func CreateAnalysis(userID int, filename string) (int64, error) {
	result, err := DB.Exec(
		"INSERT INTO analyses (user_id, filename, status, created_at) VALUES (?, ?, ?, ?)",
		userID, filename, "pending", time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// UpdateAnalysisStatus updates the status of an analysis
func UpdateAnalysisStatus(analysisID int, status string, errorMsg string) error {
	var completedAt *time.Time
	if status == "completed" || status == "failed" {
		now := time.Now()
		completedAt = &now
	}

	_, err := DB.Exec(
		"UPDATE analyses SET status = ?, error_msg = ?, completed_at = ? WHERE id = ?",
		status, errorMsg, completedAt, analysisID,
	)
	return err
}

// GetAnalysis retrieves an analysis by ID
func GetAnalysis(analysisID int) (*Analysis, error) {
	analysis := &Analysis{}
	err := DB.QueryRow(
		"SELECT id, user_id, filename, status, error_msg, created_at, completed_at FROM analyses WHERE id = ?",
		analysisID,
	).Scan(&analysis.ID, &analysis.UserID, &analysis.Filename, &analysis.Status,
		&analysis.ErrorMsg, &analysis.CreatedAt, &analysis.CompletedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return analysis, nil
}

// GetUserAnalyses retrieves all analyses for a user
func GetUserAnalyses(userID int) ([]Analysis, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, filename, status, error_msg, created_at, completed_at FROM analyses WHERE user_id = ? ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var analyses []Analysis
	for rows.Next() {
		var a Analysis
		err := rows.Scan(&a.ID, &a.UserID, &a.Filename, &a.Status, &a.ErrorMsg, &a.CreatedAt, &a.CompletedAt)
		if err != nil {
			return nil, err
		}
		analyses = append(analyses, a)
	}

	return analyses, nil
}

// DeleteAnalysis deletes an analysis and all related data
func DeleteAnalysis(analysisID int) error {
	_, err := DB.Exec("DELETE FROM analyses WHERE id = ?", analysisID)
	return err
}

// SaveAsset saves an asset to the database
func SaveAsset(asset *Asset) error {
	_, err := DB.Exec(
		"INSERT INTO assets (analysis_id, ip_address, os_type, os_confidence, mac_address) VALUES (?, ?, ?, ?, ?)",
		asset.AnalysisID, asset.IPAddress, asset.OSType, asset.OSConfidence, asset.MACAddress,
	)
	return err
}

// SaveTarget saves a target to the database
func SaveTarget(target *Target) error {
	_, err := DB.Exec(
		"INSERT INTO targets (analysis_id, ip_address, label) VALUES (?, ?, ?)",
		target.AnalysisID, target.IPAddress, target.Label,
	)
	return err
}

// SaveTCPConnection saves a TCP connection to the database
func SaveTCPConnection(conn *TCPConnection) error {
	_, err := DB.Exec(
		`INSERT INTO tcp_connections (analysis_id, src_ip, dst_ip, src_port, dst_port, 
		bytes_sent, bytes_received, protocol, duration_ms, service, start_time, end_time) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.AnalysisID, conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort,
		conn.BytesSent, conn.BytesReceived, conn.Protocol, conn.DurationMs,
		conn.Service, conn.StartTime, conn.EndTime,
	)
	return err
}

// SaveOtherConnection saves a non-TCP connection to the database
func SaveOtherConnection(conn *OtherConnection) error {
	_, err := DB.Exec(
		`INSERT INTO other_connections (analysis_id, src_ip, dst_ip, src_port, dst_port, 
		bytes_sent, bytes_received, protocol, duration_ms, service, start_time, end_time) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.AnalysisID, conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort,
		conn.BytesSent, conn.BytesReceived, conn.Protocol, conn.DurationMs,
		conn.Service, conn.StartTime, conn.EndTime,
	)
	return err
}

// GetAnalysisResults retrieves all data for an analysis
func GetAnalysisResults(analysisID int) (*AnalysisResults, error) {
	// Get analysis
	analysis, err := GetAnalysis(analysisID)
	if err != nil {
		return nil, err
	}
	if analysis == nil {
		return nil, fmt.Errorf("analysis not found")
	}

	results := &AnalysisResults{
		Analysis: *analysis,
	}

	// Get assets
	assetRows, err := DB.Query(
		"SELECT id, analysis_id, ip_address, os_type, os_confidence, mac_address FROM assets WHERE analysis_id = ?",
		analysisID,
	)
	if err != nil {
		return nil, err
	}
	defer assetRows.Close()

	for assetRows.Next() {
		var a Asset
		err := assetRows.Scan(&a.ID, &a.AnalysisID, &a.IPAddress, &a.OSType, &a.OSConfidence, &a.MACAddress)
		if err != nil {
			return nil, err
		}
		results.Assets = append(results.Assets, a)
	}
	results.AssetCount = len(results.Assets)

	// Get targets
	targetRows, err := DB.Query(
		"SELECT id, analysis_id, ip_address, label FROM targets WHERE analysis_id = ?",
		analysisID,
	)
	if err != nil {
		return nil, err
	}
	defer targetRows.Close()

	for targetRows.Next() {
		var t Target
		err := targetRows.Scan(&t.ID, &t.AnalysisID, &t.IPAddress, &t.Label)
		if err != nil {
			return nil, err
		}
		results.Targets = append(results.Targets, t)
		if t.Label == "public" {
			results.PublicTargets++
		} else {
			results.LocalTargets++
		}
	}
	results.TargetCount = len(results.Targets)

	// Get TCP connections
	tcpRows, err := DB.Query(
		`SELECT id, analysis_id, src_ip, dst_ip, src_port, dst_port, bytes_sent, bytes_received, 
		protocol, duration_ms, service, start_time, end_time FROM tcp_connections WHERE analysis_id = ?`,
		analysisID,
	)
	if err != nil {
		return nil, err
	}
	defer tcpRows.Close()

	for tcpRows.Next() {
		var c TCPConnection
		err := tcpRows.Scan(&c.ID, &c.AnalysisID, &c.SrcIP, &c.DstIP, &c.SrcPort, &c.DstPort,
			&c.BytesSent, &c.BytesReceived, &c.Protocol, &c.DurationMs, &c.Service,
			&c.StartTime, &c.EndTime)
		if err != nil {
			return nil, err
		}
		results.TCPConnections = append(results.TCPConnections, c)
	}

	// Get other connections
	otherRows, err := DB.Query(
		`SELECT id, analysis_id, src_ip, dst_ip, src_port, dst_port, bytes_sent, bytes_received, 
		protocol, duration_ms, service, start_time, end_time FROM other_connections WHERE analysis_id = ?`,
		analysisID,
	)
	if err != nil {
		return nil, err
	}
	defer otherRows.Close()

	for otherRows.Next() {
		var c OtherConnection
		err := otherRows.Scan(&c.ID, &c.AnalysisID, &c.SrcIP, &c.DstIP, &c.SrcPort, &c.DstPort,
			&c.BytesSent, &c.BytesReceived, &c.Protocol, &c.DurationMs, &c.Service,
			&c.StartTime, &c.EndTime)
		if err != nil {
			return nil, err
		}
		results.OtherConnections = append(results.OtherConnections, c)
	}

	return results, nil
}
