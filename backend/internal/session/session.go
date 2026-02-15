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

package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
)

const (
	SessionDuration = 24 * time.Hour
	SessionIDLength = 32
)

// GenerateSessionID generates a random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, SessionIDLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CreateUserSession creates a new session for a user
func CreateUserSession(userID int) (string, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(SessionDuration)
	err = database.CreateSession(sessionID, userID, expiresAt)
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

// ValidateSession validates a session and returns the user ID
func ValidateSession(sessionID string) (int, error) {
	session, err := database.GetSession(sessionID)
	if err != nil {
		return 0, err
	}

	if session == nil {
		return 0, nil
	}

	return session.UserID, nil
}

// DestroySession removes a session
func DestroySession(sessionID string) error {
	return database.DeleteSession(sessionID)
}
