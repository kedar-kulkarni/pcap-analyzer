package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/session"
	"golang.org/x/crypto/bcrypt"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login handles user login
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user from database
	user, err := database.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create session
	sessionID, err := session.CreateUserSession(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Set session cookie
	c.SetCookie(
		"session_id",
		sessionID,
		int(session.SessionDuration.Seconds()),
		"/",
		"",
		false, // secure (set to true in production with HTTPS)
		true,  // httpOnly
	)

	c.JSON(http.StatusOK, gin.H{
		"message":  "Login successful",
		"user_id":  user.ID,
		"username": user.Username,
	})
}

// Logout handles user logout
func Logout(c *gin.Context) {
	sessionID, err := c.Cookie("session_id")
	if err == nil {
		session.DestroySession(sessionID)
	}

	// Clear cookie
	c.SetCookie(
		"session_id",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// CheckSession checks if the user has a valid session
func CheckSession(c *gin.Context) {
	sessionID, err := c.Cookie("session_id")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"authenticated": false})
		return
	}

	userID, err := session.ValidateSession(sessionID)
	if err != nil || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"authenticated": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user_id":       userID,
	})
}
