package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/session"
)

// AuthRequired is a middleware that checks if the user is authenticated
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session cookie
		sessionID, err := c.Cookie("session_id")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Validate session
		userID, err := session.ValidateSession(sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		// Set user ID in context
		c.Set("user_id", userID)
		c.Next()
	}
}
