package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/api/handlers"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/api/middleware"
)

// SetupRouter configures and returns the Gin router
func SetupRouter() *gin.Engine {
	router := gin.Default()

	// Configure CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		AllowCredentials: true,
	}))

	// API routes
	api := router.Group("/api")
	{
		// Auth routes (no auth required)
		auth := api.Group("/auth")
		{
			auth.POST("/login", handlers.Login)
			auth.POST("/logout", handlers.Logout)
			auth.GET("/session", handlers.CheckSession)
		}

		// Protected routes (auth required)
		protected := api.Group("")
		protected.Use(middleware.AuthRequired())
		{
			// Upload
			protected.POST("/upload", handlers.UploadPCAP)

			// Analysis
			protected.GET("/analysis/:id", handlers.GetAnalysis)
			protected.GET("/analyses", handlers.GetAnalyses)
			protected.DELETE("/analysis/:id", handlers.DeleteAnalysis)
		}
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	return router
}
