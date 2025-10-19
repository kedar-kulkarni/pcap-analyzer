package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/analyzer"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/api"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
)

func main() {
	log.Println("Starting PCAP Analyzer Server...")

	// Initialize database
	dbPath := "backend/data/pcap-analyzer.db"
	if err := database.InitDB(dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()
	log.Println("Database initialized successfully")

	// Start worker pool for analysis jobs
	workerPool := analyzer.NewWorkerPool(2)
	workerPool.Start()
	defer workerPool.Stop()
	log.Println("Worker pool started")

	// Setup and start HTTP server
	router := api.SetupRouter()

	// Handle graceful shutdown
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
		<-sigchan
		log.Println("Shutting down gracefully...")
		workerPool.Stop()
		database.Close()
		os.Exit(0)
	}()

	// Start server
	log.Println("Server starting on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
