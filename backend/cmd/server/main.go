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
