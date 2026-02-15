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

package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/analyzer"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
)

// UploadPCAP handles PCAP file upload
func UploadPCAP(c *gin.Context) {
	userID, _ := c.Get("user_id")

	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// Validate file extension
	ext := filepath.Ext(file.Filename)
	if ext != ".pcap" && ext != ".pcapng" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only .pcap and .pcapng files are supported"})
		return
	}

	// Create unique filename
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("%d_%s", timestamp, file.Filename)
	uploadPath := filepath.Join("backend", "uploads", filename)

	// Save file
	if err := c.SaveUploadedFile(file, uploadPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Create analysis record in database
	analysisID, err := database.CreateAnalysis(userID.(int), filename)
	if err != nil {
		// Clean up uploaded file
		os.Remove(uploadPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create analysis"})
		return
	}

	// Queue analysis job
	job := analyzer.AnalysisJob{
		AnalysisID: int(analysisID),
		PcapPath:   uploadPath,
	}
	analyzer.JobQueue <- job

	c.JSON(http.StatusOK, gin.H{
		"message":     "File uploaded successfully",
		"analysis_id": analysisID,
		"filename":    filename,
	})
}
