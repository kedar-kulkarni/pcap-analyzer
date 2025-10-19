package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kedar-kulkarni/pcap-analyzer/backend/internal/database"
)

// GetAnalysis retrieves analysis status and results
func GetAnalysis(c *gin.Context) {
	userID, _ := c.Get("user_id")
	analysisIDStr := c.Param("id")

	analysisID, err := strconv.Atoi(analysisIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	// Get analysis
	analysis, err := database.GetAnalysis(analysisID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve analysis"})
		return
	}

	if analysis == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}

	// Check if user owns this analysis
	if analysis.UserID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// If analysis is not completed, just return status
	if analysis.Status != "completed" {
		c.JSON(http.StatusOK, gin.H{
			"analysis": analysis,
		})
		return
	}

	// Get full results
	results, err := database.GetAnalysisResults(analysisID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve results"})
		return
	}

	c.JSON(http.StatusOK, results)
}

// GetAnalyses retrieves all analyses for the current user
func GetAnalyses(c *gin.Context) {
	userID, _ := c.Get("user_id")

	analyses, err := database.GetUserAnalyses(userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve analyses"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"analyses": analyses,
	})
}

// DeleteAnalysis deletes an analysis and its associated file
func DeleteAnalysis(c *gin.Context) {
	userID, _ := c.Get("user_id")
	analysisIDStr := c.Param("id")

	analysisID, err := strconv.Atoi(analysisIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	// Get analysis to check ownership and get filename
	analysis, err := database.GetAnalysis(analysisID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve analysis"})
		return
	}

	if analysis == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}

	// Check if user owns this analysis
	if analysis.UserID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Delete analysis from database (cascades to related data)
	err = database.DeleteAnalysis(analysisID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete analysis"})
		return
	}

	// Delete PCAP file
	uploadPath := filepath.Join("backend", "uploads", analysis.Filename)
	os.Remove(uploadPath) // Ignore error if file doesn't exist

	c.JSON(http.StatusOK, gin.H{
		"message": "Analysis deleted successfully",
	})
}
