package logparser

import (
	"sort"
	"strings"

	goDrain "github.com/jaeyo/go-drain3/pkg/drain3"
)

// LogPattern represents a discovered log pattern with its statistics
type LogPattern struct {
	Template   string  // Log template with wildcards (e.g., "Failed to get * | Exception: *")
	Count      int     // Number of logs matching this pattern
	Percentage float64 // Percentage of total logs
	Example    string  // Example log message that matches this pattern
}

// ExtractPatterns analyzes multiple log lines and returns common patterns.
// It uses the Drain3 algorithm to cluster similar logs and extract templates.
//
// Parameters:
//   - logs: Array of log message strings to analyze
//   - maxPatterns: Maximum number of patterns to return (0 = return all)
//
// Returns:
//   - Array of LogPattern structs sorted by frequency (most common first)
//
// Example:
//
//	logs := []string{
//	    "Failed to get location: USJOT | RemoteServiceException",
//	    "Failed to get location: USCVG | RemoteServiceException",
//	    "DetectEtaChanges failed | NullPointerException",
//	}
//	patterns := ExtractPatterns(logs, 10)
//	// Returns 2 patterns:
//	// 1. "Failed to get location: <*> | RemoteServiceException" (count: 2)
//	// 2. "DetectEtaChanges failed | NullPointerException" (count: 1)
func ExtractPatterns(logs []string, maxPatterns int) []LogPattern {
	if len(logs) == 0 {
		return []LogPattern{}
	}

	// Configure Drain3 for log pattern extraction
	// These settings are optimized for error log analysis
	drain, err := goDrain.NewDrain(
		goDrain.WithDepth(4),          // Parse tree depth - balanced for structured logs
		goDrain.WithSimTh(0.5),        // 50% similarity threshold - groups similar errors
		goDrain.WithMaxChildren(50),   // Max children per tree node - performance optimized
		goDrain.WithMaxCluster(1000),  // Max number of clusters - handle diverse logs
	)

	if err != nil {
		return []LogPattern{}
	}

	// Map to store first example for each cluster
	clusterExamples := make(map[int64]string)

	// Process each log message
	for _, log := range logs {
		if strings.TrimSpace(log) == "" {
			continue
		}

		// Add to drain3 for pattern extraction
		cluster, _, err := drain.AddLogMessage(log)
		if err != nil {
			continue
		}

		// Store first example for this cluster if we don't have one yet
		if cluster != nil {
			if _, exists := clusterExamples[cluster.ClusterId]; !exists {
				clusterExamples[cluster.ClusterId] = log
			}
		}
	}

	// Get all clusters and convert to LogPattern
	clusters := drain.GetClusters()
	if len(clusters) == 0 {
		return []LogPattern{}
	}

	patterns := make([]LogPattern, 0, len(clusters))
	totalCount := 0

	for _, cluster := range clusters {
		template := formatDrainTemplate(cluster)
		if template != "" {
			example := clusterExamples[cluster.ClusterId]
			if example == "" && len(logs) > 0 {
				example = logs[0] // Fallback to first log if no example found
			}

			patterns = append(patterns, LogPattern{
				Template:   template,
				Count:      int(cluster.Size),
				Percentage: 0, // Will calculate after getting total
				Example:    example,
			})
			totalCount += int(cluster.Size)
		}
	}

	// Calculate percentages
	if totalCount > 0 {
		for i := range patterns {
			patterns[i].Percentage = float64(patterns[i].Count) * 100.0 / float64(totalCount)
		}
	}

	// Sort by count (descending), then by template alphabetically
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Count == patterns[j].Count {
			return patterns[i].Template < patterns[j].Template
		}
		return patterns[i].Count > patterns[j].Count
	})

	// Limit results if requested
	if maxPatterns > 0 && len(patterns) > maxPatterns {
		patterns = patterns[:maxPatterns]
	}

	return patterns
}

// formatDrainTemplate formats a drain3 cluster template for display
func formatDrainTemplate(cluster *goDrain.LogCluster) string {
	if cluster == nil || len(cluster.LogTemplateTokens) == 0 {
		return ""
	}

	// Join tokens with spaces
	template := strings.Join(cluster.LogTemplateTokens, " ")

	// Replace drain3 placeholders (<*>) with single asterisk for readability
	template = strings.ReplaceAll(template, "<*>", "*")

	return template
}
