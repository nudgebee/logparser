package logparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractPatterns_RemoteServiceException(t *testing.T) {
	logs := []string{
		"Failed to get latest location by identifier: USJOT | p44.exception.RemoteServiceException: Failed to make remote service call.\nApiErrorDto(httpStatusCode=404, httpMessage=Not Found, errorMessage=null, errors=[MessageDto(severity=ERROR, message=There does not exist any locations for type PORT_UN_LOCODE and value USJOT, diagnostic=null, source=null)], supportReferenceId=9ea963cd-7ba3-411f-8a3f-b01d569574bf)",
		"Failed to get latest location by identifier: USCVG | p44.exception.RemoteServiceException: Failed to make remote service call.\nApiErrorDto(httpStatusCode=404, httpMessage=Not Found, errorMessage=null, errors=[MessageDto(severity=ERROR, message=There does not exist any locations for type PORT_UN_LOCODE and value USCVG, diagnostic=null, source=null)], supportReferenceId=6dbbd508-607a-4316-86e0-35aa0ea61d4d)",
		"Failed to get latest location by identifier: USSLC | p44.exception.RemoteServiceException: Failed to make remote service call.\nApiErrorDto(httpStatusCode=404, httpMessage=Not Found, errorMessage=null, errors=[MessageDto(severity=ERROR, message=There does not exist any locations for type PORT_UN_LOCODE and value USSLC, diagnostic=null, source=null)], supportReferenceId=f99855b7-171b-4e5f-bc23-d4ea7f0e2c4a)",
		"Failed to get latest location by identifier: USZLV | p44.exception.RemoteServiceException: Failed to make remote service call.\nApiErrorDto(httpStatusCode=404, httpMessage=Not Found, errorMessage=null, errors=[MessageDto(severity=ERROR, message=There does not exist any locations for type PORT_UN_LOCODE and value USZLV, diagnostic=null, source=null)], supportReferenceId=c078713c-6a53-4902-8475-b002158637a7)",
		"Failed to get latest location by identifier: USCEF | p44.exception.RemoteServiceException: Failed to make remote service call.\nApiErrorDto(httpStatusCode=404, httpMessage=Not Found, errorMessage=null, errors=[MessageDto(severity=ERROR, message=There does not exist any locations for type PORT_UN_LOCODE and value USCEF, diagnostic=null, source=null)], supportReferenceId=9e3a5242-abeb-444d-ab9b-9c8bbbf0f9a8)",
	}

	patterns := ExtractPatterns(logs, 10)

	// Should find 1 pattern for all RemoteServiceException logs
	assert.Equal(t, 1, len(patterns), "Should cluster all similar RemoteServiceException logs into 1 pattern")

	if len(patterns) > 0 {
		pattern := patterns[0]
		assert.Equal(t, 5, pattern.Count, "Pattern should match all 5 logs")
		assert.Equal(t, 100.0, pattern.Percentage, "Pattern should represent 100% of logs")
		assert.Contains(t, pattern.Template, "Failed to get latest location by identifier", "Template should contain main error message")
		assert.Contains(t, pattern.Template, "*", "Template should contain wildcards for variable parts")
		assert.NotEmpty(t, pattern.Example, "Pattern should have an example log")
	}
}

func TestExtractPatterns_MixedExceptions(t *testing.T) {
	logs := []string{
		"Failed to get latest location by identifier: USJOT | p44.exception.RemoteServiceException: Failed to make remote service call.",
		"Failed to get latest location by identifier: USCVG | p44.exception.RemoteServiceException: Failed to make remote service call.",
		"DetectEtaChanges failed | java.lang.NullPointerException",
		"DetectEtaChanges failed | java.lang.NullPointerException",
		"DetectEtaChanges failed | java.lang.NullPointerException",
		"Failed to merge location: LocationDto(id=null, specifiedId=null, masterLocationId=null, version=0, tenantId=null)",
	}

	patterns := ExtractPatterns(logs, 10)

	// Should find 3 distinct patterns
	assert.GreaterOrEqual(t, len(patterns), 2, "Should find at least 2 distinct patterns")

	// First pattern should be most frequent (NullPointerException - 3 occurrences)
	assert.Equal(t, 3, patterns[0].Count, "First pattern should have 3 occurrences")
	assert.Contains(t, patterns[0].Template, "DetectEtaChanges", "First pattern should be NullPointerException")

	// Second pattern should be RemoteServiceException (2 occurrences)
	assert.Equal(t, 2, patterns[1].Count, "Second pattern should have 2 occurrences")
}

func TestExtractPatterns_EmptyInput(t *testing.T) {
	patterns := ExtractPatterns([]string{}, 10)
	assert.Equal(t, 0, len(patterns), "Empty input should return empty patterns")
}

func TestExtractPatterns_SingleLog(t *testing.T) {
	logs := []string{
		"Failed to get latest location by identifier: USJOT | p44.exception.RemoteServiceException",
	}

	patterns := ExtractPatterns(logs, 10)

	assert.Equal(t, 1, len(patterns), "Single log should return 1 pattern")
	if len(patterns) > 0 {
		assert.Equal(t, 1, patterns[0].Count, "Pattern count should be 1")
		assert.Equal(t, 100.0, patterns[0].Percentage, "Pattern percentage should be 100%")
	}
}

func TestExtractPatterns_MaxPatternsLimit(t *testing.T) {
	logs := []string{
		"Error type A occurred in service 1",
		"Error type B occurred in service 2",
		"Error type C occurred in service 3",
		"Error type D occurred in service 4",
		"Error type E occurred in service 5",
	}

	patterns := ExtractPatterns(logs, 3)

	assert.LessOrEqual(t, len(patterns), 3, "Should respect maxPatterns limit")
}

func TestExtractPatterns_WithUUIDs(t *testing.T) {
	logs := []string{
		"Request failed with ID: 9ea963cd-7ba3-411f-8a3f-b01d569574bf",
		"Request failed with ID: 6dbbd508-607a-4316-86e0-35aa0ea61d4d",
		"Request failed with ID: f99855b7-171b-4e5f-bc23-d4ea7f0e2c4a",
	}

	patterns := ExtractPatterns(logs, 10)

	// All UUIDs should be replaced with wildcards, creating 1 pattern
	assert.Equal(t, 1, len(patterns), "Should cluster logs with different UUIDs into 1 pattern")
	if len(patterns) > 0 {
		assert.Contains(t, patterns[0].Template, "*", "Template should contain wildcard for UUID")
		assert.Equal(t, 3, patterns[0].Count, "Pattern should match all 3 logs")
	}
}

func TestExtractPatterns_SortedByFrequency(t *testing.T) {
	logs := []string{
		"Database connection failed to host-123", // 1 occurrence
		"Network timeout on endpoint /api/users", "Network timeout on endpoint /api/users", // 2 occurrences
		"NullPointerException in service.process()", "NullPointerException in service.process()", "NullPointerException in service.process()", // 3 occurrences
	}

	patterns := ExtractPatterns(logs, 10)

	assert.GreaterOrEqual(t, len(patterns), 1, "Should find at least 1 pattern")

	// Verify sorted by count (descending)
	for i := 0; i < len(patterns)-1; i++ {
		assert.GreaterOrEqual(t, patterns[i].Count, patterns[i+1].Count,
			"Patterns should be sorted by count (descending)")
	}

	// Most frequent pattern should have 3 occurrences
	if len(patterns) > 0 {
		assert.Equal(t, 3, patterns[0].Count, "First pattern should have highest count")
	}
}

func TestExtractPatterns_WithNumbersAndCodes(t *testing.T) {
	logs := []string{
		"HTTP 404 error for endpoint /api/users/12345",
		"HTTP 500 error for endpoint /api/users/67890",
		"HTTP 404 error for endpoint /api/users/11111",
	}

	patterns := ExtractPatterns(logs, 10)

	// Should group by HTTP status code pattern
	assert.GreaterOrEqual(t, len(patterns), 1, "Should find at least 1 pattern")

	if len(patterns) > 0 {
		// Numbers and user IDs should be replaced with wildcards
		assert.Contains(t, patterns[0].Template, "*", "Template should contain wildcards for numbers")
	}
}
