package error_handling

import (
	"strings"
	"testing"
)

func TestZIAAPIErrorHandling(t *testing.T) {
	// Test ZIA API error handling patterns
	testCases := []struct {
		name        string
		errorMsg    string
		shouldSkip  bool
		description string
	}{
		{
			name:        "Rate limit error",
			errorMsg:    "Rate limit exceeded",
			shouldSkip:  true,
			description: "Should handle rate limit errors gracefully",
		},
		{
			name:        "Authentication error",
			errorMsg:    "Authentication failed",
			shouldSkip:  false,
			description: "Should not skip authentication errors",
		},
		{
			name:        "Resource not found",
			errorMsg:    "Resource not found",
			shouldSkip:  true,
			description: "Should skip when resource doesn't exist",
		},
		{
			name:        "Permission denied",
			errorMsg:    "Permission denied",
			shouldSkip:  false,
			description: "Should not skip permission errors",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock ZIA error handling logic
			shouldSkip := mockHandleZIAAPIError(tc.errorMsg)
			if shouldSkip != tc.shouldSkip {
				t.Errorf("%s: Expected shouldSkip to be %v, got %v", tc.description, tc.shouldSkip, shouldSkip)
			}
		})
	}
}

func TestZPAAPIErrorHandling(t *testing.T) {
	// Test ZPA API error handling patterns
	testCases := []struct {
		name        string
		errorMsg    string
		shouldSkip  bool
		description string
	}{
		{
			name:        "Feature flag disabled",
			errorMsg:    "authz.featureflag.permission.denied",
			shouldSkip:  true,
			description: "Should skip feature flag errors",
		},
		{
			name:        "Invalid credentials",
			errorMsg:    "Invalid authentication credentials",
			shouldSkip:  false,
			description: "Should not skip credential errors",
		},
		{
			name:        "Resource not found",
			errorMsg:    "Resource not found",
			shouldSkip:  true,
			description: "Should skip when resource doesn't exist",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock ZPA error handling logic
			shouldSkip := mockHandleZPAAPIError(tc.errorMsg)
			if shouldSkip != tc.shouldSkip {
				t.Errorf("%s: Expected shouldSkip to be %v, got %v", tc.description, tc.shouldSkip, shouldSkip)
			}
		})
	}
}

// Mock error handling functions
func mockHandleZIAAPIError(errorMsg string) bool {
	// Simplified ZIA error handling logic
	skipPatterns := []string{"Rate limit", "not found"}
	for _, pattern := range skipPatterns {
		if contains(errorMsg, pattern) {
			return true
		}
	}
	return false
}

func mockHandleZPAAPIError(errorMsg string) bool {
	// Simplified ZPA error handling logic
	skipPatterns := []string{"authz.featureflag.permission.denied", "not found"}
	for _, pattern := range skipPatterns {
		if contains(errorMsg, pattern) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
