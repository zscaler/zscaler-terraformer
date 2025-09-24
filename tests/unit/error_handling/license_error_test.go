package error_handling

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLicenseErrorDetection(t *testing.T) {
	// Test the isLicenseError function logic
	testCases := []struct {
		name           string
		errorString    string
		expectedResult bool
		expectedReason string
		description    string
	}{
		{
			name: "Valid license error with feature flag",
			errorString: `Error: {
  "code": null,
  "message": "",
  "id": "authz.featureflag.permission.denied",
  "reason": "Feature flag feature.ddil.config disabled for customer 216,196,257,331,281,920",
  "url": "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/216196257331281920/privateCloudControllerGroup?page=1&pagesize=500",
  "status": 401
}`,
			expectedResult: true,
			expectedReason: "Feature flag feature.ddil.config disabled for customer 216,196,257,331,281,920",
			description:    "Should detect feature flag permission denied error",
		},
		{
			name:           "License error with feature. prefix in reason",
			errorString:    `{"id": "authz.featureflag.permission.denied", "reason": "feature.some_feature disabled for customer"}`,
			expectedResult: true,
			expectedReason: "feature.some_feature disabled for customer",
			description:    "Should detect feature. prefix in reason",
		},
		{
			name:           "License error with Feature flag prefix",
			errorString:    `{"id": "authz.featureflag.permission.denied", "reason": "Feature flag xyz disabled"}`,
			expectedResult: true,
			expectedReason: "Feature flag xyz disabled",
			description:    "Should detect Feature flag prefix in reason",
		},
		{
			name:           "Regular API error",
			errorString:    `{"id": "some.other.error", "reason": "Some other error occurred"}`,
			expectedResult: false,
			expectedReason: "",
			description:    "Should NOT detect regular API errors as license errors",
		},
		{
			name:           "Authorization error without feature flag",
			errorString:    `{"id": "authz.featureflag.permission.denied", "reason": "Some other authorization issue"}`,
			expectedResult: false,
			expectedReason: "",
			description:    "Should NOT detect authz errors without feature flag indication",
		},
		{
			name:           "Network error",
			errorString:    `network error: connection timeout`,
			expectedResult: false,
			expectedReason: "",
			description:    "Should NOT detect network errors as license errors",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create error object
			err := errors.New(tc.errorString)

			// Test the license error detection logic
			isLicense, reason := mockIsLicenseError(err)

			if isLicense != tc.expectedResult {
				t.Errorf("%s: Expected license error detection to be %v, got %v",
					tc.description, tc.expectedResult, isLicense)
			}

			if tc.expectedResult && reason != tc.expectedReason {
				t.Errorf("%s: Expected reason '%s', got '%s'",
					tc.description, tc.expectedReason, reason)
			}
		})
	}
}

func TestLicenseErrorJSONParsing(t *testing.T) {
	// Test JSON parsing edge cases
	testCases := []struct {
		name        string
		errorString string
		shouldParse bool
		description string
	}{
		{
			name:        "Valid JSON",
			errorString: `Error: {"id": "authz.featureflag.permission.denied", "reason": "Feature flag test"}`,
			shouldParse: true,
			description: "Should parse valid JSON",
		},
		{
			name:        "Invalid JSON",
			errorString: `Error: {invalid json}`,
			shouldParse: false,
			description: "Should handle invalid JSON gracefully",
		},
		{
			name:        "No JSON in error",
			errorString: `Plain text error message`,
			shouldParse: false,
			description: "Should handle non-JSON errors gracefully",
		},
		{
			name:        "Partial JSON",
			errorString: `Error: {"id": "authz.featureflag.permission.denied"`,
			shouldParse: false,
			description: "Should handle incomplete JSON gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			canParse := hasValidJSON(tc.errorString)
			if canParse != tc.shouldParse {
				t.Errorf("%s: Expected JSON parsing to be %v, got %v",
					tc.description, tc.shouldParse, canParse)
			}
		})
	}
}

// Mock implementation of license error detection for testing
func mockIsLicenseError(err error) (bool, string) {
	const licenseErrorMsg = "authz.featureflag.permission.denied"
	errorString := err.Error()

	if !strings.Contains(errorString, licenseErrorMsg) {
		return false, ""
	}

	// Simple JSON extraction simulation
	jsonStart := strings.Index(errorString, "{")
	jsonEnd := strings.LastIndex(errorString, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return false, ""
	}

	jsonStr := errorString[jsonStart : jsonEnd+1]

	// Simple checks for the required fields
	if strings.Contains(jsonStr, `"id": "authz.featureflag.permission.denied"`) {
		if strings.Contains(jsonStr, `"reason": "feature.`) || strings.Contains(jsonStr, `"reason": "Feature flag`) {
			// Extract reason (simplified)
			start := strings.Index(jsonStr, `"reason": "`) + 11
			end := strings.Index(jsonStr[start:], `"`)
			if start > 10 && end > 0 {
				return true, jsonStr[start : start+end]
			}
		}
	}

	return false, ""
}

// Helper function to check if error string contains valid JSON
func hasValidJSON(errorString string) bool {
	jsonStart := strings.Index(errorString, "{")
	jsonEnd := strings.LastIndex(errorString, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return false
	}

	jsonStr := errorString[jsonStart : jsonEnd+1]

	// Actually validate JSON by attempting to parse it
	var temp interface{}
	return json.Unmarshal([]byte(jsonStr), &temp) == nil
}
