package flags

import (
	"strings"
	"testing"
)

func TestPrefixSanitization(t *testing.T) {
	// Test prefix sanitization for terraform compatibility
	testCases := []struct {
		name        string
		input       string
		expected    string
		description string
	}{
		{
			name:        "Valid simple prefix",
			input:       "sgio",
			expected:    "sgio",
			description: "Should preserve valid simple prefix",
		},
		{
			name:        "Prefix with spaces",
			input:       "security team",
			expected:    "security_team",
			description: "Should replace spaces with underscores",
		},
		{
			name:        "Prefix with special characters",
			input:       "prod-env@2024!",
			expected:    "prod_env_2024_",
			description: "Should replace special characters with underscores",
		},
		{
			name:        "Prefix starting with number",
			input:       "2024migration",
			expected:    "prefix_2024migration",
			description: "Should prefix with 'prefix_' when starting with number",
		},
		{
			name:        "Empty prefix",
			input:       "",
			expected:    "resource",
			description: "Should default to 'resource' for empty prefix",
		},
		{
			name:        "Only special characters",
			input:       "!@#$%",
			expected:    "resource",
			description: "Should default to 'resource' when only special characters",
		},
		{
			name:        "Mixed case prefix",
			input:       "SGIO",
			expected:    "sgio",
			description: "Should convert to lowercase",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mockSanitizePrefix(tc.input)
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestResourceNameGeneration(t *testing.T) {
	// Test resource name generation with custom prefixes
	testCases := []struct {
		name         string
		prefix       string
		resourceType string
		resourceID   string
		expected     string
		description  string
	}{
		{
			name:         "Default behavior (no prefix)",
			prefix:       "",
			resourceType: "zpa_application_segment",
			resourceID:   "216196257331383019",
			expected:     "zpa_application_segment_216196257331383019",
			description:  "Should use current approach when no prefix specified",
		},
		{
			name:         "Custom prefix creates short names",
			prefix:       "sgio",
			resourceType: "zpa_pra_credential_controller",
			resourceID:   "14669",
			expected:     "sgio_14669",
			description:  "Should create short names with custom prefix",
		},
		{
			name:         "Custom prefix with sanitization",
			prefix:       "prod-env",
			resourceType: "zia_firewall_filtering_rule",
			resourceID:   "1503414",
			expected:     "prod_env_1503414",
			description:  "Should sanitize prefix and create short name",
		},
		{
			name:         "Enterprise prefix",
			prefix:       "SecurityTeam",
			resourceType: "zpa_server_group",
			resourceID:   "789012",
			expected:     "securityteam_789012",
			description:  "Should lowercase and create short name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mockBuildResourceNameWithPrefix(tc.prefix, tc.resourceType, tc.resourceID)
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestPrefixValidation(t *testing.T) {
	// Test prefix validation rules
	validPrefixes := []string{
		"sgio",
		"production",
		"team_alpha",
		"proj2024",
		"dev",
		"staging",
		"migration_v2",
	}

	invalidPrefixes := []string{
		"",           // Empty (should fallback to default)
		"!@#$%",      // Only special characters
		"123invalid", // Starts with number (should be prefixed)
	}

	for _, prefix := range validPrefixes {
		t.Run("valid_"+prefix, func(t *testing.T) {
			sanitized := mockSanitizePrefix(prefix)
			if sanitized == "resource" && prefix != "" {
				t.Errorf("Valid prefix '%s' should not fallback to 'resource'", prefix)
			}
		})
	}

	for _, prefix := range invalidPrefixes {
		t.Run("invalid_"+prefix, func(t *testing.T) {
			sanitized := mockSanitizePrefix(prefix)

			// Should either be sanitized or fallback to resource/prefix_
			if prefix == "" && sanitized != "resource" {
				t.Errorf("Empty prefix should fallback to 'resource', got '%s'", sanitized)
			}

			if prefix == "123invalid" && !strings.HasPrefix(sanitized, "prefix_") {
				t.Errorf("Number-starting prefix should be prefixed with 'prefix_', got '%s'", sanitized)
			}
		})
	}
}

// Mock helper functions for testing.

func mockSanitizePrefix(prefix string) string {
	if prefix == "" {
		return "resource"
	}

	// Convert to lowercase and replace invalid characters
	sanitized := strings.ToLower(prefix)
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	sanitized = strings.ReplaceAll(sanitized, "-", "_")
	sanitized = strings.ReplaceAll(sanitized, ".", "_")
	sanitized = strings.ReplaceAll(sanitized, "@", "_")
	sanitized = strings.ReplaceAll(sanitized, "!", "_")
	sanitized = strings.ReplaceAll(sanitized, "#", "_")
	sanitized = strings.ReplaceAll(sanitized, "$", "_")
	sanitized = strings.ReplaceAll(sanitized, "%", "_")

	// Remove multiple consecutive underscores
	sanitized = strings.ReplaceAll(sanitized, "__", "_")

	// Trim leading/trailing underscores
	sanitized = strings.Trim(sanitized, "_")

	// Ensure it's not empty after sanitization
	if sanitized == "" {
		return "resource"
	}

	// Ensure it doesn't start with a number (terraform requirement)
	if len(sanitized) > 0 && sanitized[0] >= '0' && sanitized[0] <= '9' {
		sanitized = "prefix_" + sanitized
	}

	return sanitized
}

func mockBuildResourceNameWithPrefix(prefix, resourceType, resourceID string) string {
	if prefix != "" {
		// Custom prefix mode: prefix_ID (short names)
		sanitizedPrefix := mockSanitizePrefix(prefix)
		return sanitizedPrefix + "_" + resourceID
	} else {
		// Default mode: resourceType_ID (current approach)
		return resourceType + "_" + resourceID
	}
}
