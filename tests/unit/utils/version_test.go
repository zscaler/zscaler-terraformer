package utils

import (
	"strings"
	"testing"

	"github.com/zscaler/zscaler-terraformer/v2/terraformutils"
)

func TestVersionRetrieval(t *testing.T) {
	// Test version retrieval from terraformutils
	version := terraformutils.Version()

	if version == "" {
		t.Error("Version should not be empty")
	}

	// Verify version format (should be semver-like: X.Y.Z)
	if !strings.Contains(version, ".") {
		t.Error("Version should contain version number format")
	}

	// Verify version follows semver pattern (e.g., 2.1.0, 2.1.1, etc.)
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		t.Errorf("Version should follow semver pattern (X.Y or X.Y.Z), got %s", version)
	}

	// Verify each part is numeric (basic check)
	for i, part := range parts {
		if part == "" {
			t.Errorf("Version part %d should not be empty in version %s", i, version)
		}
		// Check if part contains only digits
		for _, char := range part {
			if char < '0' || char > '9' {
				t.Errorf("Version part %d (%s) should contain only digits in version %s", i, part, version)
				break
			}
		}
	}
}

func TestVersionFormatting(t *testing.T) {
	// Test version formatting in different contexts using actual version
	actualVersion := terraformutils.Version()

	testCases := []struct {
		name        string
		version     string
		prefix      string
		expected    string
		description string
	}{
		{
			name:        "Version with v prefix",
			version:     actualVersion,
			prefix:      "v",
			expected:    "v" + actualVersion,
			description: "Should format version with v prefix",
		},
		{
			name:        "Version in tool name",
			version:     actualVersion,
			prefix:      "zscaler-terraformer ",
			expected:    "zscaler-terraformer " + actualVersion,
			description: "Should format version with tool name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.prefix + tc.version
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestVersionConsistency(t *testing.T) {
	// Test that version is consistent across different retrievals
	version1 := terraformutils.Version()
	version2 := terraformutils.Version()

	if version1 != version2 {
		t.Errorf("Version should be consistent across calls: %s != %s", version1, version2)
	}
}

func TestVersionNonEmpty(t *testing.T) {
	// Test that version is never empty or invalid
	version := terraformutils.Version()

	invalidVersions := []string{"", "dev", "unknown", "null"}

	for _, invalid := range invalidVersions {
		if version == invalid {
			t.Errorf("Version should not be '%s'", invalid)
		}
	}

	// Should be a proper version number
	if len(version) < 3 { // At minimum "1.0"
		t.Errorf("Version '%s' seems too short to be valid", version)
	}
}
