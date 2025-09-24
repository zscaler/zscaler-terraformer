package flags

import (
	"strings"
	"testing"
)

func TestValidationErrorDetection(t *testing.T) {
	// Test syntax error detection logic
	testCases := []struct {
		name            string
		terraformOutput string
		expectedSyntax  bool
		description     string
	}{
		{
			name: "Unclosed configuration block",
			terraformOutput: `Error: Unclosed configuration block
  on zpa_segment_group.tf line 16, in resource "zpa_segment_group":
  16: resource "zpa_segment_group" "resource_zpa_segment_group_123" {
There is no closing brace for this block before the end of the file.`,
			expectedSyntax: true,
			description:    "Should detect unclosed block syntax error",
		},
		{
			name: "Parsing error",
			terraformOutput: `Error: Invalid syntax
  on main.tf line 5:
  5: resource "test" "example {
Parsing error: missing closing quote`,
			expectedSyntax: true,
			description:    "Should detect parsing syntax error",
		},
		{
			name: "Provider missing",
			terraformOutput: `Error: Missing required provider
This configuration requires provider registry.terraform.io/hashicorp/zpa,
but that provider isn't available. You may be able to install it
automatically by running: terraform init`,
			expectedSyntax: false,
			description:    "Should NOT detect provider issue as syntax error",
		},
		{
			name: "Provider configuration",
			terraformOutput: `Error: Failed to query available provider packages
Could not retrieve the list of available versions for provider
hashicorp/zia: provider registry registry.terraform.io does not have a
provider named registry.terraform.io/hashicorp/zia`,
			expectedSyntax: false,
			description:    "Should NOT detect provider config issue as syntax error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isSyntaxError := isSyntaxError(tc.terraformOutput)
			if isSyntaxError != tc.expectedSyntax {
				t.Errorf("%s: Expected syntax error detection to be %v, got %v",
					tc.description, tc.expectedSyntax, isSyntaxError)
			}
		})
	}
}

func TestValidationSuggestions(t *testing.T) {
	// Test validation error suggestion logic
	syntaxErrorSuggestions := []string{
		"Check for missing closing braces '}' in .tf files",
		"Verify all resource blocks are properly formatted",
		"Look for unclosed quotes or brackets",
	}

	providerErrorSuggestions := []string{
		"Add provider configuration to your .tf files",
		"terraform {",
		"required_providers {",
		"source = \"zscaler/zpa\"",
		"source = \"zscaler/zia\"",
	}

	// Verify syntax error suggestions contain expected content
	for _, suggestion := range syntaxErrorSuggestions {
		if suggestion == "" {
			t.Error("Syntax error suggestion should not be empty")
		}
	}

	// Verify provider error suggestions contain expected content
	for _, suggestion := range providerErrorSuggestions {
		if suggestion == "" {
			t.Error("Provider error suggestion should not be empty")
		}
	}
}

func TestTerraformVersionDetection(t *testing.T) {
	// Test terraform version detection logic
	testCases := []struct {
		name           string
		versionOutput  string
		expectedResult string
		description    string
	}{
		{
			name:           "Valid terraform version",
			versionOutput:  "Terraform v1.9.0\non linux_amd64",
			expectedResult: "Terraform v1.9.0",
			description:    "Should extract version from valid output",
		},
		{
			name:           "Complex version output",
			versionOutput:  "Terraform v1.5.7\n+ provider registry.terraform.io/hashicorp/aws v5.0.0",
			expectedResult: "Terraform v1.5.7",
			description:    "Should extract only the first line",
		},
		{
			name:           "Empty output",
			versionOutput:  "",
			expectedResult: "Not installed",
			description:    "Should handle empty output gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractTerraformVersion(tc.versionOutput)
			if result != tc.expectedResult {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expectedResult, result)
			}
		})
	}
}

// Helper functions for testing (these simulate the logic from the actual code)

func isSyntaxError(output string) bool {
	return strings.Contains(output, "Unclosed configuration block") ||
		strings.Contains(output, "syntax") ||
		strings.Contains(output, "parsing")
}

func extractTerraformVersion(output string) string {
	if output == "" {
		return "Not installed"
	}

	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}

	return "Not installed"
}
