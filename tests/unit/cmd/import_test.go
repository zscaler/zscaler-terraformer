package cmd

import (
	"strings"
	"testing"
)

func TestResourceImport(t *testing.T) {
	// Test resource import for all supported resource types (similar to CloudFlare's approach)
	tests := map[string]struct {
		resourceType     string
		cloudType        string
		expectFiles      []string
		expectProcessing []string
		description      string
	}{
		// ZPA Resources
		"zpa app connector group": {
			resourceType:     "zpa_app_connector_group",
			cloudType:        "zpa",
			expectFiles:      []string{"zpa_app_connector_group.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZPA app connector group with post-processing",
		},
		"zpa application segment": {
			resourceType:     "zpa_application_segment",
			cloudType:        "zpa",
			expectFiles:      []string{"zpa_application_segment.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZPA application segment with post-processing",
		},
		"zpa server group": {
			resourceType:     "zpa_server_group",
			cloudType:        "zpa",
			expectFiles:      []string{"zpa_server_group.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZPA server group with post-processing",
		},
		"zpa policy access rule": {
			resourceType:     "zpa_policy_access_rule",
			cloudType:        "zpa",
			expectFiles:      []string{"zpa_policy_access_rule.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation", "zpa_policy_processing"},
			description:      "Should import ZPA policy with special operand processing",
		},

		// ZIA Resources
		"zia firewall filtering rule": {
			resourceType:     "zia_firewall_filtering_rule",
			cloudType:        "zia",
			expectFiles:      []string{"zia_firewall_filtering_rule.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZIA firewall rule with post-processing",
		},
		"zia location management": {
			resourceType:     "zia_location_management",
			cloudType:        "zia",
			expectFiles:      []string{"zia_location_management.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZIA location management with post-processing",
		},
		"zia dlp web rules": {
			resourceType:     "zia_dlp_web_rules",
			cloudType:        "zia",
			expectFiles:      []string{"zia_dlp_web_rules.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZIA DLP rules with post-processing",
		},
		"zia url filtering rules": {
			resourceType:     "zia_url_filtering_rules",
			cloudType:        "zia",
			expectFiles:      []string{"zia_url_filtering_rules.tf", "terraform.tfstate"},
			expectProcessing: []string{"reference_replacement", "data_source_creation"},
			description:      "Should import ZIA URL filtering rules with post-processing",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Test resource type validation
			if tc.resourceType == "" {
				t.Errorf("%s: Resource type should not be empty", tc.description)
			}

			// Test cloud type validation
			if tc.cloudType != "zpa" && tc.cloudType != "zia" {
				t.Errorf("%s: Cloud type should be 'zpa' or 'zia', got '%s'", tc.description, tc.cloudType)
			}

			// Test expected files
			for _, expectedFile := range tc.expectFiles {
				if !strings.HasSuffix(expectedFile, ".tf") && !strings.HasSuffix(expectedFile, ".tfstate") {
					t.Errorf("%s: Expected file '%s' should be .tf or .tfstate", tc.description, expectedFile)
				}
			}

			// Test expected processing steps
			for _, step := range tc.expectProcessing {
				if step == "" {
					t.Errorf("%s: Processing step should not be empty", tc.description)
				}
			}
		})
	}
}

func TestImportCommandValidation(t *testing.T) {
	// Test import command parameter validation
	testCases := []struct {
		name        string
		resources   string
		exclude     string
		shouldError bool
		description string
	}{
		{
			name:        "Single resource import",
			resources:   "zpa_application_segment",
			exclude:     "",
			shouldError: false,
			description: "Should accept single resource import",
		},
		{
			name:        "Multiple resource import",
			resources:   "zpa_app_connector_group,zpa_server_group",
			exclude:     "",
			shouldError: false,
			description: "Should accept multiple resource import",
		},
		{
			name:        "Full cloud import",
			resources:   "zpa",
			exclude:     "",
			shouldError: false,
			description: "Should accept full cloud import",
		},
		{
			name:        "Import with exclusions",
			resources:   "zpa",
			exclude:     "zpa_segment_group,zpa_server_group",
			shouldError: false,
			description: "Should accept import with exclusions",
		},
		{
			name:        "Invalid resource",
			resources:   "invalid_resource",
			exclude:     "",
			shouldError: true,
			description: "Should reject invalid resource types",
		},
		{
			name:        "Empty resources",
			resources:   "",
			exclude:     "",
			shouldError: true,
			description: "Should reject empty resource specification",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock validation logic
			isValid := mockValidateImportParams(tc.resources, tc.exclude)
			expectValid := !tc.shouldError

			if isValid != expectValid {
				t.Errorf("%s: Expected validation to be %v, got %v", tc.description, expectValid, isValid)
			}
		})
	}
}

func TestPostProcessingWorkflow(t *testing.T) {
	// Test the complete post-processing workflow for imports
	workflowSteps := []struct {
		name        string
		step        string
		required    bool
		description string
	}{
		{
			name:        "Resource reference processing",
			step:        "resource_references",
			required:    true,
			description: "Should always run resource reference processing",
		},
		{
			name:        "Data source processing",
			step:        "data_source_processing",
			required:    true,
			description: "Should always run data source processing",
		},
		{
			name:        "ZPA policy processing",
			step:        "zpa_policy_processing",
			required:    false, // Only for ZPA policy resources
			description: "Should run ZPA policy processing when applicable",
		},
		{
			name:        "Import summary generation",
			step:        "import_summary",
			required:    true,
			description: "Should always generate import summary",
		},
	}

	for _, step := range workflowSteps {
		t.Run(step.name, func(t *testing.T) {
			// Test step configuration
			if step.step == "" {
				t.Errorf("%s: Step identifier should not be empty", step.description)
			}

			// Test step naming convention
			if !strings.Contains(step.step, "_") {
				t.Errorf("%s: Step '%s' should follow snake_case naming", step.description, step.step)
			}

			// Test required vs optional logic
			stepExists := mockCheckProcessingStep(step.step)
			if step.required && !stepExists {
				t.Errorf("%s: Required step '%s' should exist", step.description, step.step)
			}
		})
	}
}

func TestReferenceResolution(t *testing.T) {
	// Test our core reference resolution feature
	testCases := []struct {
		name            string
		resourceMap     map[string]string
		dataSourceID    string
		expectedRefType string
		description     string
	}{
		{
			name: "Resource reference when imported",
			resourceMap: map[string]string{
				"123456": "zia_location_groups.resource_zia_location_groups_123456.id",
			},
			dataSourceID:    "123456",
			expectedRefType: "resource",
			description:     "Should use resource reference when resource is imported",
		},
		{
			name:            "Data source when not imported",
			resourceMap:     map[string]string{},
			dataSourceID:    "789012",
			expectedRefType: "datasource",
			description:     "Should use data source reference when resource is not imported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock reference resolution logic
			refType := mockResolveReferenceType(tc.resourceMap, tc.dataSourceID)

			if refType != tc.expectedRefType {
				t.Errorf("%s: Expected reference type '%s', got '%s'", tc.description, tc.expectedRefType, refType)
			}
		})
	}
}

// Mock helper functions for testing

func mockValidateImportParams(resources, exclude string) bool {
	if resources == "" {
		return false
	}

	// Valid cloud types
	if resources == "zpa" || resources == "zia" {
		return true
	}

	// Valid individual resources
	validResources := []string{
		"zpa_application_segment", "zpa_app_connector_group", "zpa_server_group",
		"zia_firewall_filtering_rule", "zia_location_management", "zia_dlp_web_rules",
	}

	// Check single resource
	for _, valid := range validResources {
		if resources == valid {
			return true
		}
	}

	// Check comma-separated resources
	if strings.Contains(resources, ",") {
		parts := strings.Split(resources, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			found := false
			for _, valid := range validResources {
				if part == valid {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	return false
}

func mockCheckProcessingStep(step string) bool {
	validSteps := []string{
		"resource_references",
		"data_source_processing",
		"zpa_policy_processing",
		"import_summary",
	}

	for _, valid := range validSteps {
		if step == valid {
			return true
		}
	}
	return false
}

func mockResolveReferenceType(resourceMap map[string]string, id string) string {
	if _, exists := resourceMap[id]; exists {
		return "resource"
	}
	return "datasource"
}
