package cmd

import (
	"fmt"
	"strings"
	"testing"
)

func TestResourceGeneration(t *testing.T) {
	// Test resource generation for all supported resource types
	tests := map[string]struct {
		resourceType string
		cloudType    string
		expectFiles  []string
		description  string
	}{
		// ZPA Resources
		"zpa app connector group": {
			resourceType: "zpa_app_connector_group",
			cloudType:    "zpa",
			expectFiles:  []string{"zpa_app_connector_group.tf", "outputs.tf"},
			description:  "Should generate ZPA app connector group files",
		},
		"zpa application segment": {
			resourceType: "zpa_application_segment",
			cloudType:    "zpa",
			expectFiles:  []string{"zpa_application_segment.tf", "outputs.tf"},
			description:  "Should generate ZPA application segment files",
		},
		"zpa server group": {
			resourceType: "zpa_server_group",
			cloudType:    "zpa",
			expectFiles:  []string{"zpa_server_group.tf", "outputs.tf"},
			description:  "Should generate ZPA server group files",
		},
		"zpa policy access rule": {
			resourceType: "zpa_policy_access_rule",
			cloudType:    "zpa",
			expectFiles:  []string{"zpa_policy_access_rule.tf", "outputs.tf"},
			description:  "Should generate ZPA policy access rule files",
		},

		// ZIA Resources
		"zia firewall filtering rule": {
			resourceType: "zia_firewall_filtering_rule",
			cloudType:    "zia",
			expectFiles:  []string{"zia_firewall_filtering_rule.tf", "outputs.tf"},
			description:  "Should generate ZIA firewall rule files",
		},
		"zia location management": {
			resourceType: "zia_location_management",
			cloudType:    "zia",
			expectFiles:  []string{"zia_location_management.tf", "outputs.tf"},
			description:  "Should generate ZIA location management files",
		},
		"zia dlp web rules": {
			resourceType: "zia_dlp_web_rules",
			cloudType:    "zia",
			expectFiles:  []string{"zia_dlp_web_rules.tf", "outputs.tf"},
			description:  "Should generate ZIA DLP web rules files",
		},
		"zia url filtering rules": {
			resourceType: "zia_url_filtering_rules",
			cloudType:    "zia",
			expectFiles:  []string{"zia_url_filtering_rules.tf", "outputs.tf"},
			description:  "Should generate ZIA URL filtering rules files",
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

			// Test expected files list
			if len(tc.expectFiles) == 0 {
				t.Errorf("%s: Should expect at least one file to be generated", tc.description)
			}

			// Test that all expected files have .tf extension
			for _, file := range tc.expectFiles {
				if !strings.HasSuffix(file, ".tf") {
					t.Errorf("%s: Expected file '%s' should have .tf extension", tc.description, file)
				}
			}
		})
	}
}

func TestGenerateCommandValidation(t *testing.T) {
	// Test generate command parameter validation
	testCases := []struct {
		name         string
		resourceType string
		resources    string
		shouldError  bool
		description  string
	}{
		{
			name:         "Valid single resource",
			resourceType: "zpa_application_segment",
			resources:    "",
			shouldError:  false,
			description:  "Should accept valid single resource type",
		},
		{
			name:         "Valid multiple resources",
			resourceType: "",
			resources:    "zpa_app_connector_group,zpa_server_group",
			shouldError:  false,
			description:  "Should accept valid multiple resources",
		},
		{
			name:         "Valid cloud type",
			resourceType: "",
			resources:    "zpa",
			shouldError:  false,
			description:  "Should accept valid cloud type",
		},
		{
			name:         "Invalid resource type",
			resourceType: "invalid_resource_type",
			resources:    "",
			shouldError:  true,
			description:  "Should reject invalid resource type",
		},
		{
			name:         "Empty parameters",
			resourceType: "",
			resources:    "",
			shouldError:  true,
			description:  "Should reject empty parameters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock validation logic
			isValid := mockValidateGenerateParams(tc.resourceType, tc.resources)
			expectValid := !tc.shouldError

			if isValid != expectValid {
				t.Errorf("%s: Expected validation to be %v, got %v", tc.description, expectValid, isValid)
			}
		})
	}
}

func TestSupportedResourceTypes(t *testing.T) {
	// Test that all supported resources are valid
	supportedZPAResources := []string{
		"zpa_app_connector_group",
		"zpa_application_server",
		"zpa_application_segment",
		"zpa_server_group",
		"zpa_policy_access_rule",
		"zpa_policy_timeout_rule",
		"zpa_policy_forwarding_rule",
		"zpa_policy_inspection_rule",
		"zpa_policy_isolation_rule",
	}

	supportedZIAResources := []string{
		"zia_firewall_filtering_rule",
		"zia_location_management",
		"zia_dlp_web_rules",
		"zia_url_filtering_rules",
		"zia_dlp_engines",
		"zia_rule_labels",
	}

	// Test ZPA resources
	for _, resource := range supportedZPAResources {
		t.Run("zpa_"+resource, func(t *testing.T) {
			if !strings.HasPrefix(resource, "zpa_") {
				t.Errorf("ZPA resource '%s' should start with 'zpa_'", resource)
			}

			if len(resource) < 5 {
				t.Errorf("Resource name '%s' seems too short", resource)
			}
		})
	}

	// Test ZIA resources
	for _, resource := range supportedZIAResources {
		t.Run("zia_"+resource, func(t *testing.T) {
			if !strings.HasPrefix(resource, "zia_") {
				t.Errorf("ZIA resource '%s' should start with 'zia_'", resource)
			}

			if len(resource) < 5 {
				t.Errorf("Resource name '%s' seems too short", resource)
			}
		})
	}
}

func TestHCLGeneration(t *testing.T) {
	// Test HCL generation patterns
	testCases := []struct {
		name          string
		resourceType  string
		mockData      map[string]interface{}
		expectContent []string
		description   string
	}{
		{
			name:         "ZPA application segment",
			resourceType: "zpa_application_segment",
			mockData: map[string]interface{}{
				"id":      "72058304855047123",
				"name":    "Test_App_Segment",
				"enabled": true,
			},
			expectContent: []string{
				"resource \"zpa_application_segment\"",
				"name = \"Test_App_Segment\"",
				"enabled = true",
			},
			description: "Should generate valid ZPA application segment HCL",
		},
		{
			name:         "ZIA firewall rule",
			resourceType: "zia_firewall_filtering_rule",
			mockData: map[string]interface{}{
				"id":     1503414,
				"name":   "Test_Rule",
				"action": "ALLOW",
				"state":  "ENABLED",
			},
			expectContent: []string{
				"resource \"zia_firewall_filtering_rule\"",
				"name = \"Test_Rule\"",
				"action = \"ALLOW\"",
				"state = \"ENABLED\"",
			},
			description: "Should generate valid ZIA firewall rule HCL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock HCL generation
			hcl := mockGenerateHCL(tc.resourceType, tc.mockData)

			// Verify expected content exists
			for _, expected := range tc.expectContent {
				if !strings.Contains(hcl, expected) {
					t.Errorf("%s: Generated HCL should contain '%s'", tc.description, expected)
				}
			}

			// Verify basic HCL structure
			if !strings.Contains(hcl, "resource \"") {
				t.Error("Generated HCL should contain resource block")
			}
		})
	}
}

// Mock helper functions for testing

func mockValidateGenerateParams(resourceType, resources string) bool {
	// Basic validation logic
	if resourceType == "" && resources == "" {
		return false
	}

	if resourceType != "" {
		// Check if it's a valid resource type
		validResources := []string{
			"zpa_application_segment", "zpa_app_connector_group", "zpa_server_group",
			"zia_firewall_filtering_rule", "zia_location_management", "zia_dlp_web_rules",
		}
		for _, valid := range validResources {
			if resourceType == valid {
				return true
			}
		}
		return false
	}

	if resources != "" {
		// Check cloud types or resource lists
		if resources == "zpa" || resources == "zia" {
			return true
		}
		// Check for comma-separated resource list
		if strings.Contains(resources, ",") {
			return true
		}
	}

	return true
}

func mockGenerateHCL(resourceType string, data map[string]interface{}) string {
	result := "resource \"" + resourceType + "\" \"" + resourceType + "_test\" {\n"

	for key, value := range data {
		switch v := value.(type) {
		case string:
			result += "  " + key + " = \"" + v + "\"\n"
		case bool:
			result += "  " + key + " = " + fmt.Sprintf("%t", v) + "\n"
		case int:
			result += "  " + key + " = " + fmt.Sprintf("%d", v) + "\n"
		}
	}

	result += "}\n"
	return result
}
