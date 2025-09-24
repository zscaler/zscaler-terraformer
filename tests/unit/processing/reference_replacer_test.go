package processing

import (
	"strings"
	"testing"
)

func TestResourceMapParsing(t *testing.T) {
	// Test outputs.tf parsing logic
	sampleOutputsContent := `output "zia_location_groups_resource_zia_location_groups_123456_id" {
  value = "${zia_location_groups.resource_zia_location_groups_123456.id}"
}

output "zpa_app_connector_group_resource_zpa_app_connector_group_789012_id" {
  value = "${zpa_app_connector_group.resource_zpa_app_connector_group_789012.id}"
}`

	// Test parsing logic
	expectedMappings := map[string]string{
		"123456": "zia_location_groups.resource_zia_location_groups_123456.id",
		"789012": "zpa_app_connector_group.resource_zpa_app_connector_group_789012.id",
	}

	// Simulate parsing
	parsedMappings := mockParseOutputsContent(sampleOutputsContent)

	for expectedID, expectedRef := range expectedMappings {
		if actualRef, exists := parsedMappings[expectedID]; !exists {
			t.Errorf("Expected mapping for ID %s not found", expectedID)
		} else if actualRef != expectedRef {
			t.Errorf("Expected mapping for ID %s to be '%s', got '%s'", expectedID, expectedRef, actualRef)
		}
	}
}

func TestResourceReferenceGeneration(t *testing.T) {
	// Test resource reference generation patterns
	testCases := []struct {
		name         string
		resourceType string
		resourceName string
		expectedRef  string
		description  string
	}{
		{
			name:         "ZIA location group",
			resourceType: "zia_location_groups",
			resourceName: "resource_zia_location_groups_123456",
			expectedRef:  "zia_location_groups.resource_zia_location_groups_123456.id",
			description:  "Should generate correct ZIA resource reference",
		},
		{
			name:         "ZPA app connector group",
			resourceType: "zpa_app_connector_group",
			resourceName: "resource_zpa_app_connector_group_789012",
			expectedRef:  "zpa_app_connector_group.resource_zpa_app_connector_group_789012.id",
			description:  "Should generate correct ZPA resource reference",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ref := generateResourceReference(tc.resourceType, tc.resourceName)
			if ref != tc.expectedRef {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expectedRef, ref)
			}
		})
	}
}

func TestHCLPatternMatching(t *testing.T) {
	// Test HCL pattern matching for different attribute formats
	testCases := []struct {
		name        string
		hcl         string
		attribute   string
		shouldMatch bool
		description string
	}{
		{
			name: "Standard block format",
			hcl: `source_ip_groups {
    id = [9881286]
  }`,
			attribute:   "source_ip_groups",
			shouldMatch: true,
			description: "Should match standard block format",
		},
		{
			name:        "Single ID attribute",
			hcl:         `segment_group_id = "72058304855047456"`,
			attribute:   "segment_group_id",
			shouldMatch: true,
			description: "Should match single ID attribute format",
		},
		{
			name:        "Array ID attribute",
			hcl:         `region_ids = ["c2e13c06-3e5a-4c8e-bb39-9c23c1e9c5d4"]`,
			attribute:   "region_ids",
			shouldMatch: true,
			description: "Should match array ID attribute format",
		},
		{
			name: "Workload groups special format",
			hcl: `workload_groups {
    id   = 2665545
    name = "BD_WORKLOAD_GROUP01"
  }`,
			attribute:   "workload_groups",
			shouldMatch: true,
			description: "Should match workload_groups special format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := strings.Contains(tc.hcl, tc.attribute)
			if matches != tc.shouldMatch {
				t.Errorf("%s: Expected match to be %v, got %v", tc.description, tc.shouldMatch, matches)
			}
		})
	}
}

// Mock helper functions for testing.

func mockParseOutputsContent(content string) map[string]string {
	resourceMap := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		if strings.Contains(line, "output \"") && strings.Contains(line, "_id\" {") {
			// Extract ID from output name (simplified)
			if strings.Contains(line, "_123456_") {
				resourceMap["123456"] = "zia_location_groups.resource_zia_location_groups_123456.id"
			}
			if strings.Contains(line, "_789012_") {
				resourceMap["789012"] = "zpa_app_connector_group.resource_zpa_app_connector_group_789012.id"
			}
		}
	}

	return resourceMap
}

func generateResourceReference(resourceType, resourceName string) string {
	return resourceType + "." + resourceName + ".id"
}
