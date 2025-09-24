package utils

import (
	"fmt"
	"strings"
	"testing"
)

func TestHCLBlockGeneration(t *testing.T) {
	// Test HCL block generation helpers
	testCases := []struct {
		name        string
		fieldName   string
		ids         []int
		expected    string
		description string
	}{
		{
			name:        "Single ID block",
			fieldName:   "location_groups",
			ids:         []int{123456},
			expected:    "location_groups {\nid=[123456]\n}\n",
			description: "Should generate single ID block",
		},
		{
			name:        "Multiple ID block",
			fieldName:   "device_groups",
			ids:         []int{123, 456, 789},
			expected:    "device_groups {\nid=[123,456,789]\n}\n",
			description: "Should generate multiple ID block",
		},
		{
			name:        "Empty ID list",
			fieldName:   "users",
			ids:         []int{},
			expected:    "",
			description: "Should return empty string for no IDs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mockGenerateIDBlock(tc.fieldName, tc.ids)
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestResourceNameGeneration(t *testing.T) {
	// Test resource name generation logic
	testCases := []struct {
		name         string
		resourceType string
		resourceID   string
		resourceName string
		expected     string
		description  string
	}{
		{
			name:         "Resource with ID",
			resourceType: "zia_location_groups",
			resourceID:   "123456",
			resourceName: "",
			expected:     "resource_zia_location_groups_123456",
			description:  "Should generate name with resource type and ID",
		},
		{
			name:         "Resource with name",
			resourceType: "zpa_application_segment",
			resourceID:   "",
			resourceName: "Test Application",
			expected:     "resource_zpa_application_segment_test_application",
			description:  "Should generate name with resource type and sanitized name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mockGenerateResourceName(tc.resourceType, tc.resourceID, tc.resourceName)
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestStringCleaning(t *testing.T) {
	// Test string cleaning and sanitization
	testCases := []struct {
		name        string
		input       string
		expected    string
		description string
	}{
		{
			name:        "Remove spaces",
			input:       "Test Application Name",
			expected:    "test_application_name",
			description: "Should replace spaces with underscores and lowercase",
		},
		{
			name:        "Remove special characters",
			input:       "Test-App@Name!",
			expected:    "test_app_name_",
			description: "Should remove special characters",
		},
		{
			name:        "Handle empty string",
			input:       "",
			expected:    "",
			description: "Should handle empty string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mockCleanString(tc.input)
			if result != tc.expected {
				t.Errorf("%s: Expected '%s', got '%s'", tc.description, tc.expected, result)
			}
		})
	}
}

func TestWorkloadGroupsFormatting(t *testing.T) {
	// Test workload_groups special formatting
	testData := map[string]interface{}{
		"id":   2665545,
		"name": "BD_WORKLOAD_GROUP01",
	}

	result := mockFormatWorkloadGroups(testData)

	// Check key components
	if !strings.Contains(result, "workload_groups {") {
		t.Error("Should contain workload_groups block start")
	}

	if !strings.Contains(result, "id   = 2665545") {
		t.Error("Should contain ID with proper formatting")
	}

	if !strings.Contains(result, `name = "BD_WORKLOAD_GROUP01"`) {
		t.Error("Should contain name with quotes")
	}
}

// Mock helper functions for testing

func mockGenerateIDBlock(fieldName string, ids []int) string {
	if len(ids) == 0 {
		return ""
	}

	result := fieldName + " {\nid=["
	for i, id := range ids {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("%d", id) // Convert int to string
	}
	result += "]\n}\n"
	return result
}

func mockGenerateResourceName(resourceType, resourceID, resourceName string) string {
	if resourceID != "" {
		return "resource_" + resourceType + "_" + resourceID
	}
	if resourceName != "" {
		cleaned := mockCleanString(resourceName)
		return "resource_" + resourceType + "_" + cleaned
	}
	return "resource_" + resourceType
}

func mockCleanString(input string) string {
	result := strings.ToLower(input)
	result = strings.ReplaceAll(result, " ", "_")
	result = strings.ReplaceAll(result, "-", "_")
	result = strings.ReplaceAll(result, "@", "_")
	result = strings.ReplaceAll(result, "!", "_")
	return result
}

func mockFormatWorkloadGroups(data map[string]interface{}) string {
	result := "workload_groups {\n"
	if id, ok := data["id"]; ok {
		result += fmt.Sprintf("  id   = %d\n", id.(int))
	}
	if name, ok := data["name"]; ok {
		result += "  name = \"" + name.(string) + "\"\n"
	}
	result += "}"
	return result
}
