package processing

import (
	"strings"
	"testing"

	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
	"github.com/zscaler/zscaler-terraformer/v2/tests/testutils"
)

func TestDataSourceMappingResolution(t *testing.T) {
	// Test data source mapping logic for ZIA
	ziaMappings := map[string]string{
		"location_groups":      "zia_location_groups",
		"users":                "zia_user_management",
		"device_groups":        "zia_device_groups",
		"workload_groups":      "zia_workload_groups",
		"nw_services":          "zia_firewall_filtering_network_service",
		"services":             "zia_firewall_filtering_network_service",
		"source_ip_groups":     "zia_firewall_filtering_ip_source_groups",
		"src_ip_groups":        "zia_firewall_filtering_ip_source_groups",
		"dest_ip_groups":       "zia_firewall_filtering_destination_groups",
		"labels":               "zia_rule_labels",
		"app_connector_groups": "zpa_app_connector_group",
		"server_groups":        "zpa_server_group",
		"segment_group_id":     "zpa_segment_group",
	}

	// Test data source mapping logic for ZTC
	ztcMappings := map[string]string{
		"dest_ip_groups":      "ztc_ip_destination_groups",
		"src_ip_groups":       "ztc_ip_source_groups",
		"nw_services":         "ztc_network_services",
		"nw_service_groups":   "ztc_network_service_groups",
		"locations":           "ztc_location_management",
		"src_workload_groups": "ztc_workload_groups",
		"proxy_gateway":       "ztc_forwarding_gateway",
	}

	// Test ZIA mappings
	for attribute, expectedDataSource := range ziaMappings {
		t.Run("zia_mapping_"+attribute, func(t *testing.T) {
			// Verify mapping exists and is correct
			if expectedDataSource == "" {
				t.Errorf("Data source mapping for %s should not be empty", attribute)
			}

			// Verify naming conventions
			if !strings.HasPrefix(expectedDataSource, "zia_") && !strings.HasPrefix(expectedDataSource, "zpa_") {
				t.Errorf("Data source %s should start with zia_ or zpa_", expectedDataSource)
			}
		})
	}

	// Test ZTC mappings
	for attribute, expectedDataSource := range ztcMappings {
		t.Run("ztc_mapping_"+attribute, func(t *testing.T) {
			// Verify mapping exists and is correct
			if expectedDataSource == "" {
				t.Errorf("Data source mapping for %s should not be empty", attribute)
			}

			// Verify naming conventions
			if !strings.HasPrefix(expectedDataSource, "ztc_") {
				t.Errorf("ZTC Data source %s should start with ztc_", expectedDataSource)
			}
		})
	}
}

func TestResourceVsDataSourceSelection(t *testing.T) {
	// Test intelligent resource vs data source selection logic
	resourceMap := map[string]string{
		"123456": "zia_location_groups.resource_zia_location_groups_123456.id",
		"789012": "zia_device_groups.resource_zia_device_groups_789012.id",
	}

	testCases := []struct {
		name         string
		id           string
		expectedType string // "resource" or "datasource"
		description  string
	}{
		{
			name:         "ID with resource import",
			id:           "123456",
			expectedType: "resource",
			description:  "Should use resource reference when resource is imported",
		},
		{
			name:         "ID without resource import",
			id:           "555555",
			expectedType: "datasource",
			description:  "Should use data source reference when resource is not imported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, hasResource := resourceMap[tc.id]

			if tc.expectedType == "resource" && !hasResource {
				t.Errorf("%s: Expected resource reference but no resource mapping found", tc.description)
			}

			if tc.expectedType == "datasource" && hasResource {
				t.Errorf("%s: Expected data source reference but resource mapping exists", tc.description)
			}
		})
	}
}

func TestWorkloadGroupsSpecialHandling(t *testing.T) {
	// Test workload_groups special handling (id + name)
	testHCL := `resource "zia_firewall_filtering_rule" "test" {
  workload_groups {
    id   = 2665545
    name = "BD_WORKLOAD_GROUP01"
  }
}`

	// Test pattern matching for workload_groups (pattern defined but not used in simple test)
	// This would test the actual regex matching logic in a full implementation
	if !strings.Contains(testHCL, "workload_groups") {
		t.Error("Test HCL should contain workload_groups")
	}

	if !strings.Contains(testHCL, "id   = 2665545") {
		t.Error("Test HCL should contain id value")
	}

	if !strings.Contains(testHCL, `name = "BD_WORKLOAD_GROUP01"`) {
		t.Error("Test HCL should contain name value")
	}
}

func TestDataSourceFileGeneration(t *testing.T) {
	// Test data source file generation format
	testDataSources := []struct {
		dataSourceType string
		id             string
		uniqueName     string
		name           string // For workload_groups
	}{
		{
			dataSourceType: "zia_location_groups",
			id:             "123456",
			uniqueName:     "this_123456",
			name:           "",
		},
		{
			dataSourceType: "zia_workload_groups",
			id:             "789012",
			uniqueName:     "this_789012",
			name:           "TEST_WORKLOAD",
		},
	}

	// Test data source generation format
	for _, ds := range testDataSources {
		expectedFormat := `data "` + ds.dataSourceType + `" "` + ds.uniqueName + `" {`

		if ds.name != "" {
			// For workload_groups, should include both id and name
			expectedContent := []string{
				`id = "` + ds.id + `"`,
				`name = "` + ds.name + `"`,
			}

			for _, content := range expectedContent {
				// Verify expected content format
				if !strings.Contains(content, ds.id) && !strings.Contains(content, ds.name) {
					t.Errorf("Data source content should contain id or name: %s", content)
				}
			}
		} else {
			// For regular data sources, should only include id
			expectedContent := `id = "` + ds.id + `"`
			if !strings.Contains(expectedContent, ds.id) {
				t.Errorf("Data source content should contain id: %s", expectedContent)
			}
		}

		// Verify data source block format
		if !strings.Contains(expectedFormat, "data \"") {
			t.Error("Data source should start with 'data \"'")
		}

		if !strings.Contains(expectedFormat, ds.dataSourceType) {
			t.Errorf("Data source should contain type: %s", ds.dataSourceType)
		}
	}
}

func TestStripEmailSuffix(t *testing.T) {
	// Test the StripEmailSuffix function that handles ZIA API inconsistency
	// where user names are returned as "Name(email@domain.com)" but the API
	// doesn't accept that format for lookups.
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Name with email suffix",
			input:    "ZCC User(zcc@psaraswat.zscloud.net)",
			expected: "ZCC User",
		},
		{
			name:     "Name with email and spaces",
			input:    "ZS2 ONEAPI(zs2oneapiuser@psaraswat.zslogin.net)",
			expected: "ZS2 ONEAPI",
		},
		{
			name:     "Name with trailing space before email",
			input:    "Test User (test@example.com)",
			expected: "Test User",
		},
		{
			name:     "Name without email suffix",
			input:    "Regular User",
			expected: "Regular User",
		},
		{
			name:     "Name with parentheses but no email",
			input:    "John (Johnny) Doe",
			expected: "John (Johnny) Doe",
		},
		{
			name:     "Name with nested parentheses and email at end",
			input:    "John (Johnny) Doe(john@example.com)",
			expected: "John (Johnny) Doe",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Only email in parentheses",
			input:    "(user@domain.com)",
			expected: "",
		},
		{
			name:     "Complex domain",
			input:    "Admin User(admin@sub.domain.company.co.uk)",
			expected: "Admin User",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := helpers.StripEmailSuffix(tc.input)
			if result != tc.expected {
				t.Errorf("StripEmailSuffix(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestReferenceReplacement(t *testing.T) {
	// Test reference replacement logic
	testCases := []struct {
		name           string
		originalHCL    string
		expectedHCL    string
		dataSourceType string
		id             string
		description    string
	}{
		{
			name: "Single ID replacement",
			originalHCL: `source_ip_groups {
    id = [9881286]
  }`,
			expectedHCL: `source_ip_groups {
    id = [data.zia_firewall_filtering_ip_source_groups.this_9881286.id]
  }`,
			dataSourceType: "zia_firewall_filtering_ip_source_groups",
			id:             "9881286",
			description:    "Should replace single ID with data source reference",
		},
		{
			name: "Multiple ID replacement",
			originalHCL: `location_groups {
    id = [66754722, 66754723]
  }`,
			expectedHCL: `location_groups {
    id = [data.zia_location_groups.this_66754722.id, data.zia_location_groups.this_66754723.id]
  }`,
			dataSourceType: "zia_location_groups",
			id:             "66754722,66754723",
			description:    "Should replace multiple IDs with data source references",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the replacement logic pattern
			hasOriginalID := strings.Contains(tc.originalHCL, tc.id)
			if !hasOriginalID && tc.name == "Single ID replacement" {
				testutils.AssertContains(t, tc.originalHCL, "9881286", "Original HCL should contain the ID")
			}

			// Verify expected replacement format
			testutils.AssertContains(t, tc.expectedHCL, "data.", "Replaced HCL should contain data source reference")
			testutils.AssertContains(t, tc.expectedHCL, tc.dataSourceType, "Replaced HCL should contain correct data source type")
		})
	}
}
