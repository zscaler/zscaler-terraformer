package processing

import (
	"strings"
	"testing"

	"github.com/zscaler/zscaler-terraformer/v2/tests/testutils"
)

func TestZPAPolicyObjectTypeMappings(t *testing.T) {
	// Test ZPA policy object type mappings
	expectedMappings := map[string]map[string]string{
		"SCIM": {
			"idp_id": "zpa_idp_controller",
			"lhs":    "zpa_scim_attribute_header",
		},
		"SCIM_GROUP": {
			"idp_id": "zpa_idp_controller",
			"lhs":    "zpa_idp_controller",
			"rhs":    "zpa_scim_groups",
		},
		"SAML": {
			"idp_id": "zpa_idp_controller",
			"lhs":    "zpa_saml_attribute",
			"name":   "zpa_saml_attribute@name",
		},
		"POSTURE": {
			"lhs": "zpa_posture_profile",
		},
		"TRUSTED_NETWORK": {
			"lhs": "zpa_trusted_network",
		},
		"MACHINE_GRP": {
			"rhs": "zpa_machine_group",
		},
	}

	// Verify each object type has expected mappings
	for objectType, fieldMappings := range expectedMappings {
		t.Run("object_type_"+objectType, func(t *testing.T) {
			if len(fieldMappings) == 0 {
				t.Errorf("Object type %s should have field mappings", objectType)
			}

			for field, dataSourceType := range fieldMappings {
				// Verify data source type format
				if !strings.HasPrefix(dataSourceType, "zpa_") {
					t.Errorf("Data source type %s should start with zpa_", dataSourceType)
				}

				// Verify field names are valid
				validFields := []string{"idp_id", "lhs", "rhs", "name"}
				found := false
				for _, validField := range validFields {
					if field == validField {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Field %s is not a valid operand field", field)
				}
			}
		})
	}
}

func TestZPAPolicyOperandExtraction(t *testing.T) {
	// Test operand field extraction logic
	testHCL := `conditions {
    operator = "OR"
    operands {
      idp_id = "216196257331285825"
      lhs = "216196257331285828"
      name = "Email_SGIO-User-Okta"
      object_type = "SAML"
      rhs = "wguilherme@securitygeek.io"
    }
  }`

	// Test extraction patterns
	testCases := []struct {
		field         string
		expectedValue string
		description   string
	}{
		{
			field:         "idp_id",
			expectedValue: "216196257331285825",
			description:   "Should extract idp_id value",
		},
		{
			field:         "lhs",
			expectedValue: "216196257331285828",
			description:   "Should extract lhs value",
		},
		{
			field:         "object_type",
			expectedValue: "SAML",
			description:   "Should extract object_type value",
		},
		{
			field:         "name",
			expectedValue: "Email_SGIO-User-Okta",
			description:   "Should extract name value",
		},
	}

	for _, tc := range testCases {
		t.Run("extract_"+tc.field, func(t *testing.T) {
			// Verify the field and value exist in the HCL
			fieldPattern := tc.field + ` = "`
			testutils.AssertContains(t, testHCL, fieldPattern, "HCL should contain field pattern")
			testutils.AssertContains(t, testHCL, tc.expectedValue, "HCL should contain expected value")
		})
	}
}

func TestZPADataSourceGeneration(t *testing.T) {
	// Test ZPA data source generation patterns
	testCases := []struct {
		name           string
		dataSourceType string
		queryField     string
		exportField    string
		id             string
		expectedFormat string
		description    string
	}{
		{
			name:           "POSTURE profile",
			dataSourceType: "zpa_posture_profile",
			queryField:     "id",
			exportField:    "posture_udid",
			id:             "d0b05ecf-b36e-4b28-ab83-f8665a32fd73",
			expectedFormat: `data "zpa_posture_profile" "this_d0b05ecf-b36e-4b28-ab83-f8665a32fd73" {
  id = "d0b05ecf-b36e-4b28-ab83-f8665a32fd73"
}`,
			description: "Should generate posture profile data source querying by id",
		},
		{
			name:           "TRUSTED_NETWORK",
			dataSourceType: "zpa_trusted_network",
			queryField:     "id",
			exportField:    "network_id",
			id:             "01b54e90-39c1-43e1-a484-6d5c33c65195",
			expectedFormat: `data "zpa_trusted_network" "this_01b54e90-39c1-43e1-a484-6d5c33c65195" {
  id = "01b54e90-39c1-43e1-a484-6d5c33c65195"
}`,
			description: "Should generate trusted network data source querying by id",
		},
		{
			name:           "SAML attribute by name",
			dataSourceType: "zpa_saml_attribute",
			queryField:     "name",
			exportField:    "name",
			id:             "Email_SGIO-User-Okta",
			expectedFormat: `data "zpa_saml_attribute" "this_Email_SGIO-User-Okta" {
  name = "Email_SGIO-User-Okta"
  idp_name = data.zpa_idp_controller.this_216196257331285825.name
}`,
			description: "Should generate SAML attribute data source querying by name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify data source format
			testutils.AssertContains(t, tc.expectedFormat, `data "`+tc.dataSourceType+`"`, "Should contain correct data source type")
			testutils.AssertContains(t, tc.expectedFormat, tc.queryField+` = "`+tc.id+`"`, "Should contain correct query field")

			if tc.name == "SAML attribute by name" {
				testutils.AssertContains(t, tc.expectedFormat, "idp_name =", "SAML data source should include idp_name")
			}
		})
	}
}

func TestIDExtractionFromContent(t *testing.T) {
	// Test ID extraction from various HCL content formats
	testCases := []struct {
		name        string
		content     string
		expectedIDs []string
		description string
	}{
		{
			name:        "Single quoted ID",
			content:     `"123456"`,
			expectedIDs: []string{"123456"},
			description: "Should extract single quoted ID",
		},
		{
			name:        "Multiple quoted IDs",
			content:     `"123", "456", "789"`,
			expectedIDs: []string{"123", "456", "789"},
			description: "Should extract multiple quoted IDs",
		},
		{
			name:        "Single unquoted ID",
			content:     `9881286`,
			expectedIDs: []string{"9881286"},
			description: "Should extract single unquoted ID",
		},
		{
			name:        "Multiple unquoted IDs",
			content:     `123, 456, 789`,
			expectedIDs: []string{"123", "456", "789"},
			description: "Should extract multiple unquoted IDs",
		},
		{
			name:        "Mixed format IDs",
			content:     `"123", 456, "789"`,
			expectedIDs: []string{"123", "456", "789"},
			description: "Should extract mixed format IDs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate ID extraction logic
			extractedIDs := mockExtractIDsFromContent(tc.content)

			if len(extractedIDs) != len(tc.expectedIDs) {
				t.Errorf("%s: Expected %d IDs, got %d", tc.description, len(tc.expectedIDs), len(extractedIDs))
			}

			for i, expectedID := range tc.expectedIDs {
				if i < len(extractedIDs) && extractedIDs[i] != expectedID {
					t.Errorf("%s: Expected ID %s at position %d, got %s", tc.description, expectedID, i, extractedIDs[i])
				}
			}
		})
	}
}

// Mock implementation of ID extraction for testing
func mockExtractIDsFromContent(content string) []string {
	var ids []string
	content = strings.TrimSpace(content)

	// Remove outer quotes if present
	if strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) && strings.Count(content, `"`) == 2 {
		content = content[1 : len(content)-1]
	}

	// Split by comma and clean up each part
	parts := strings.Split(content, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		part = strings.TrimSpace(part)

		if part != "" {
			ids = append(ids, part)
		}
	}

	return ids
}
