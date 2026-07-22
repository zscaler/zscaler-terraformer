package processing

import (
	"testing"

	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
)

func TestNormalizePolicyStyle(t *testing.T) {
	testCases := []struct {
		name         string
		resourceType string
		input        []interface{}
		expected     []interface{}
	}{
		{
			name:         "DUAL_POLICY_EVAL becomes true for application segment",
			resourceType: "zpa_application_segment",
			input:        []interface{}{map[string]interface{}{"policyStyle": "DUAL_POLICY_EVAL"}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": true}},
		},
		{
			name:         "NONE becomes false for application segment",
			resourceType: "zpa_application_segment",
			input:        []interface{}{map[string]interface{}{"policyStyle": "NONE"}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": false}},
		},
		{
			name:         "unknown string becomes false",
			resourceType: "zpa_application_segment",
			input:        []interface{}{map[string]interface{}{"policyStyle": "SOMETHING"}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": false}},
		},
		{
			name:         "inspection resource is also normalized",
			resourceType: "zpa_application_segment_inspection",
			input:        []interface{}{map[string]interface{}{"policyStyle": "DUAL_POLICY_EVAL"}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": true}},
		},
		{
			name:         "missing attribute is left untouched",
			resourceType: "zpa_application_segment",
			input:        []interface{}{map[string]interface{}{"name": "seg1"}},
			expected:     []interface{}{map[string]interface{}{"name": "seg1"}},
		},
		{
			name:         "already bool is left untouched",
			resourceType: "zpa_application_segment",
			input:        []interface{}{map[string]interface{}{"policyStyle": true}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": true}},
		},
		{
			name:         "unconfigured resource type is returned unchanged",
			resourceType: "zpa_application_segment_pra",
			input:        []interface{}{map[string]interface{}{"policyStyle": "NONE"}},
			expected:     []interface{}{map[string]interface{}{"policyStyle": "NONE"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := helpers.NormalizePolicyStyle(tc.resourceType, tc.input)
			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d items, got %d", len(tc.expected), len(result))
			}
			for i := range result {
				got := result[i].(map[string]interface{})
				want := tc.expected[i].(map[string]interface{})
				for k, wantVal := range want {
					if got[k] != wantVal {
						t.Errorf("key %q: expected %v (%T), got %v (%T)", k, wantVal, wantVal, got[k], got[k])
					}
				}
			}
		})
	}
}
