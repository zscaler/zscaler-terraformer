package processing

import (
	"testing"

	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
)

func TestShouldSkipNonPositiveOrderRules(t *testing.T) {
	testCases := []struct {
		name         string
		resourceType string
		expected     bool
	}{
		{name: "zia_firewall_dns_rule is configured to skip", resourceType: "zia_firewall_dns_rule", expected: true},
		{name: "zia_firewall_ips_rule is not configured", resourceType: "zia_firewall_ips_rule", expected: false},
		{name: "zia_url_filtering_rules is not configured", resourceType: "zia_url_filtering_rules", expected: false},
		{name: "unknown resource is not configured", resourceType: "zia_something_else", expected: false},
		{name: "empty resource is not configured", resourceType: "", expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := helpers.ShouldSkipNonPositiveOrderRules(tc.resourceType); got != tc.expected {
				t.Errorf("ShouldSkipNonPositiveOrderRules(%q) = %v, want %v", tc.resourceType, got, tc.expected)
			}
		})
	}
}

func TestFilterNonPositiveOrderRules(t *testing.T) {
	testCases := []struct {
		name          string
		resourceType  string
		input         []interface{}
		expectedNames []string
		description   string
	}{
		{
			name:         "skips negative order rules for configured resource",
			resourceType: "zia_firewall_dns_rule",
			input: []interface{}{
				map[string]interface{}{"name": "User Rule 1", "order": float64(1)},
				map[string]interface{}{"name": "Predefined Rule", "order": float64(-1)},
				map[string]interface{}{"name": "User Rule 2", "order": float64(2)},
			},
			expectedNames: []string{"User Rule 1", "User Rule 2"},
			description:   "Negative order rules must be removed",
		},
		{
			name:         "skips zero order rules for configured resource",
			resourceType: "zia_firewall_dns_rule",
			input: []interface{}{
				map[string]interface{}{"name": "Zero Order Rule", "order": float64(0)},
				map[string]interface{}{"name": "Valid Rule", "order": float64(5)},
			},
			expectedNames: []string{"Valid Rule"},
			description:   "Zero order rules must be removed when present",
		},
		{
			name:         "retains all rules for non-configured resource",
			resourceType: "zia_firewall_ips_rule",
			input: []interface{}{
				map[string]interface{}{"name": "Rule A", "order": float64(-1)},
				map[string]interface{}{"name": "Rule B", "order": float64(1)},
			},
			expectedNames: []string{"Rule A", "Rule B"},
			description:   "Non-configured resources are not filtered",
		},
		{
			name:         "retains rules without an order field",
			resourceType: "zia_firewall_dns_rule",
			input: []interface{}{
				map[string]interface{}{"name": "No Order Rule"},
				map[string]interface{}{"name": "Valid Rule", "order": float64(3)},
			},
			expectedNames: []string{"No Order Rule", "Valid Rule"},
			description:   "Entries without an order field must be retained",
		},
		{
			name:         "handles integer order values",
			resourceType: "zia_firewall_dns_rule",
			input: []interface{}{
				map[string]interface{}{"name": "Int Negative", "order": -2},
				map[string]interface{}{"name": "Int Positive", "order": 4},
			},
			expectedNames: []string{"Int Positive"},
			description:   "Integer-typed order values must be handled",
		},
		{
			name:          "handles empty input",
			resourceType:  "zia_firewall_dns_rule",
			input:         []interface{}{},
			expectedNames: []string{},
			description:   "Empty input returns empty output",
		},
		{
			name:         "removes all rules when all are non-positive",
			resourceType: "zia_firewall_dns_rule",
			input: []interface{}{
				map[string]interface{}{"name": "Predefined 1", "order": float64(-1)},
				map[string]interface{}{"name": "Predefined 2", "order": float64(-2)},
			},
			expectedNames: []string{},
			description:   "All predefined rules must be removed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := helpers.FilterNonPositiveOrderRules(tc.resourceType, tc.input)

			if len(result) != len(tc.expectedNames) {
				t.Fatalf("%s: expected %d rules, got %d", tc.description, len(tc.expectedNames), len(result))
			}

			for i, item := range result {
				m, ok := item.(map[string]interface{})
				if !ok {
					t.Fatalf("%s: result item %d is not a map", tc.description, i)
				}
				name, _ := m["name"].(string)
				if name != tc.expectedNames[i] {
					t.Errorf("%s: result[%d] name = %q, want %q", tc.description, i, name, tc.expectedNames[i])
				}
			}
		})
	}
}
