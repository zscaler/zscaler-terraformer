/*
Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

                            MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package helpers

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ResourceReference defines a mapping between an attribute and a target resource type.
type ResourceReference struct {
	AttributeName string
	ResourceType  string
}

// GetResourceReferences returns the mapping of attribute names to resource types.
// NOTE: This function returns ZIA mappings by default for backwards compatibility.
// For context-aware mappings, use GetResourceReferencesForProvider().
func GetResourceReferences() []ResourceReference {
	return GetResourceReferencesForProvider("")
}

// GetResourceReferencesForProvider returns the mapping of attribute names to resource types
// based on the provider context. This ensures that attributes with the same names (e.g., dest_ip_groups)
// are mapped to the correct provider-specific resources.
func GetResourceReferencesForProvider(providerPrefix string) []ResourceReference {
	// Common ZPA mappings (provider-agnostic)
	zpaMappings := []ResourceReference{
		{"appConnectorGroups", "zpa_app_connector_group"},
		{"zcomponentId", "zpa_app_connector_group"},
		{"serverGroups", "zpa_server_group"},
		{"appServerGroups", "zpa_application_server"},
		{"segmentGroupId", "zpa_segment_group"},
		{"applications", "zpa_application_segment"},
		{"appSegments", "zpa_application_segment"},
		{"serviceEdges", "zpa_service_edge_group"},
		{"trustedNetworks", "zpa_trusted_network"},
		{"connectorGroups", "zpa_app_connector_group"},
		{"praPortals", "zpa_pra_portal_controller"},
		{"praApplications", "zpa_application_segment"},
		{"praApplication", "zpa_application_segment"},
	}

	// ZTC-specific mappings for attributes that overlap with ZIA
	ztcMappings := []ResourceReference{
		// ZTC Location Mappings
		{"locations", "ztc_location_management"},

		// ZTC IP Group Mappings
		{"src_ip_groups", "ztc_ip_source_groups"},
		{"srcIpGroups", "ztc_ip_source_groups"},
		{"dest_ip_groups", "ztc_ip_destination_groups"},
		{"destIpGroups", "ztc_ip_destination_groups"},

		// ZTC Network Service Mappings
		{"nw_services", "ztc_network_services"},
		{"nwServices", "ztc_network_services"},
		{"services", "ztc_network_services"},
		{"nw_service_groups", "ztc_network_service_groups"},
		{"nwServiceGroups", "ztc_network_service_groups"},

		// ZTC Workload Mappings
		{"src_workload_groups", "ztc_workload_groups"},
		{"workload_groups", "ztc_workload_groups"},

		// ZTC User/Group Mappings
		{"departments", "ztc_department"},
		{"groups", "ztc_group"},
		{"users", "ztc_user_management"},
	}

	// ZIA-specific mappings (default for backwards compatibility)
	ziaMappings := []ResourceReference{
		// ZIA Resource Mappings
		{"departments", "zia_department"},
		{"groups", "zia_group"},
		{"locations", "zia_location_management"},
		{"users", "zia_user_management"},
		{"urlCategories", "zia_url_categories"},
		{"dlp_engines", "zia_dlp_engines"},
		{"dlpDictionaries", "zia_dlp_dictionaries"},
		{"dlpNotificationTemplates", "zia_dlp_notification_templates"},
		{"dlpWebRules", "zia_dlp_web_rules"},
		{"firewallFilteringRules", "zia_firewall_filtering_rule"},
		{"firewallFilteringDestinationGroups", "zia_firewall_filtering_destination_groups"},
		{"firewallFilteringIpSourceGroups", "zia_firewall_filtering_ip_source_groups"},
		{"firewallFilteringNetworkApplicationGroups", "zia_firewall_filtering_network_application_groups"},
		{"firewallFilteringNetworkServiceGroups", "zia_firewall_filtering_network_service_groups"},

		// ZIA Firewall Filtering Rule Attribute Mappings
		{"nw_application_groups", "zia_firewall_filtering_network_application_groups"},
		{"nw_service_groups", "zia_firewall_filtering_network_service_groups"},
		{"nw_services", "zia_firewall_filtering_network_service"},
		{"bandwidth_classes", "zia_bandwidth_classes"},
		{"src_ip_groups", "zia_firewall_filtering_ip_source_groups"},
		{"dest_ip_groups", "zia_firewall_filtering_destination_groups"},
		{"labels", "zia_rule_labels"},
		{"services", "zia_firewall_filtering_network_service"},
		{"firewallFilteringNetworkServices", "zia_firewall_filtering_network_service"},
		{"trafficForwardingGreTunnels", "zia_traffic_forwarding_gre_tunnel"},
		{"trafficForwardingStaticIps", "zia_traffic_forwarding_static_ip"},
		{"trafficForwardingVpnCredentials", "zia_traffic_forwarding_vpn_credentials"},
		{"urlFilteringRules", "zia_url_filtering_rules"},
		{"authSettingsUrls", "zia_auth_settings_urls"},
		{"adminUsers", "zia_admin_users"},
		{"securitySettings", "zia_security_settings"},
		{"ruleLabels", "zia_rule_labels"},
	}

	// Return provider-specific mappings based on context
	switch providerPrefix {
	case "ztc":
		// For ZTC resources: use ZTC mappings first, then ZPA (shared), skip ZIA duplicates
		return append(ztcMappings, zpaMappings...)
	case "zpa":
		// For ZPA resources: use ZPA mappings only
		return zpaMappings
	case "zia":
		// For ZIA resources: use ZIA mappings first, then ZPA (shared)
		return append(ziaMappings, zpaMappings...)
	default:
		// Default: ZIA mappings first, then ZPA, then ZTC (backwards compatibility)
		return append(append(ziaMappings, zpaMappings...), ztcMappings...)
	}
}

// OutputResource represents a resource from outputs.tf.
type OutputResource struct {
	ResourceType string
	ResourceName string
	ResourceID   string
}

// ParseOutputsFile parses the outputs.tf file and returns a map of resource ID to resource reference.
func ParseOutputsFile(workingDir string) (map[string]string, error) {
	outputsFile := filepath.Join(workingDir, "outputs.tf")
	if _, err := os.Stat(outputsFile); os.IsNotExist(err) {
		return make(map[string]string), nil
	}

	file, err := os.Open(outputsFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	resourceMap := make(map[string]string)
	scanner := bufio.NewScanner(file)

	// Regex to match output lines like: output "zpa_server_group_resource_zpa_server_group_72058304855144105_id"
	// OR the newer format: output "ztc_ip_destination_groups_ztc_ip_destination_groups_17595967_id"
	outputRegex := regexp.MustCompile(`output\s+"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for output declarations
		if matches := outputRegex.FindStringSubmatch(line); matches != nil {
			outputName := matches[1]

			// Parse the output name to extract resource type, name, and ID
			// Format 1: zpa_app_connector_group_resource_zpa_app_connector_group_72058304855047746_id (with "resource")
			// Format 2: ztc_ip_destination_groups_ztc_ip_destination_groups_17595967_id (resource type repeated)

			// Find the last occurrence of "_id" to identify the end
			if strings.HasSuffix(outputName, "_id") {
				nameWithoutId := strings.TrimSuffix(outputName, "_id")
				parts := strings.Split(nameWithoutId, "_")

				if len(parts) >= 4 {
					resourceType := ""
					resourceID := ""
					resourceName := ""

					// Try Format 1: Find where "resource" appears
					resourceIndex := -1
					for i, part := range parts {
						if part == "resource" {
							resourceIndex = i
							break
						}
					}

					if resourceIndex > 0 && resourceIndex < len(parts)-1 {
						// Format 1: Resource type is everything before "resource"
						resourceType = strings.Join(parts[0:resourceIndex], "_")
						// Resource name is everything from "resource" onwards
						resourceName = strings.Join(parts[resourceIndex:], "_")
						// Resource ID is the last part
						resourceID = parts[len(parts)-1]
					} else {
						// Format 2: Resource type is repeated (e.g., ztc_ip_destination_groups_ztc_ip_destination_groups_17595967)
						// We need to find where the resource type is repeated
						resourceType, resourceName, resourceID = parseRepeatedResourceTypeFormat(nameWithoutId)
					}

					if resourceType != "" && resourceID != "" && resourceName != "" {
						// Store the mapping: resourceID -> resourceType.resourceName.id
						resourceMap[resourceID] = fmt.Sprintf("%s.%s.id", resourceType, resourceName)
						log.Printf("[DEBUG] ParseOutputsFile: Mapped ID %s -> %s.%s.id", resourceID, resourceType, resourceName)
					}
				}
			}
		}
	}

	return resourceMap, scanner.Err()
}

// parseRepeatedResourceTypeFormat handles output names where the resource type is repeated
// e.g., "ztc_ip_destination_groups_ztc_ip_destination_groups_17595967"
// Returns: resourceType, resourceName, resourceID
func parseRepeatedResourceTypeFormat(nameWithoutId string) (string, string, string) {
	// Common prefixes to try
	prefixes := []string{"ztc_", "zia_", "zpa_"}

	for _, prefix := range prefixes {
		if strings.HasPrefix(nameWithoutId, prefix) {
			// Find where the prefix appears again (marks start of resource name)
			firstOccurrence := strings.Index(nameWithoutId, prefix)
			remaining := nameWithoutId[firstOccurrence+len(prefix):]
			secondOccurrence := strings.Index(remaining, prefix)

			if secondOccurrence > 0 {
				// Resource type is from start to second occurrence
				resourceType := nameWithoutId[:firstOccurrence+len(prefix)+secondOccurrence-1]
				// Resource name is from second occurrence to end
				resourceName := remaining[secondOccurrence:]
				// Resource ID is the last part (after the last underscore)
				lastUnderscore := strings.LastIndex(resourceName, "_")
				if lastUnderscore > 0 {
					resourceID := resourceName[lastUnderscore+1:]
					return resourceType, resourceName, resourceID
				}
			}
		}
	}

	return "", "", ""
}

// ExtractResourceIDFromName extracts the resource ID from a Terraform resource name.
func ExtractResourceIDFromName(resourceName string) string {
	// Resource names are typically in format: resource_type_resource_id
	// Extract the ID part after the last underscore
	parts := strings.Split(resourceName, "_")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// ReplaceReferencesInData replaces raw IDs with resource references in the data.
func ReplaceReferencesInData(resourceType string, structData map[string]interface{}, resourceMap map[string]string) {
	references := GetResourceReferences()

	for _, ref := range references {
		if value, exists := structData[ref.AttributeName]; exists {
			replaceAttributeReferencesInData(value, ref.ResourceType, resourceMap)
		}
	}
}

// replaceAttributeReferencesInData handles the replacement of references in a specific attribute.
func replaceAttributeReferencesInData(value interface{}, targetResourceType string, resourceMap map[string]string) {
	switch v := value.(type) {
	case []interface{}:
		// Handle arrays of references
		for i, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if id, exists := itemMap["id"]; exists {
					if resourceRef, found := resourceMap[fmt.Sprintf("%v", id)]; found {
						// Replace the ID with a resource reference
						itemMap["id"] = resourceRef
						log.Printf("[DEBUG] Replaced ID %v with reference %s", id, resourceRef)
					} else {
						// Create a datasource reference for missing resources
						datasourceRef := fmt.Sprintf("data.%s.this.id", targetResourceType)
						itemMap["id"] = datasourceRef
						log.Printf("[DEBUG] Created datasource reference %s for missing ID %v", datasourceRef, id)
					}
				}
			} else if idStr, ok := item.(string); ok {
				// Handle direct string IDs
				if resourceRef, found := resourceMap[idStr]; found {
					v[i] = resourceRef
					log.Printf("[DEBUG] Replaced string ID %s with reference %s", idStr, resourceRef)
				} else {
					// Create a datasource reference for missing resources
					datasourceRef := fmt.Sprintf("data.%s.this.id", targetResourceType)
					v[i] = datasourceRef
					log.Printf("[DEBUG] Created datasource reference %s for missing string ID %s", datasourceRef, idStr)
				}
			}
		}
	case map[string]interface{}:
		// Handle single reference objects
		if id, exists := v["id"]; exists {
			if resourceRef, found := resourceMap[fmt.Sprintf("%v", id)]; found {
				v["id"] = resourceRef
				log.Printf("[DEBUG] Replaced object ID %v with reference %s", id, resourceRef)
			} else {
				// Create a datasource reference for missing resources
				datasourceRef := fmt.Sprintf("data.%s.this.id", targetResourceType)
				v["id"] = datasourceRef
				log.Printf("[DEBUG] Created datasource reference %s for missing object ID %v", datasourceRef, id)
			}
		}
	case string:
		// Handle direct string IDs (less common but possible)
		if resourceRef, found := resourceMap[v]; found {
			log.Printf("[DEBUG] Found string reference to replace: %s -> %s", v, resourceRef)
		} else {
			// Create a datasource reference for missing resources
			datasourceRef := fmt.Sprintf("data.%s.this.id", targetResourceType)
			log.Printf("[DEBUG] Would create datasource reference %s for missing string ID %s", datasourceRef, v)
		}
	}
}

// GenerateDatasourceFile generates a datasource.tf file for missing resources.
func GenerateDatasourceFile(workingDir string, missingResources map[string]string) error {
	if len(missingResources) == 0 {
		return nil
	}

	datasourceFile := filepath.Join(workingDir, "datasource.tf")
	file, err := os.Create(datasourceFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	_, _ = file.WriteString("# Datasources for missing referenced resources\n\n")

	for resourceType, resourceID := range missingResources {
		_, _ = fmt.Fprintf(file, `data "%s" "this" {
  id = "%s"
}

`, resourceType, resourceID)
	}

	log.Printf("[DEBUG] Generated datasource.tf with %d missing resources", len(missingResources))
	return nil
}
