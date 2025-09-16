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

// ResourceReference defines a mapping between an attribute and a target resource type
type ResourceReference struct {
	AttributeName string
	ResourceType  string
}

// GetResourceReferences returns the mapping of attribute names to resource types
func GetResourceReferences() []ResourceReference {
	return []ResourceReference{
		// ZPA Resource Mappings
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

		// ZIA Resource Mappings
		{"departments", "zia_department"},
		{"groups", "zia_group"},
		{"locations", "zia_location_management"},
		{"users", "zia_user_management"},
		{"urlCategories", "zia_url_categories"},
		{"dlpEngines", "zia_dlp_engines"},
		{"dlpDictionaries", "zia_dlp_dictionaries"},
		{"dlpNotificationTemplates", "zia_dlp_notification_templates"},
		{"dlpWebRules", "zia_dlp_web_rules"},
		{"firewallFilteringRules", "zia_firewall_filtering_rule"},
		{"firewallFilteringDestinationGroups", "zia_firewall_filtering_destination_groups"},
		{"firewallFilteringIpSourceGroups", "zia_firewall_filtering_ip_source_groups"},
		{"firewallFilteringNetworkApplicationGroups", "zia_firewall_filtering_network_application_groups"},
		{"firewallFilteringNetworkServiceGroups", "zia_firewall_filtering_network_service_groups"},
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
}

// OutputResource represents a resource from outputs.tf
type OutputResource struct {
	ResourceType string
	ResourceName string
	ResourceID   string
}

// ParseOutputsFile parses the outputs.tf file and returns a map of resource ID to resource reference
func ParseOutputsFile(workingDir string) (map[string]string, error) {
	outputsFile := filepath.Join(workingDir, "outputs.tf")
	fmt.Printf("[DEBUG] ParseOutputsFile: Looking for outputs.tf at %s\n", outputsFile)
	if _, err := os.Stat(outputsFile); os.IsNotExist(err) {
		fmt.Printf("[DEBUG] outputs.tf not found at %s, returning empty map\n", outputsFile)
		return make(map[string]string), nil
	}

	file, err := os.Open(outputsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	resourceMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	fmt.Printf("[DEBUG] ParseOutputsFile: Successfully opened outputs.tf\n")

	// Regex to match output lines like: output "zpa_server_group_resource_zpa_server_group_72058304855144105_id"
	outputRegex := regexp.MustCompile(`output\s+"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fmt.Printf("[DEBUG] Processing line: %s\n", line)

		// Look for output declarations
		if matches := outputRegex.FindStringSubmatch(line); matches != nil {
			outputName := matches[1]
			fmt.Printf("[DEBUG] Found output: %s\n", outputName)

			// Parse the output name to extract resource type, name, and ID
			// Format: zpa_app_connector_group_resource_zpa_app_connector_group_72058304855047746_id
			// We need to extract: resourceType="zpa_app_connector_group", resourceName="resource_zpa_app_connector_group_72058304855047746", resourceID="72058304855047746"

			// Find the last occurrence of "_id" to identify the end
			if strings.HasSuffix(outputName, "_id") {
				nameWithoutId := strings.TrimSuffix(outputName, "_id")
				fmt.Printf("[DEBUG] nameWithoutId: %s\n", nameWithoutId)
				parts := strings.Split(nameWithoutId, "_")
				fmt.Printf("[DEBUG] parts: %v (length: %d)\n", parts, len(parts))

				if len(parts) >= 4 {
					// Find the resource type by looking for the pattern: zpa_*_group
					// The resource type is typically the first 3 parts: zpa_app_connector_group
					resourceType := ""
					resourceID := ""
					resourceName := ""

					// The structure is: zpa_server_group_resource_zpa_server_group_72058304855144105
					// For zpa_server_group: resourceType="zpa_server_group", resourceName="resource_zpa_server_group_72058304855144105"
					// For zpa_app_connector_group: resourceType="zpa_app_connector_group", resourceName="resource_zpa_app_connector_group_72058304855047746"

					// Find where "resource" appears - this marks the boundary between resource type and resource name
					resourceIndex := -1
					for i, part := range parts {
						if part == "resource" {
							resourceIndex = i
							break
						}
					}

					fmt.Printf("[DEBUG] resourceIndex: %d\n", resourceIndex)

					if resourceIndex > 0 && resourceIndex < len(parts)-1 {
						// Resource type is everything before "resource"
						resourceType = strings.Join(parts[0:resourceIndex], "_")
						// Resource name is everything from "resource" onwards
						resourceName = strings.Join(parts[resourceIndex:], "_")
						// Resource ID is the last part
						resourceID = parts[len(parts)-1]

						fmt.Printf("[DEBUG] Extracted: resourceType=%s, resourceName=%s, resourceID=%s\n", resourceType, resourceName, resourceID)
					}

					if resourceType != "" && resourceID != "" && resourceName != "" {
						// Store the mapping: resourceID -> resourceType.resourceName.id
						resourceMap[resourceID] = fmt.Sprintf("%s.%s.id", resourceType, resourceName)
						log.Printf("[DEBUG] Mapped resource ID %s -> %s.%s.id", resourceID, resourceType, resourceName)
					} else {
						log.Printf("[DEBUG] Failed to parse output %s: resourceType=%s, resourceID=%s, resourceName=%s", outputName, resourceType, resourceID, resourceName)
					}
				}
			}
		}
	}

	fmt.Printf("[DEBUG] ParseOutputsFile: Found %d resources in resourceMap:\n", len(resourceMap))
	for id, ref := range resourceMap {
		fmt.Printf("[DEBUG]   ID %s -> %s\n", id, ref)
	}
	return resourceMap, scanner.Err()
}

// ExtractResourceIDFromName extracts the resource ID from a Terraform resource name
func ExtractResourceIDFromName(resourceName string) string {
	// Resource names are typically in format: resource_type_resource_id
	// Extract the ID part after the last underscore
	parts := strings.Split(resourceName, "_")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// ReplaceReferencesInData replaces raw IDs with resource references in the data
func ReplaceReferencesInData(resourceType string, structData map[string]interface{}, resourceMap map[string]string) {
	references := GetResourceReferences()

	for _, ref := range references {
		if value, exists := structData[ref.AttributeName]; exists {
			replaceAttributeReferencesInData(value, ref.ResourceType, resourceMap)
		}
	}
}

// replaceAttributeReferencesInData handles the replacement of references in a specific attribute
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

// GenerateDatasourceFile generates a datasource.tf file for missing resources
func GenerateDatasourceFile(workingDir string, missingResources map[string]string) error {
	if len(missingResources) == 0 {
		return nil
	}

	datasourceFile := filepath.Join(workingDir, "datasource.tf")
	file, err := os.Create(datasourceFile)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("# Datasources for missing referenced resources\n\n")

	for resourceType, resourceID := range missingResources {
		file.WriteString(fmt.Sprintf(`data "%s" "this" {
  id = "%s"
}

`, resourceType, resourceID))
	}

	log.Printf("[DEBUG] Generated datasource.tf with %d missing resources", len(missingResources))
	return nil
}
