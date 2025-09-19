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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils"
)

func IsInList(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

// TypeSetBlock generates HCL for TypeSet attributes like notification_template, auditor, icap_server.
func TypeSetBlock(blockName string, blockData interface{}) string {
	output := ""

	switch blockData := blockData.(type) {
	case map[string]interface{}:
		// Check if the ID exists and is valid
		if id, ok := blockData["id"].(float64); ok && id != 0 {
			output += fmt.Sprintf("%s {\n  id = %d\n}\n", blockName, int64(id))
		}
	case []interface{}:
		// Process each item in the array
		for _, item := range blockData {
			if itemMap, ok := item.(map[string]interface{}); ok {
				nestedBlock := TypeSetBlock(blockName, itemMap)
				if nestedBlock != "" {
					output += nestedBlock
				}
			}
		}
	}

	return output
}

func Strip(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if ('a' <= b && b <= 'z') ||
			('A' <= b && b <= 'Z') ||
			('0' <= b && b <= '9') ||
			b == ' ' ||
			b == '_' {
			result.WriteByte(b)
		}
	}
	return result.String()
}

func GenerateOutputs(resourceType string, resourceID string, workingDir string) {
	// Define the output file path.
	outputsFile := fmt.Sprintf("%s/outputs.tf", strings.TrimSuffix(workingDir, "/"))

	// Exclude specified resources from generating outputs.
	excludedResources := []string{
		"zia_auth_settings_urls",
		"zia_sandbox_behavioral_analysis",
		"zia_security_settings",
		"zia_advanced_settings",
		"zia_atp_malicious_urls",
		"zia_atp_security_exceptions",
		"zia_advanced_threat_settings",
		"zia_atp_malware_inspection",
		"zia_atp_malware_protocols",
		"zia_atp_malware_settings",
		"zia_atp_malware_policy",
		"zia_url_filtering_and_cloud_app_settings",
		"zia_end_user_notification",
	}

	// Check if the resourceType is in the excluded list.
	for _, excludedResource := range excludedResources {
		if resourceType == excludedResource {
			return
		}
	}

	// Read the existing outputs.tf file content if it exists.
	existingOutputs := ""
	if _, err := os.Stat(outputsFile); err == nil {
		content, err := os.ReadFile(outputsFile)
		if err != nil {
			log.Fatalf("failed to read outputs file: %s", err)
		}
		existingOutputs = string(content)
	}

	// Create the output block string.
	outputBlock := fmt.Sprintf(`output "%s_%s_id" {
  value = "${%s.%s.id}"
}

`, resourceType, resourceID, resourceType, resourceID)

	// Check if the output block already exists.
	if strings.Contains(existingOutputs, fmt.Sprintf(`output "%s_%s_id"`, resourceType, resourceID)) {
		return
	}

	// Open the file in append mode or create it if it doesn't exist.
	f, err := os.OpenFile(outputsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("failed to open outputs file: %s", err)
	}
	defer f.Close()

	// Write the output block to the file.
	if _, err := f.WriteString(outputBlock); err != nil {
		log.Fatalf("failed to write to outputs file: %s", err)
	}
}

// / Custom function to Removes attributes from ZPA StateFile.
func RemoveTcpPortRangesFromState(stateFile string) {
	// Read the state file
	stateData, err := ioutil.ReadFile(stateFile)
	if err != nil {
		log.Fatalf("failed to read state file: %s", err)
	}

	// Unmarshal the JSON data
	var state map[string]interface{}
	if err := json.Unmarshal(stateData, &state); err != nil {
		log.Fatalf("failed to unmarshal state file: %s", err)
	}

	// Traverse the state file structure to remove tcp_port_ranges.
	resources, ok := state["resources"].([]interface{})
	if !ok {
		log.Fatalf("unexpected structure in state file: resources not found or not a list")
	}

	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			log.Fatalf("unexpected structure in state file: resource is not a map")
		}

		instances, ok := resourceMap["instances"].([]interface{})
		if !ok {
			continue
		}

		for _, instance := range instances {
			instanceMap, ok := instance.(map[string]interface{})
			if !ok {
				continue
			}

			attributes, ok := instanceMap["attributes"].(map[string]interface{})
			if !ok {
				continue
			}

			// Remove the tcp_port_ranges and udp_port_ranges attribute.
			delete(attributes, "tcp_port_ranges")
			delete(attributes, "udp_port_ranges")
		}
	}

	// Marshal the modified state back to JSON.
	modifiedStateData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal modified state file: %s", err)
	}

	// Write the modified state back to the file
	if err := ioutil.WriteFile(stateFile, modifiedStateData, 0600); err != nil {
		log.Fatalf("failed to write modified state file: %s", err)
	}
}

// / Remove computed from ZPA Application Segments.
func IsComputedAttribute(attr string) bool {
	computedAttributes := []string{"portal", "app_id", "hidden", "id", "certificate_name"}
	for _, computed := range computedAttributes {
		if attr == computed {
			return true
		}
	}
	return false
}

func ListIdsIntBlockIDExtentionsSingle(fieldName string, obj interface{}) string {
	output := ""
	if obj == nil {
		return output
	}
	if m, ok := obj.(map[string]interface{}); ok {
		output = fieldName + " {\n"
		output += "id=["
		if idInterface, ok := m["id"]; ok {
			id, ok := idInterface.(float64)
			if ok && id > 0 {
				output += fmt.Sprintf("%d", int64(id))
			}
		}
		output += "]\n"
		output += "}\n"
	}
	return output
}

// WorkloadGroupsBlock handles workload_groups blocks for zia_dlp_web_rules with both id and name fields.
func WorkloadGroupsBlock(fieldName string, obj interface{}) string {
	output := ""
	if obj != nil && len(obj.([]interface{})) > 0 {
		for _, v := range obj.([]interface{}) {
			m, ok := v.(map[string]interface{})
			if !ok || m == nil {
				continue
			}

			output += fieldName + " {\n"

			// Add id if present
			if id, ok := m["id"]; ok && id != nil && id != 0 {
				switch idVal := id.(type) {
				case float64:
					output += fmt.Sprintf("  id = %d\n", int64(idVal))
				case int:
					output += fmt.Sprintf("  id = %d\n", idVal)
				case string:
					output += fmt.Sprintf("  id = %q\n", idVal)
				}
			}

			// Add name if present
			if name, ok := m["name"]; ok && name != nil && name != "" {
				output += fmt.Sprintf("  name = %q\n", name)
			}

			output += "}\n"
		}
	}
	return output
}

func ListIdsIntBlock(fieldName string, obj interface{}) string {
	// Check if the list is empty or nil, and if so, don't generate the block
	if obj == nil {
		return ""
	}

	objList, ok := obj.([]interface{})
	if !ok || len(objList) == 0 {
		return ""
	}

	// Check if all items in the list are valid (have non-zero id)
	validItems := []string{}
	for _, v := range objList {
		m, ok := v.(map[string]interface{})
		if !ok || m == nil || m["id"] == 0 {
			continue
		}
		id, ok := m["id"].(float64)
		if !ok || id == 0 {
			continue
		}
		validItems = append(validItems, fmt.Sprintf("%d", int64(id)))
	}

	// If no valid items, don't generate the block
	if len(validItems) == 0 {
		return ""
	}

	// Generate the block with valid items
	output := fieldName + " {\n"
	output += "id=["
	output += strings.Join(validItems, ",")
	output += "]\n"
	output += "}\n"
	return output
}

func ListIdsStringBlock(fieldName string, obj interface{}) string {
	// Check if the list is empty or nil, and if so, don't generate the block
	if obj == nil {
		return ""
	}

	objList, ok := obj.([]interface{})
	if !ok || len(objList) == 0 {
		return ""
	}

	// Check if all items in the list are valid (have non-empty id)
	validItems := []string{}
	for _, v := range objList {
		m, ok := v.(map[string]interface{})
		if !ok || m == nil || m["id"] == "" {
			continue
		}
		id, ok := m["id"].(string)
		if !ok || id == "" {
			continue
		}
		// Check if this is a Terraform reference (contains dots and doesn't start with quotes)
		if strings.Contains(id, ".") && !strings.HasPrefix(id, "\"") {
			// This is a Terraform reference, don't add quotes
			validItems = append(validItems, id)
		} else {
			// This is a regular ID, add quotes
			validItems = append(validItems, "\""+id+"\"")
		}
	}

	// If no valid items, don't generate the block
	if len(validItems) == 0 {
		return ""
	}

	// Generate the block with valid items
	output := fieldName + " {\n"
	output += "id=["
	output += strings.Join(validItems, ",")
	output += "]\n"
	output += "}\n"
	return output
}

// ListExternalIdBlock handles blocks that contain external_id and name fields (like zpa_app_segments and zpa_server_group).
func ListExternalIdBlock(fieldName string, obj interface{}) string {
	output := ""
	if obj == nil {
		return output
	}

	// Handle both single object and array cases
	switch objType := obj.(type) {
	case []interface{}:
		// Handle array case (like zpa_app_segments)
		if len(objType) > 0 {
			for _, v := range objType {
				m, ok := v.(map[string]interface{})
				if !ok || m == nil {
					continue
				}
				output += generateExternalIdBlock(fieldName, m)
			}
		}
	case map[string]interface{}:
		// Handle single object case (like zpa_server_group)
		output += generateExternalIdBlock(fieldName, objType)
	}

	return output
}

// Helper function to generate a single external_id block.
func generateExternalIdBlock(fieldName string, m map[string]interface{}) string {
	output := fieldName + " {\n"

	// Add external_id if present
	if externalID, ok := m["externalId"]; ok && externalID != nil && externalID != "" {
		switch externalIDVal := externalID.(type) {
		case float64:
			output += fmt.Sprintf("  external_id = %d\n", int64(externalIDVal))
		case int:
			output += fmt.Sprintf("  external_id = %d\n", externalIDVal)
		case string:
			output += fmt.Sprintf("  external_id = %q\n", externalIDVal)
		}
	}

	// Add name if present
	if name, ok := m["name"]; ok && name != nil && name != "" {
		output += fmt.Sprintf("  name = %q\n", name)
	}

	output += "}\n"
	return output
}

// / Custom function to manipulate generate and import of ZPA application segments.
func ListNestedBlock(fieldName string, obj interface{}) string {
	output := fieldName + " {\n"
	if obj != nil {
		for _, v := range obj.([]interface{}) {
			m, ok := v.(map[string]interface{})
			if !ok || m == nil {
				continue
			}
			output += "apps_config {\n"
			for key, value := range m {
				snakeKey := strcase.ToSnake(key)
				if IsComputedAttribute(snakeKey) {
					continue
				}
				switch value := value.(type) {
				case string:
					output += fmt.Sprintf("%s = \"%s\"\n", snakeKey, value)
				case bool:
					output += fmt.Sprintf("%s = %t\n", snakeKey, value)
				case []interface{}:
					output += fmt.Sprintf("%s = [", snakeKey)
					for i, val := range value {
						if i > 0 {
							output += ","
						}
						output += fmt.Sprintf("\"%v\"", val)
					}
					output += "]\n"
				}

				// Inject app_types based on application_protocol.
				if key == "applicationProtocol" {
					appTypes := []string{}
					switch value {
					case "RDP", "SSH", "VNC":
						appTypes = []string{"SECURE_REMOTE_ACCESS"}
					case "HTTPS", "HTTP":
						appTypes = []string{"INSPECT"}
					}
					output += "app_types = ["
					for i, appType := range appTypes {
						if i > 0 {
							output += ","
						}
						output += fmt.Sprintf("\"%s\"", appType)
					}
					output += "]\n"
				}
			}
			output += "}\n"
		}
	}
	output += "}\n"
	return output
}

// This function handles TypeSet attributes.
func TypeSetNestedBlock(attrName string, value interface{}) string {
	if attrMap, ok := value.(map[string]interface{}); ok {
		if id, ok := attrMap["id"].(string); ok {
			return fmt.Sprintf("%s {\n  id = %q\n}\n", attrName, id)
		}
	}
	return ""
}

// Dedicated function to convert Browser Isolation Profile Attributes.
func ConvertAttributes(structData map[string]interface{}) {
	if banner, ok := structData["banner"].(map[string]interface{}); ok {
		if id, idOk := banner["id"].(string); idOk {
			structData["banner_id"] = id
		} else {
			log.Printf("[ERROR] banner_id is not of type string")
		}
		delete(structData, "banner")
	}
	if certificates, ok := structData["certificates"].([]interface{}); ok {
		var certIDs []string
		for _, cert := range certificates {
			if certMap, ok := cert.(map[string]interface{}); ok {
				if id, idOk := certMap["id"].(string); idOk {
					certIDs = append(certIDs, id)
				} else {
					log.Printf("[ERROR] certificate id is not of type string")
				}
			}
		}
		structData["certificate_ids"] = certIDs
		delete(structData, "certificates")
	}
	if regions, ok := structData["regions"].([]interface{}); ok {
		var regionIDs []string
		for _, region := range regions {
			if regionMap, ok := region.(map[string]interface{}); ok {
				if id, idOk := regionMap["id"].(string); idOk {
					regionIDs = append(regionIDs, id)
				} else {
					log.Printf("[ERROR] region id is not of type string")
				}
			}
		}
		structData["region_ids"] = regionIDs
		delete(structData, "regions")
	}
}

type ZIAAPIErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	Status  int    `json:"status,omitempty"`
}

// HandleZIAError processes ZIA API error responses and determines if the resource should be skipped.
// Returns (shouldSkip, message) where shouldSkip indicates if the import should continue gracefully.
func HandleZIAError(responseBody []byte) (bool, string) {
	var ziaErr ZIAAPIErrorResponse
	if jsonErr := json.Unmarshal(responseBody, &ziaErr); jsonErr == nil {
		switch ziaErr.Code {
		case "INVALID_INPUT_ARGUMENT":
			if strings.Contains(ziaErr.Message, "Custom File Hash feature is not enabled for your org") {
				return true, "Custom File Hash feature is disabled, skipping import"
			}
		case "NOT_SUBSCRIBED":
			// Handle subscription-related errors that should be skipped gracefully
			return true, fmt.Sprintf("Subscription required but not active: %s", ziaErr.Message)
		default:
			return false, fmt.Sprintf("Unhandled ZIA error: %s - %s", ziaErr.Code, ziaErr.Message)
		}
	}
	return false, ""
}

// HandleZIAAPIError processes ZIA API errors and determines if the resource should be skipped.
// Returns (shouldSkip, message) where shouldSkip indicates if the import should continue gracefully.
func HandleZIAAPIError(err error, resourceType string) (bool, string) {
	if err == nil {
		return false, ""
	}

	errorString := err.Error()

	// Try to extract and parse JSON from the error string
	jsonStart := strings.Index(errorString, "{")
	jsonEnd := strings.LastIndex(errorString, "}")

	if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
		jsonStr := errorString[jsonStart : jsonEnd+1]
		var ziaErr ZIAAPIErrorResponse
		if jsonErr := json.Unmarshal([]byte(jsonStr), &ziaErr); jsonErr == nil {
			switch ziaErr.Code {
			case "INVALID_INPUT_ARGUMENT":
				if strings.Contains(ziaErr.Message, "Custom File Hash feature is not enabled for your org") {
					return true, "Custom File Hash feature is disabled, skipping import"
				}
			case "NOT_SUBSCRIBED":
				// Handle subscription-related errors that should be skipped gracefully
				return true, fmt.Sprintf("Subscription required but not active: %s", ziaErr.Message)
			default:
				return false, fmt.Sprintf("Unhandled ZIA error: %s - %s", ziaErr.Code, ziaErr.Message)
			}
		}
	}

	// If no subscription-related error detected, return false to indicate this is a real error
	return false, fmt.Sprintf("Unhandled error for %s: %s", resourceType, errorString)
}

func FormatHeredoc(value string) string {
	// Match the provider's normalizeMultiLineString logic
	if value == "" {
		return ""
	}

	// Trim leading/trailing whitespace for consistency
	value = strings.TrimSpace(value)

	// Ensure uniform indentation by trimming each line
	lines := strings.Split(value, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	// Join lines back together
	formatted := strings.Join(lines, "\n")

	// Escape Terraform variable interpolation (`$` → `$$`)
	formatted = strings.ReplaceAll(formatted, "$", "$$")

	// Ensure the final newline for heredoc formatting
	return formatted + "\n"
}

func GenerateUserAgent() string {
	return fmt.Sprintf("(%s %s) Zscaler Terraformer/%s",
		runtime.GOOS,
		runtime.GOARCH,
		terraformutils.Version(),
	)
}

func SnakeCaseNoDigitBreak(in string) string {
	snake := strcase.ToSnake(in)

	// Collapse the underscore that strcase inserts before a digit.
	//   http_2_enabled -> http2_enabled
	re := regexp.MustCompile(`_([0-9]+)_`)
	for {
		newSnake := re.ReplaceAllString(snake, `${1}_`)
		if newSnake == snake {
			break
		}
		snake = newSnake
	}
	return snake
}

// Convenience wrapper used by the writers.
func TfAttrName(apiField string) string {
	return strings.ToLower(SnakeCaseNoDigitBreak(apiField))
}

// MapSpecialFieldNames handles special cases where API field names contain acronyms.
// that need to be preserved in uppercase (e.g., "IP" in "routableIP").
func MapSpecialFieldNames(resourceType, fieldName string) string {
	// Define special mappings for resources that have non-standard camelCase.
	specialMappings := map[string]map[string]string{
		"zia_traffic_forwarding_static_ip": {
			"routable_ip": "routableIP",
		},
		"zia_location_management": {
			"state": "state",
		},
		"zia_end_user_notification": {
			"display_company_name": "displayCompName",
			"display_company_logo": "displayCompLogo",
		},
	}

	if resourceMappings, exists := specialMappings[resourceType]; exists {
		if mappedName, exists := resourceMappings[fieldName]; exists {
			return mappedName
		}
	}

	// Return empty string if no special mapping exists
	return ""
}
