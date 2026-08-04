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
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/iancoleman/strcase"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils"
)

// idNameRegistry stores a mapping of resource IDs to their human-readable names.
// This is populated during HCL generation when processing nested attribute blocks
// (e.g., groups, departments) and consumed when generating datasource.tf.
var (
	idNameRegistryMu sync.RWMutex
	idNameRegistry   = make(map[string]string) // "id" -> "name" (type-agnostic fallback)
	// typedIDNames maps "dataSourceType|id" to a name. IDs are only unique within
	// a single object type — ZIA in particular reuses small integer IDs across
	// types (a file type category and a rule label can both be id 56) — so names
	// are scoped by data source type to avoid resolving an ID to another type's name.
	typedIDNames = make(map[string]string) // "type|id" -> "name"
	// typedNameIDs tracks which distinct IDs carry a given name within a data
	// source type. Names are not guaranteed unique (BA certificate names come
	// from the certificate CN, ZIA device and user names can repeat), so a data
	// source is only queried by name when exactly one ID of that type has it.
	typedNameIDs = make(map[string]map[string]bool) // "type|name" -> set of ids
)

// typedKey builds the composite registry key for a data source type and value.
func typedKey(dataSourceType, value string) string {
	return dataSourceType + "|" + value
}

// RegisterIDName stores an ID-to-name mapping for later use in data source generation.
// Prefer RegisterTypedIDName when the data source type is known: this type-agnostic
// registry is only consulted as a fallback and cannot detect cross-type ID reuse.
func RegisterIDName(id, name string) {
	if id == "" || name == "" {
		return
	}
	idNameRegistryMu.Lock()
	defer idNameRegistryMu.Unlock()
	idNameRegistry[id] = name
}

// RegisterTypedIDName stores an ID-to-name mapping scoped to a data source type
// and tracks how many distinct IDs of that type share the name
// (see IsNameUniqueForDataSource).
func RegisterTypedIDName(dataSourceType, id, name string) {
	if dataSourceType == "" || id == "" || name == "" {
		return
	}
	idNameRegistryMu.Lock()
	defer idNameRegistryMu.Unlock()
	typedIDNames[typedKey(dataSourceType, id)] = name
	nameKey := typedKey(dataSourceType, name)
	if typedNameIDs[nameKey] == nil {
		typedNameIDs[nameKey] = make(map[string]bool)
	}
	typedNameIDs[nameKey][id] = true
}

// IsNameAmbiguousForDataSource reports whether more than one registered ID of the
// given data source type carries the name, which makes a lookup by name unsafe.
// A name with no type-scoped registration is not considered ambiguous: nothing
// observed during import contradicts it.
func IsNameAmbiguousForDataSource(dataSourceType, name string) bool {
	idNameRegistryMu.RLock()
	defer idNameRegistryMu.RUnlock()
	return len(typedNameIDs[typedKey(dataSourceType, name)]) > 1
}

// LookupNameForDataSource returns the name registered for an ID within a data
// source type, falling back to the type-agnostic registry when the type-scoped
// registry has no entry (e.g. names captured by the ListIds*Block helpers).
func LookupNameForDataSource(dataSourceType, id string) (string, bool) {
	idNameRegistryMu.RLock()
	if name, ok := typedIDNames[typedKey(dataSourceType, id)]; ok {
		idNameRegistryMu.RUnlock()
		return name, true
	}
	idNameRegistryMu.RUnlock()
	return LookupNameByID(id)
}

// LookupNameByID returns the name for a given ID from the type-agnostic registry.
func LookupNameByID(id string) (string, bool) {
	idNameRegistryMu.RLock()
	defer idNameRegistryMu.RUnlock()
	name, ok := idNameRegistry[id]
	return name, ok
}

// ResetIDNameRegistry clears the ID-to-name registries (useful for testing).
func ResetIDNameRegistry() {
	idNameRegistryMu.Lock()
	defer idNameRegistryMu.Unlock()
	idNameRegistry = make(map[string]string)
	typedIDNames = make(map[string]string)
	typedNameIDs = make(map[string]map[string]bool)
}

// siblingIDNameFields maps an API ID field to the companion name field the API
// returns in the same payload, along with the data source type the pair resolves
// to (e.g. an application segment carries segmentGroupId and segmentGroupName
// side by side, both describing a zpa_segment_group).
var siblingIDNameFields = map[string]struct {
	nameField      string
	dataSourceType string
}{
	"segmentGroupId": {"segmentGroupName", "zpa_segment_group"},
	"certificateId":  {"certificateName", "zpa_ba_certificate"},
}

// RegisterNestedIDNames recursively walks an API response payload and registers
// the ID-to-name pairs that datasource.tf generation needs, scoped by data source
// type. Names are taken from the payload the tool already holds, so no additional
// API calls are made.
//
// Objects are typed by the attribute that contains them: the same attribute-to-data
// source mapping used when collecting IDs (e.g. "departments" -> zia_department_management,
// "serverGroups" -> zpa_server_group) is applied here, which guarantees that every
// collected ID can be resolved with the type it was collected under.
func RegisterNestedIDNames(resourceType string, data interface{}) {
	attributeToDataSource := make(map[string]string)
	for _, mapping := range GetDataSourceMappingsForProvider(providerPrefixFromResourceType(resourceType)) {
		attributeToDataSource[mapping.AttributeName] = mapping.DataSourceType
	}
	registerNestedIDNames(data, attributeToDataSource)
}

func registerNestedIDNames(data interface{}, attributeToDataSource map[string]string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for idField, sibling := range siblingIDNameFields {
			if id := stringifyID(v[idField]); id != "" {
				if name, ok := v[sibling.nameField].(string); ok && name != "" {
					RegisterTypedIDName(sibling.dataSourceType, id, name)
				}
			}
		}
		for key, nested := range v {
			if dataSourceType, ok := attributeToDataSource[key]; ok {
				registerObjectNames(dataSourceType, nested)
			}
			registerNestedIDNames(nested, attributeToDataSource)
		}
	case []interface{}:
		for _, item := range v {
			registerNestedIDNames(item, attributeToDataSource)
		}
	}
}

// registerObjectNames registers the {id, name} pairs of an attribute value under
// the data source type that attribute maps to. The value may be a single object
// or a list of them.
func registerObjectNames(dataSourceType string, value interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		if id := stringifyID(v["id"]); id != "" {
			if name, ok := v["name"].(string); ok && name != "" {
				RegisterTypedIDName(dataSourceType, id, name)
			}
		}
	case []interface{}:
		for _, item := range v {
			registerObjectNames(dataSourceType, item)
		}
	}
}

// providerPrefixFromResourceType extracts the provider prefix (zia, zpa, ztc)
// from a resource type such as "zia_dlp_web_rules".
func providerPrefixFromResourceType(resourceType string) string {
	if idx := strings.Index(resourceType, "_"); idx > 0 {
		return resourceType[:idx]
	}
	return resourceType
}

// stringifyID normalizes an ID value from a JSON payload to its string form.
// Terraform references (values containing dots) are not IDs and yield "".
func stringifyID(v interface{}) string {
	switch id := v.(type) {
	case string:
		if id == "" || strings.Contains(id, ".") {
			return ""
		}
		return id
	case float64:
		if id == 0 {
			return ""
		}
		return fmt.Sprintf("%d", int64(id))
	case int:
		if id == 0 {
			return ""
		}
		return fmt.Sprintf("%d", id)
	}
	return ""
}

func IsInList(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

// resourcesSkippingNonPositiveOrder lists rule-based resource types whose entries
// with a non-positive "order" value (order <= 0) must be skipped during import
// and generation. The Zscaler API returns predefined/system rules with negative
// (or zero) order values that the Terraform provider does not support managing.
//
// To extend this behavior to additional rule-based resources in the future,
// simply add the resource type to this set. All rule-based resources carry the
// "order" attribute, so no other changes are required.
var resourcesSkippingNonPositiveOrder = map[string]bool{
	"zia_firewall_dns_rule": true,
}

// ShouldSkipNonPositiveOrderRules reports whether entries of the given resource
// type with a non-positive "order" value (order <= 0) should be skipped.
func ShouldSkipNonPositiveOrderRules(resourceType string) bool {
	return resourcesSkippingNonPositiveOrder[resourceType]
}

// FilterNonPositiveOrderRules removes entries with a non-positive "order" value
// (order <= 0) from the provided data when the resource type is configured to
// skip such rules (see resourcesSkippingNonPositiveOrder). These correspond to
// predefined/system rules that the provider cannot manage.
//
// Entries whose "order" field is absent or unparseable are retained so that
// resources without a meaningful order are never dropped. When the resource type
// is not configured for skipping, the input is returned unchanged.
func FilterNonPositiveOrderRules(resourceType string, data []interface{}) []interface{} {
	if !ShouldSkipNonPositiveOrderRules(resourceType) {
		return data
	}

	filtered := make([]interface{}, 0, len(data))
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			filtered = append(filtered, item)
			continue
		}

		orderVal, exists := m["order"]
		if !exists {
			filtered = append(filtered, item)
			continue
		}

		order, ok := toFloat64(orderVal)
		if ok && order <= 0 {
			name, _ := m["name"].(string)
			log.Printf("[INFO] Skipping predefined %s rule %q with non-positive order %v", resourceType, name, orderVal)
			continue
		}

		filtered = append(filtered, item)
	}

	return filtered
}

// policyStyleBoolResources lists the ZPA resource types whose "policy_style"
// attribute is modeled as a bool in the Terraform provider even though the API
// returns it as a string ("NONE" / "DUAL_POLICY_EVAL"). The provider performs
// the string<->bool conversion at runtime, so the generated HCL must use a bool.
var policyStyleBoolResources = map[string]bool{
	"zpa_application_segment":            true,
	"zpa_application_segment_inspection": true,
}

// NormalizePolicyStyle rewrites the API "policyStyle" string value into the bool
// expected by the Terraform provider schema for the given resource type
// ("DUAL_POLICY_EVAL" -> true, anything else -> false). Entries that already use
// a bool, or that omit the attribute, are left untouched. When the resource type
// does not model policy_style as a bool, the input is returned unchanged.
func NormalizePolicyStyle(resourceType string, data []interface{}) []interface{} {
	if !policyStyleBoolResources[resourceType] {
		return data
	}

	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if v, exists := m["policyStyle"]; exists {
			if s, ok := v.(string); ok {
				m["policyStyle"] = s == "DUAL_POLICY_EVAL"
			}
		}
	}

	return data
}

// toFloat64 best-effort converts a value decoded from JSON (or a typed struct)
// into a float64. It returns false when the value cannot be interpreted as a
// number.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
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
		"zia_ftp_control_policy",
		"zia_mobile_malware_protection_policy",
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
	defer func() { _ = f.Close() }()

	// Write the output block to the file.
	if _, err := f.WriteString(outputBlock); err != nil {
		log.Fatalf("failed to write to outputs file: %s", err)
	}
}

// / Custom function to Removes attributes from ZPA StateFile.
func RemoveTcpPortRangesFromState(stateFile string) {
	// Check if the state file exists first
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		log.Printf("[DEBUG] State file %s does not exist, skipping tcp_port_ranges removal", stateFile)
		return
	}

	// Read the state file
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		log.Printf("[WARNING] Failed to read state file %s: %s", stateFile, err)
		return
	}

	// Unmarshal the JSON data
	var state map[string]interface{}
	if err := json.Unmarshal(stateData, &state); err != nil {
		log.Printf("[WARNING] Failed to unmarshal state file: %s", err)
		return
	}

	// Traverse the state file structure to remove tcp_port_ranges.
	resources, ok := state["resources"].([]interface{})
	if !ok {
		log.Printf("[DEBUG] State file has no resources or unexpected structure, skipping")
		return
	}

	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			log.Printf("[WARNING] Unexpected structure in state file: resource is not a map, skipping")
			continue
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
		log.Printf("[WARNING] Failed to marshal modified state file: %s", err)
		return
	}

	// Write the modified state back to the file
	if err := os.WriteFile(stateFile, modifiedStateData, 0600); err != nil {
		log.Printf("[WARNING] Failed to write modified state file: %s", err)
		return
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
	// Check if the list is empty or nil, and if so, don't generate the block.
	if obj == nil {
		return ""
	}

	objList, ok := obj.([]interface{})
	if !ok || len(objList) == 0 {
		return ""
	}

	// Check if all items in the list are valid (have non-zero id).
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
		idStr := fmt.Sprintf("%d", int64(id))
		validItems = append(validItems, idStr)

		// Capture the name for data source generation if available.
		if name, ok := m["name"].(string); ok && name != "" {
			RegisterIDName(idStr, name)
		}
	}

	// If no valid items, don't generate the block.
	if len(validItems) == 0 {
		return ""
	}

	// Generate the block with valid items.
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

			// Capture the name for data source generation if available.
			if name, ok := m["name"].(string); ok && name != "" {
				RegisterIDName(id, name)
			}
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
				// "enabled" is not configurable within common_apps_dto.apps_config;
				// strip it to avoid unconfigurable/computed attribute errors.
				if snakeKey == "enabled" {
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
			case "ONLY_ONEAPI_SUPPORTED":
				// Handle OneAPI-only endpoints that require specific access tokens
				return true, fmt.Sprintf("Resource requires OneAPI access: %s", ziaErr.Message)
			default:
				return false, fmt.Sprintf("Unhandled ZIA error: %s - %s", ziaErr.Code, ziaErr.Message)
			}
		}
	}

	// Check for specific error patterns in the error string
	if strings.Contains(errorString, "ONLY_ONEAPI_SUPPORTED") {
		return true, "Resource requires OneAPI access, skipping import"
	}
	if strings.Contains(errorString, "This API endpoint can be accessed only through Zscaler OneAPI") {
		return true, "Resource requires OneAPI access, skipping import"
	}
	if strings.Contains(errorString, "not licensed") || strings.Contains(errorString, "not authorized") {
		return true, "Resource not licensed or authorized, skipping import"
	}
	if strings.Contains(errorString, "feature is not enabled") {
		return true, "Required feature not enabled, skipping import"
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
