// Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

//                             MIT License
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package helpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/iancoleman/strcase"
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

func ListIdsIntBlock(fieldName string, obj interface{}) string {
	output := ""
	if obj != nil && len(obj.([]interface{})) >= 0 {
		output = fieldName + " {\n"
		output += "id=["
		for i, v := range obj.([]interface{}) {
			m, ok := v.(map[string]interface{})
			if !ok || m == nil || m["id"] == 0 {
				continue
			}
			id, ok := m["id"].(float64)
			if !ok || id == 0 {
				continue
			}
			if i > 0 {
				output += ","
			}
			output += fmt.Sprintf("%d", int64(id))
		}
		output += "]\n"
		output += "}\n"
	}
	return output
}

func ListIdsStringBlock(fieldName string, obj interface{}) string {
	output := fieldName + " {\n"
	output += "id=["
	if obj != nil && len(obj.([]interface{})) >= 0 {
		for i, v := range obj.([]interface{}) {
			m, ok := v.(map[string]interface{})
			if !ok || m == nil || m["id"] == "" {
				continue
			}
			id, ok := m["id"].(string)
			if !ok || id == "" {
				continue
			}
			if i > 0 {
				output += ","
			}
			output += "\"" + id + "\""
		}
	}
	output += "]\n"
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
}

func HandleZIAError(responseBody []byte) (bool, string) {
	var ziaErr ZIAAPIErrorResponse
	if jsonErr := json.Unmarshal(responseBody, &ziaErr); jsonErr == nil {
		switch ziaErr.Code {
		case "INVALID_INPUT_ARGUMENT":
			if strings.Contains(ziaErr.Message, "Custom File Hash feature is not enabled for your org") {
				return true, "Custom File Hash feature is disabled, skipping import"
			}
		default:
			return false, fmt.Sprintf("Unhandled ZIA error: %s - %s", ziaErr.Code, ziaErr.Message)
		}
	}
	return false, ""
}

func FormatHeredoc(value string) string {
	lines := strings.Split(value, "\n")
	formatted := ""
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			formatted += fmt.Sprintf("%s\n", trimmedLine)
		} else if i != len(lines)-1 {
			formatted += "\n"
		}
	}
	return formatted
}
