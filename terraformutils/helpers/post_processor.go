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
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PostProcessReferences performs reference replacement after all imports are complete
func PostProcessReferences(workingDir string) error {
	log.Printf("[INFO] Starting post-processing reference replacement...")

	// Parse outputs.tf to get all available resource mappings
	resourceMap, err := ParseOutputsFile(workingDir)
	if err != nil {
		log.Printf("[WARNING] Failed to parse outputs.tf: %v", err)
		resourceMap = make(map[string]string)
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip outputs.tf and datasource.tf
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" {
			continue
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		// Process the content
		processedContent := ProcessFileContent(string(content), resourceMap)

		// Write back the processed content
		if processedContent != string(content) {
			err = ioutil.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
		}
	}

	log.Printf("[INFO] Post-processing reference replacement completed")
	return nil
}

// ProcessFileContent processes the content of a .tf file and returns processed content
func ProcessFileContent(content string, resourceMap map[string]string) string {
	// Find all id = ["..."] patterns (nested blocks) - handle both single and multiple IDs
	// Only match raw IDs (those in quotes), not already-processed resource references
	re := regexp.MustCompile(`id\s*=\s*\[([^\]]+)\]`)

	processedContent := re.ReplaceAllStringFunc(content, func(match string) string {
		// Check if this is within an app_service_groups block - if so, skip processing
		// Look backwards in the content to find the attribute name
		matchIndex := strings.Index(content, match)
		if matchIndex > 0 {
			// Look for the attribute name before this match
			beforeMatch := content[:matchIndex]
			lines := strings.Split(beforeMatch, "\n")
			if len(lines) > 0 {
				lastLine := strings.TrimSpace(lines[len(lines)-1])
				if strings.Contains(lastLine, "app_service_groups") {
					return match // Skip processing for app_service_groups
				}
			}
		}

		// Extract the content inside the brackets
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		idsContent := submatches[1]

		// Skip if this is already a processed resource reference (contains dots and no quotes)
		if strings.Contains(idsContent, ".") && !strings.Contains(idsContent, `"`) {
			return match
		}

		// Parse the IDs - they can be single "id" or multiple "id1", "id2", etc.
		// Handle both formats: ["id1", "id2"] and ["id1, id2"]
		// Also handle mixed formats with already-processed resource references
		idParts := []string{}

		// Handle different formats:
		// 1. "id1", "id2", "id3" (multiple quoted strings)
		// 2. "id1, id2, id3" (single quoted string with comma-separated values)
		// 3. id1, id2, id3 (unquoted comma-separated values)

		if strings.Contains(idsContent, `", "`) {
			// Format 1: "id1", "id2", "id3"
			parts := strings.Split(idsContent, `", "`)
			for i, part := range parts {
				// Remove leading quote from first part
				if i == 0 {
					part = strings.TrimPrefix(part, `"`)
				}
				// Remove trailing quote from last part
				if i == len(parts)-1 {
					part = strings.TrimSuffix(part, `"`)
				}
				part = strings.TrimSpace(part)
				if part != "" {
					idParts = append(idParts, part)
				}
			}
		} else {
			// Format 2 or 3: "id1, id2, id3" or id1, id2, id3
			// Remove outer quotes if present
			cleanContent := strings.TrimSpace(idsContent)
			if strings.HasPrefix(cleanContent, `"`) && strings.HasSuffix(cleanContent, `"`) {
				cleanContent = cleanContent[1 : len(cleanContent)-1]
			}

			// Split by comma and process each part
			parts := strings.Split(cleanContent, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					idParts = append(idParts, part)
				}
			}
		}

		// Process each ID
		var processedIds []string
		for _, id := range idParts {
			// Check if this is already a resource reference (contains dots)
			if strings.Contains(id, ".") {
				// Already a resource reference, don't quote it
				processedIds = append(processedIds, id)
			} else if resourceRef, exists := resourceMap[id]; exists {
				// Found in resource map, use the reference
				processedIds = append(processedIds, resourceRef)
			} else {
				// Raw ID - check if it needs quotes
				// If it's a number, don't quote it
				// If it's already quoted, don't add more quotes
				if strings.HasPrefix(id, `"`) && strings.HasSuffix(id, `"`) {
					// Already quoted, use as-is
					processedIds = append(processedIds, id)
				} else if _, err := strconv.Atoi(id); err == nil {
					// It's a number, don't quote it
					processedIds = append(processedIds, id)
				} else {
					// It's a string, quote it
					processedIds = append(processedIds, fmt.Sprintf(`"%s"`, id))
				}
			}
		}

		// Reconstruct the id block
		return fmt.Sprintf("id = [%s]", strings.Join(processedIds, ", "))
	})

	// Handle single ID attributes (not arrays) that should be mapped to resource references
	// Pattern: attribute_name { id = 123 }
	singleIdRe := regexp.MustCompile(`(\w+)\s*\{\s*id\s*=\s*(\d+)\s*\}`)

	processedContent = singleIdRe.ReplaceAllStringFunc(processedContent, func(match string) string {
		// Extract the attribute name and ID
		submatches := singleIdRe.FindStringSubmatch(match)
		if len(submatches) < 3 {
			return match
		}

		attributeName := submatches[1]
		idValue := submatches[2]

		// Check if this attribute should be mapped to a resource reference
		resourceType := getSingleIdResourceType(attributeName)
		if resourceType == "" {
			return match // No mapping defined, leave as is
		}

		// Look up the resource reference in the resource map
		if resourceRef, exists := resourceMap[idValue]; exists {
			// Replace with resource reference
			return fmt.Sprintf("%s {\n  id = %s\n}", attributeName, resourceRef)
		}

		// If not found in resource map, leave as is
		return match
	})

	// Find all rhs = "..." patterns in operands blocks and replace based on object_type
	rhsRe := regexp.MustCompile(`(\s+operands\s*\{[^}]*object_type\s*=\s*"([^"]+)"[^}]*rhs\s*=\s*)"([^"]+)"([^}]*\})`)

	processedContent = rhsRe.ReplaceAllStringFunc(processedContent, func(match string) string {
		// Extract the object_type and rhs value
		submatches := rhsRe.FindStringSubmatch(match)
		if len(submatches) < 5 {
			return match
		}

		prefix := submatches[1]
		objectType := submatches[2]
		rhsValue := submatches[3]
		suffix := submatches[4]

		// Determine the resource type based on object_type
		var expectedResourceType string
		switch objectType {
		case "APP":
			expectedResourceType = "zpa_application_segment"
		case "APP_GROUP":
			expectedResourceType = "zpa_segment_group"
		default:
			// For other object types, leave as raw ID
			return match
		}

		// Look for a resource reference in the resourceMap
		if resourceRef, exists := resourceMap[rhsValue]; exists {
			// Check if the resource reference matches the expected type
			if strings.Contains(resourceRef, expectedResourceType) {
				return prefix + resourceRef + suffix
			}
		}

		return match
	})

	// Find flat attribute patterns that need reference replacement
	// Pattern: attribute_name = "ID"
	flatAttributePatterns := []string{
		`segment_group_id\s*=\s*"([^"]+)"`,
		`zpn_isolation_profile_id\s*=\s*"([^"]+)"`,
	}

	for _, pattern := range flatAttributePatterns {
		re = regexp.MustCompile(pattern)
		processedContent = re.ReplaceAllStringFunc(processedContent, func(match string) string {
			// Extract the ID from the match
			submatches := re.FindStringSubmatch(match)
			if len(submatches) < 2 {
				return match
			}

			id := submatches[1]

			// Determine the resource type based on the attribute name
			var expectedResourceType string
			if strings.Contains(pattern, "segment_group_id") {
				expectedResourceType = "zpa_segment_group"
			} else if strings.Contains(pattern, "zpn_isolation_profile_id") {
				expectedResourceType = "zpa_cloud_browser_isolation_external_profile"
			}

			// Check if this ID exists in our resource map
			if resourceRef, exists := resourceMap[id]; exists {
				// Ensure the found reference matches the expected type
				if strings.Contains(resourceRef, expectedResourceType) {
					// Replace with resource reference (no quotes)
					return strings.Replace(match, fmt.Sprintf(`"%s"`, id), resourceRef, 1)
				}
			}
			// Leave the ID as is - no replacement
			return match
		})
	}

	// Special handling for zcomponent_id - need to consider association_type context
	zcomponentRe := regexp.MustCompile(`(\s+association_type\s*=\s*"([^"]+)"[^}]*zcomponent_id\s*=\s*)"([^"]+)"([^}]*\})`)
	processedContent = zcomponentRe.ReplaceAllStringFunc(processedContent, func(match string) string {
		// Extract the association_type and zcomponent_id value
		submatches := zcomponentRe.FindStringSubmatch(match)
		if len(submatches) < 5 {
			return match
		}

		prefix := submatches[1]
		associationType := submatches[2]
		zcomponentId := submatches[3]
		suffix := submatches[4]

		// Determine the expected resource type based on association_type
		var expectedResourceType string
		switch associationType {
		case "CONNECTOR_GRP":
			expectedResourceType = "zpa_app_connector_group"
		case "SERVICE_EDGE_GRP":
			expectedResourceType = "zpa_service_edge_group"
		default:
			// For other association types, leave as raw ID
			return match
		}

		// Look for a resource reference in the resourceMap
		if resourceRef, exists := resourceMap[zcomponentId]; exists {
			// Check if the resource reference matches the expected type
			if strings.Contains(resourceRef, expectedResourceType) {
				return prefix + resourceRef + suffix
			}
		}

		return match
	})

	// Handle single ID attributes that don't use array syntax
	// Pattern: attribute_name = "ID" (without brackets)
	singleIdAttributePatterns := []string{
		`services\s*\{\s*id\s*=\s*\["([^"]+)"\]\s*\}`,
	}

	for _, pattern := range singleIdAttributePatterns {
		re = regexp.MustCompile(pattern)
		processedContent = re.ReplaceAllStringFunc(processedContent, func(match string) string {
			submatches := re.FindStringSubmatch(match)
			if len(submatches) < 2 {
				return match
			}

			idsContent := submatches[1]

			// Parse comma-separated IDs
			idParts := []string{}
			if strings.Contains(idsContent, ",") {
				parts := strings.Split(idsContent, ",")
				for _, part := range parts {
					idParts = append(idParts, strings.TrimSpace(part))
				}
			} else {
				idParts = []string{strings.TrimSpace(idsContent)}
			}

			// For services attribute, we need to handle it as a set of numbers
			// Convert all IDs to a set format (no quotes)
			if len(idParts) > 0 {
				var processedIds []string
				for _, id := range idParts {
					processedIds = append(processedIds, id)
				}
				// Convert to set format: [id1, id2, id3] (no quotes)
				return fmt.Sprintf("services {\n    id = [%s]\n  }", strings.Join(processedIds, ", "))
			}

			return match
		})
	}

	return processedContent
}

// getSingleIdResourceType returns the resource type for single ID attributes
func getSingleIdResourceType(attributeName string) string {
	// Map of attribute names to their corresponding resource types
	singleIdMappings := map[string]string{
		"notification_template": "zia_dlp_notification_templates",
		// Add more mappings here as needed
	}

	if resourceType, exists := singleIdMappings[attributeName]; exists {
		return resourceType
	}

	return ""
}
