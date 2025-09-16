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
	"strings"
)

// PostProcessReferences performs reference replacement after all imports are complete
func PostProcessReferences(workingDir string) error {
	fmt.Printf("[DEBUG] PostProcessReferences called with workingDir: %s\n", workingDir)
	log.Printf("[INFO] Starting post-processing reference replacement...")
	log.Printf("[DEBUG] Working directory: %s", workingDir)

	// Parse outputs.tf to get all available resource mappings
	fmt.Printf("[DEBUG] About to parse outputs.tf...\n")
	resourceMap, err := ParseOutputsFile(workingDir)
	if err != nil {
		log.Printf("[WARNING] Failed to parse outputs.tf: %v", err)
		resourceMap = make(map[string]string)
	}
	log.Printf("[DEBUG] Loaded %d resource mappings from outputs.tf", len(resourceMap))
	for id, ref := range resourceMap {
		log.Printf("[DEBUG] ResourceMap: %s -> %s", id, ref)
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}
	fmt.Printf("[DEBUG] Found %d .tf files: %v\n", len(tfFiles), tfFiles)

	// Process each .tf file
	log.Printf("[DEBUG] Found %d .tf files to process", len(tfFiles))
	for _, tfFile := range tfFiles {
		// Skip outputs.tf and datasource.tf
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" {
			continue
		}

		log.Printf("[DEBUG] Processing file: %s", baseName)

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}
		fmt.Printf("[DEBUG] Read file %s, content length: %d\n", baseName, len(content))

		// Process the content
		processedContent := processFileContent(string(content), resourceMap)

		// Write back the processed content
		if processedContent != string(content) {
			err = ioutil.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			log.Printf("[DEBUG] Updated file: %s", baseName)
		}
	}

	log.Printf("[INFO] Post-processing reference replacement completed")
	return nil
}

// processFileContent processes the content of a .tf file and returns processed content
func processFileContent(content string, resourceMap map[string]string) string {
	// Find all id = ["..."] patterns (nested blocks) - handle both single and multiple IDs
	// Only match raw IDs (those in quotes), not already-processed resource references
	re := regexp.MustCompile(`id\s*=\s*\[([^\]]+)\]`)

	processedContent := re.ReplaceAllStringFunc(content, func(match string) string {
		// Extract the content inside the brackets
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		idsContent := submatches[1]
		fmt.Printf("[DEBUG] Processing nested IDs content: %s in match: %s\n", idsContent, match)

		// Skip if this is already a processed resource reference (contains dots and no quotes)
		if strings.Contains(idsContent, ".") && !strings.Contains(idsContent, `"`) {
			fmt.Printf("[DEBUG] Skipping already-processed resource reference: %s\n", idsContent)
			return match
		}

		// Parse the IDs - they can be single "id" or multiple "id1", "id2", etc.
		// Split by quote-comma-quote pattern to handle multiple quoted IDs
		idParts := []string{}
		if strings.Contains(idsContent, `", "`) {
			// Multiple IDs: "id1", "id2", "id3"
			parts := strings.Split(idsContent, `", "`)
			for i, part := range parts {
				if i == 0 {
					// First part: remove leading quote
					part = strings.TrimPrefix(part, `"`)
				}
				if i == len(parts)-1 {
					// Last part: remove trailing quote
					part = strings.TrimSuffix(part, `"`)
				}
				idParts = append(idParts, strings.TrimSpace(part))
			}
		} else {
			// Single ID: "id" - remove quotes
			cleanId := strings.TrimSpace(idsContent)
			cleanId = strings.Trim(cleanId, `"`)
			idParts = []string{cleanId}
		}

		// Process each ID
		var processedIds []string
		for _, id := range idParts {
			if resourceRef, exists := resourceMap[id]; exists {
				fmt.Printf("[DEBUG] Found resource reference for nested ID %s: %s\n", id, resourceRef)
				processedIds = append(processedIds, resourceRef)
			} else {
				fmt.Printf("[DEBUG] Nested ID %s not found in resource map, leaving as raw ID\n", id)
				processedIds = append(processedIds, fmt.Sprintf(`"%s"`, id))
			}
		}

		// Reconstruct the id block
		return fmt.Sprintf("id = [%s]", strings.Join(processedIds, ", "))
	})

	// Find flat attribute patterns that need reference replacement
	// Pattern: attribute_name = "ID"
	flatAttributePatterns := []string{
		`segment_group_id\s*=\s*"([^"]+)"`,
		`zcomponent_id\s*=\s*"([^"]+)"`,
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
			fmt.Printf("[DEBUG] Processing flat attribute ID: %s in match: %s\n", id, match)

			// Check if this ID exists in our resource map
			if resourceRef, exists := resourceMap[id]; exists {
				fmt.Printf("[DEBUG] Found resource reference for flat attribute ID %s: %s\n", id, resourceRef)
				// Replace with resource reference (no quotes)
				return fmt.Sprintf("%s = %s", strings.Split(match, "=")[0], resourceRef)
			} else {
				fmt.Printf("[DEBUG] Flat attribute ID %s not found in resource map, leaving as raw ID\n", id)
				// Leave the ID as is - no replacement
				return match
			}
		})
	}

	return processedContent
}
