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
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DataSourceMapping defines a mapping between an attribute and its corresponding data source
type DataSourceMapping struct {
	AttributeName  string // e.g., "location_groups", "time_windows"
	DataSourceType string // e.g., "zia_location_groups", "zia_firewall_filtering_time_window"
}

// GetDataSourceMappings returns the mapping of attribute names to data source types
// This is where you can easily add new mappings as requested by the user
func GetDataSourceMappings() []DataSourceMapping {
	return []DataSourceMapping{
		// ZIA Data Source Mappings for common attributes
		{"location_groups", "zia_location_groups"},
		{"time_windows", "zia_firewall_filtering_time_window"},
		{"users", "zia_user_management"},
		{"groups", "zia_group_management"},
		{"departments", "zia_department_management"},
		{"proxy_gateways", "zia_forwarding_control_proxy_gateway"},
		{"device_groups", "zia_device_groups"},
		{"devices", "zia_devices"},
		{"workload_groups", "zia_workload_groups"},

		// Additional mappings can be easily added here
		// {"new_attribute", "zia_new_data_source"},
	}
}

// CollectedDataSourceID represents a data source that needs to be created
type CollectedDataSourceID struct {
	DataSourceType string
	ID             string
	UniqueName     string // e.g., "this_345645"
	Name           string // For workload_groups, stores the name value
}

// PostProcessDataSources performs data source replacement after all imports are complete
// This function is designed to work alongside the existing PostProcessReferences without interference
func PostProcessDataSources(workingDir string) error {
	log.Printf("[INFO] Starting data source post-processing...")

	// Create a timeout context to prevent hanging (5 minutes timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run the processing in a goroutine with timeout protection
	done := make(chan error, 1)
	go func() {
		done <- processDataSourcesWithTimeout(workingDir)
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		if err != nil {
			return err
		}
		log.Printf("[INFO] Data source post-processing completed successfully")
		return nil
	case <-ctx.Done():
		log.Printf("[ERROR] Data source post-processing timed out after 5 minutes")
		return fmt.Errorf("data source post-processing timed out")
	}
}

// processDataSourcesWithTimeout performs the actual data source processing
func processDataSourcesWithTimeout(workingDir string) error {
	// Step 1: Clean up empty data source attribute blocks first
	log.Printf("[DEBUG] Step 1: Cleaning up empty blocks...")
	err := CleanupEmptyDataSourceBlocks(workingDir)
	if err != nil {
		log.Printf("[WARNING] Failed to cleanup empty blocks: %v", err)
	}

	// Step 2: Collect all IDs that need data source references
	log.Printf("[DEBUG] Step 2: Collecting data source IDs...")
	dataSourceIDs, err := CollectDataSourceIDs(workingDir)
	if err != nil {
		return fmt.Errorf("failed to collect data source IDs: %w", err)
	}

	if len(dataSourceIDs) == 0 {
		log.Printf("[INFO] No data source IDs found to process")
		return nil
	}

	// Step 3: Generate datasource.tf file
	log.Printf("[DEBUG] Step 3: Generating datasource.tf file...")
	err = GenerateDataSourceFile(workingDir, dataSourceIDs)
	if err != nil {
		return fmt.Errorf("failed to generate datasource.tf: %w", err)
	}

	// Step 4: Replace IDs with data source references in all .tf files
	log.Printf("[DEBUG] Step 4: Replacing data source references...")
	err = ReplaceDataSourceReferences(workingDir, dataSourceIDs)
	if err != nil {
		return fmt.Errorf("failed to replace data source references: %w", err)
	}

	return nil
}

// CleanupEmptyDataSourceBlocks removes empty data source attribute blocks from .tf files
func CleanupEmptyDataSourceBlocks(workingDir string) error {
	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Get data source mappings
	mappings := GetDataSourceMappings()

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		originalContent := string(content)
		processedContent := originalContent

		// Remove empty blocks for each mapped attribute
		for _, mapping := range mappings {
			attributeName := mapping.AttributeName

			// Pattern to match empty blocks: attribute_name { id = [] }
			// Use multiline and dotall mode to handle newlines and whitespace in blocks
			// Also capture surrounding whitespace to avoid leaving blank lines
			pattern := fmt.Sprintf(`(?ms)\s*\b%s\s*\{\s*id\s*=\s*\[\s*\]\s*\}\s*`, regexp.QuoteMeta(attributeName))
			re := regexp.MustCompile(pattern)

			// Remove the empty blocks and replace with a single newline to maintain formatting
			processedContent = re.ReplaceAllString(processedContent, "\n")
		}

		// Clean up multiple consecutive newlines
		multipleNewlines := regexp.MustCompile(`\n{3,}`)
		processedContent = multipleNewlines.ReplaceAllString(processedContent, "\n\n")

		// Write back the processed content if it changed
		if processedContent != originalContent {
			err = ioutil.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			log.Printf("[INFO] Removed empty data source blocks from %s", baseName)
		}
	}

	return nil
}

// CollectDataSourceIDs scans all .tf files and collects IDs that should be replaced with data source references
func CollectDataSourceIDs(workingDir string) ([]CollectedDataSourceID, error) {
	var collectedIDs []CollectedDataSourceID
	idTracker := make(map[string]bool) // To avoid duplicates

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return nil, fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Get data source mappings
	mappings := GetDataSourceMappings()

	// Create a map for quick lookup
	attributeToDataSource := make(map[string]string)
	for _, mapping := range mappings {
		attributeToDataSource[mapping.AttributeName] = mapping.DataSourceType
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		fileContent := string(content)

		// Look for attribute blocks that match our mappings
		for attributeName, dataSourceType := range attributeToDataSource {
			var matches [][]string

			if attributeName == "workload_groups" {
				// Special pattern for workload_groups: capture both id and name
				// Pattern: workload_groups { id = 123 name = "NAME" }
				pattern := fmt.Sprintf(`(?ms)\b%s\s*\{[^}]*?id\s*=\s*(\d+)[^}]*?name\s*=\s*"([^"]+)"[^}]*\}`, regexp.QuoteMeta(attributeName))
				re := regexp.MustCompile(pattern)
				matches = re.FindAllStringSubmatch(fileContent, -1)
			} else {
				// Standard pattern for other attributes: attribute_name { id = [123, 456] }
				pattern := fmt.Sprintf(`(?ms)\b%s\s*\{[^}]*id\s*=\s*\[([^\]]+)\][^}]*\}`, regexp.QuoteMeta(attributeName))
				re := regexp.MustCompile(pattern)
				matches = re.FindAllStringSubmatch(fileContent, -1)
			}

			for _, match := range matches {
				if len(match) < 2 {
					continue
				}

				if attributeName == "workload_groups" {
					// For workload_groups, match[1] is the ID and match[2] is the name
					if len(match) >= 3 {
						id := match[1]
						name := match[2]

						// Skip if already processed or if it's already a resource reference
						if strings.Contains(id, ".") {
							continue // Already a reference
						}

						uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
						if idTracker[uniqueKey] {
							continue // Already collected
						}

						collectedIDs = append(collectedIDs, CollectedDataSourceID{
							DataSourceType: dataSourceType,
							ID:             id,
							UniqueName:     fmt.Sprintf("this_%s", id),
							Name:           name, // Store the name for workload_groups
						})
						idTracker[uniqueKey] = true
					}
				} else {
					// For other attributes, match[1] is the array content
					idsContent := match[1]
					ids := extractIDsFromContent(idsContent)

					for _, id := range ids {
						// Skip if already processed or if it's already a resource reference
						if strings.Contains(id, ".") {
							continue // Already a reference
						}

						uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
						if idTracker[uniqueKey] {
							continue // Already collected
						}

						collectedIDs = append(collectedIDs, CollectedDataSourceID{
							DataSourceType: dataSourceType,
							ID:             id,
							UniqueName:     fmt.Sprintf("this_%s", id),
							Name:           "", // Empty for non-workload_groups attributes
						})
						idTracker[uniqueKey] = true
					}
				}
			}
		}
	}

	log.Printf("[INFO] Collected %d unique data source IDs", len(collectedIDs))
	return collectedIDs, nil
}

// extractIDsFromContent extracts individual IDs from content like "123, 456" or "123", "456"
func extractIDsFromContent(content string) []string {
	var ids []string

	// Handle different formats:
	// 1. "123", "456" (quoted, comma-separated)
	// 2. 123, 456 (unquoted, comma-separated)
	// 3. "123, 456" (single quoted string with comma-separated values)

	content = strings.TrimSpace(content)

	// Remove outer quotes if present
	if strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) && strings.Count(content, `"`) == 2 {
		content = content[1 : len(content)-1]
	}

	// Split by comma and clean up each part
	parts := strings.Split(content, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Remove quotes if present
		part = strings.Trim(part, `"`)
		if part != "" && !strings.Contains(part, ".") { // Ensure it's not already a reference
			ids = append(ids, part)
		}
	}

	return ids
}

// GenerateDataSourceFile creates a datasource.tf file with all required data sources
func GenerateDataSourceFile(workingDir string, dataSourceIDs []CollectedDataSourceID) error {
	if len(dataSourceIDs) == 0 {
		return nil
	}

	datasourceFile := filepath.Join(workingDir, "datasource.tf")
	file, err := os.Create(datasourceFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	_, err = file.WriteString("# Data sources for attribute ID references\n")
	if err != nil {
		return err
	}
	_, err = file.WriteString("# Generated automatically by Zscaler Terraformer\n\n")
	if err != nil {
		return err
	}

	// Write each data source
	for _, dsID := range dataSourceIDs {
		var dataSourceBlock string

		if dsID.DataSourceType == "zia_workload_groups" && dsID.Name != "" {
			// For workload_groups, include both id and name
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  id   = %s
  name = "%s"
}

`, dsID.DataSourceType, dsID.UniqueName, dsID.ID, dsID.Name)
		} else {
			// For other data sources, only include id
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  id = %s
}

`, dsID.DataSourceType, dsID.UniqueName, dsID.ID)
		}

		_, err = file.WriteString(dataSourceBlock)
		if err != nil {
			return err
		}
	}

	log.Printf("[INFO] Generated datasource.tf with %d data sources", len(dataSourceIDs))
	return nil
}

// ReplaceDataSourceReferences replaces IDs with data source references in all .tf files
func ReplaceDataSourceReferences(workingDir string, dataSourceIDs []CollectedDataSourceID) error {
	// Create a lookup map: ID -> data source reference
	idToReference := make(map[string]string)
	for _, dsID := range dataSourceIDs {
		reference := fmt.Sprintf("data.%s.%s.id", dsID.DataSourceType, dsID.UniqueName)
		idToReference[dsID.ID] = reference
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Get data source mappings and pre-compile regex patterns for performance
	mappings := GetDataSourceMappings()
	attributePatterns := make(map[string]*regexp.Regexp)
	attributeToDataSource := make(map[string]string)

	for _, mapping := range mappings {
		attributeName := mapping.AttributeName
		attributeToDataSource[attributeName] = mapping.DataSourceType

		// Pre-compile regex patterns to avoid recompilation in loops
		pattern := fmt.Sprintf(`(?ms)(\b%s\s*\{[^}]*id\s*=\s*\[)([^\]]+)(\][^}]*\})`, regexp.QuoteMeta(attributeName))
		attributePatterns[attributeName] = regexp.MustCompile(pattern)
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Check file size to prevent processing extremely large files
		fileInfo, err := os.Stat(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to get file info %s: %v", tfFile, err)
			continue
		}

		// Skip files larger than 10MB to prevent performance issues
		maxFileSize := int64(10 * 1024 * 1024) // 10MB
		if fileInfo.Size() > maxFileSize {
			log.Printf("[WARNING] Skipping large file %s (%d bytes) to prevent performance issues", baseName, fileInfo.Size())
			continue
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		originalContent := string(content)
		processedContent := originalContent
		hasChanges := false

		// Replace IDs in each mapped attribute using pre-compiled patterns
		for attributeName, expectedDataSourceType := range attributeToDataSource {
			var matches [][]string

			if attributeName == "workload_groups" {
				// Special handling for workload_groups - process both id and name replacement
				workloadPattern := fmt.Sprintf(`(?ms)(\b%s\s*\{[^}]*?)id\s*=\s*(\d+)([^}]*?)name\s*=\s*"([^"]+)"([^}]*?\})`, regexp.QuoteMeta(attributeName))
				workloadRe := regexp.MustCompile(workloadPattern)
				workloadMatches := workloadRe.FindAllStringSubmatch(processedContent, -1)

				// Process workload_groups matches in reverse order
				for j := len(workloadMatches) - 1; j >= 0; j-- {
					workloadMatch := workloadMatches[j]
					if len(workloadMatch) < 6 {
						continue
					}

					fullWorkloadMatch := workloadMatch[0]
					prefix := workloadMatch[1]
					id := workloadMatch[2]
					middle := workloadMatch[3]
					_ = workloadMatch[4] // name (not used for processing, but captured by regex)
					suffix := workloadMatch[5]

					// Check if this ID should be replaced with a data source reference
					if reference, exists := idToReference[id]; exists {
						// Ensure the reference matches the expected data source type
						if strings.Contains(reference, expectedDataSourceType) {
							// Create data source reference base (remove the .id suffix)
							dataSourceBase := strings.TrimSuffix(reference, ".id")

							// Replace both id and name with data source references
							replacement := prefix + "id = " + dataSourceBase + ".id" + middle + "name = " + dataSourceBase + ".name" + suffix
							processedContent = strings.Replace(processedContent, fullWorkloadMatch, replacement, 1)
							hasChanges = true
						}
					}
				}
				continue // Skip the standard processing for workload_groups
			} else {
				// Standard pattern for other attributes using pre-compiled patterns
				re := attributePatterns[attributeName]
				matches = re.FindAllStringSubmatch(processedContent, -1)
			}

			if len(matches) == 0 {
				continue // No matches for this attribute, skip to next
			}

			// Limit the number of matches to prevent excessive processing
			maxMatches := 1000
			if len(matches) > maxMatches {
				log.Printf("[WARNING] Too many matches (%d) for attribute %s in %s, limiting to %d",
					len(matches), attributeName, baseName, maxMatches)
				matches = matches[:maxMatches]
			}

			// Process matches in reverse order to avoid index shifting issues
			for i := len(matches) - 1; i >= 0; i-- {
				match := matches[i]

				// Handle standard array format: prefix + [ids] + suffix
				if len(match) < 4 {
					continue
				}

				fullMatch := match[0]
				prefix := match[1]
				idsContent := match[2]
				suffix := match[3]

				// Extract and process IDs
				ids := extractIDsFromContent(idsContent)
				var processedIds []string
				needsReplacement := false

				for _, id := range ids {
					// Skip if this is already a data source reference
					if strings.Contains(id, "data.") {
						processedIds = append(processedIds, id)
						continue
					}

					// Check if this ID should be replaced with a data source reference
					if reference, exists := idToReference[id]; exists {
						// Ensure the reference matches the expected data source type
						if strings.Contains(reference, expectedDataSourceType) {
							processedIds = append(processedIds, reference)
							needsReplacement = true
						} else {
							// Keep original ID if data source type doesn't match
							processedIds = append(processedIds, id)
						}
					} else {
						// Keep original ID if no data source reference found
						processedIds = append(processedIds, id)
					}
				}

				// Only replace if we actually made changes
				if needsReplacement {
					replacement := prefix + strings.Join(processedIds, ", ") + suffix
					processedContent = strings.Replace(processedContent, fullMatch, replacement, 1)
					hasChanges = true
				}
			}
		}

		// Write back the processed content if it changed
		if hasChanges && processedContent != originalContent {
			err = ioutil.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			log.Printf("[INFO] Updated data source references in %s", baseName)
		}
	}

	return nil
}
