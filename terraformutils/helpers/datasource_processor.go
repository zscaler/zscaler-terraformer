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
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DataSourceMapping defines a mapping between an attribute and its corresponding data source.
type DataSourceMapping struct {
	AttributeName  string // e.g., "location_groups", "time_windows"
	DataSourceType string // e.g., "zia_location_groups", "zia_firewall_filtering_time_window"
}

// GetDataSourceMappings returns the mapping of attribute names to data source types.
// This is where you can easily add new mappings as requested by the user.
// NOTE: This function returns ZIA mappings by default for backwards compatibility.
// For context-aware mappings, use GetDataSourceMappingsForProvider().
func GetDataSourceMappings() []DataSourceMapping {
	return GetDataSourceMappingsForProvider("")
}

// GetDataSourceMappingsForProvider returns the mapping of attribute names to data source types
// based on the provider context. This ensures that attributes with the same names (e.g., dest_ip_groups)
// are mapped to the correct provider-specific data sources.
func GetDataSourceMappingsForProvider(providerPrefix string) []DataSourceMapping {
	// Common ZPA mappings (provider-agnostic)
	zpaMappings := []DataSourceMapping{
		// ZPA Application and Group Mappings
		{"app_connector_groups", "zpa_app_connector_group"},
		{"appConnectorGroups", "zpa_app_connector_group"},
		{"zcomponentId", "zpa_app_connector_group"},
		{"connector_groups", "zpa_app_connector_group"},
		{"connectorGroups", "zpa_app_connector_group"},
		{"server_groups", "zpa_server_group"},
		{"serverGroups", "zpa_server_group"},
		{"app_server_groups", "zpa_application_server"},
		{"appServerGroups", "zpa_application_server"},
		{"segment_group_id", "zpa_segment_group"},
		{"segmentGroupId", "zpa_segment_group"},
		{"applications", "zpa_application_segment"},
		{"app_segments", "zpa_application_segment"},
		{"appSegments", "zpa_application_segment"},

		// ZPA Service Edge and Network Mappings
		{"service_edges", "zpa_service_edge_controller"},
		{"serviceEdges", "zpa_service_edge_controller"},
		{"trusted_networks", "zpa_trusted_network"},
		{"trustedNetworks", "zpa_trusted_network"},

		// ZPA PRA Mappings
		{"pra_portals", "zpa_pra_portal_controller"},
		{"praPortals", "zpa_pra_portal_controller"},
		{"pra_applications", "zpa_application_segment"},
		{"praApplications", "zpa_application_segment"},
		{"pra_application", "zpa_application_segment"},
		{"praApplication", "zpa_application_segment"},

		// ZPA Profile Mappings for policy resources
		{"zpn_inspection_profile_id", "zpa_inspection_profile"},
		{"zpn_isolation_profile_id", "zpa_isolation_profile"},

		// ZPA Cloud Browser Isolation Mappings
		{"banner_id", "zpa_cloud_browser_isolation_banner"},
		{"region_ids", "zpa_cloud_browser_isolation_region"},
	}

	// ZTC-specific mappings for attributes that overlap with ZIA
	ztcMappings := []DataSourceMapping{
		// ZTC Location and Group Mappings
		{"locations", "ztc_location_management"},
		{"location_groups", "ztc_location_groups"},

		// ZTC IP Group Mappings
		{"source_ip_groups", "ztc_ip_source_groups"},
		{"src_ip_groups", "ztc_ip_source_groups"},
		{"srcIpGroups", "ztc_ip_source_groups"},
		{"dest_ip_groups", "ztc_ip_destination_groups"},
		{"destIpGroups", "ztc_ip_destination_groups"},
		{"destination_groups", "ztc_ip_destination_groups"},

		// ZTC Network Service Mappings
		{"nw_services", "ztc_network_services"},
		{"nwServices", "ztc_network_services"},
		{"services", "ztc_network_services"},
		{"nw_service_groups", "ztc_network_service_groups"},
		{"nwServiceGroups", "ztc_network_service_groups"},

		// ZTC Workload and Gateway Mappings
		{"src_workload_groups", "ztc_workload_groups"},
		{"workload_groups", "ztc_workload_groups"},
		{"proxy_gateway", "ztc_forwarding_gateway"},

		// ZTC User/Group Mappings (if applicable)
		{"users", "ztc_user_management"},
		{"groups", "ztc_group_management"},
		{"departments", "ztc_department_management"},
	}

	// ZIA-specific mappings (default for backwards compatibility)
	ziaMappings := []DataSourceMapping{
		// ZIA Location and Group Mappings
		{"locations", "zia_location_management"},
		{"location_groups", "zia_location_groups"},
		{"time_windows", "zia_firewall_filtering_time_window"},

		// ZIA User/Group Mappings
		{"users", "zia_user_management"},
		{"groups", "zia_group_management"},
		{"departments", "zia_department_management"},

		// ZIA Device Mappings
		{"proxy_gateways", "zia_forwarding_control_proxy_gateway"},
		{"device_groups", "zia_device_groups"},
		{"devices", "zia_devices"},
		{"workload_groups", "zia_workload_groups"},

		// ZIA Network Service Mappings
		{"nw_services", "zia_firewall_filtering_network_service"},
		{"services", "zia_firewall_filtering_network_service"},

		// ZIA Firewall and IP Group Mappings
		{"source_ip_groups", "zia_firewall_filtering_ip_source_groups"},
		{"src_ip_groups", "zia_firewall_filtering_ip_source_groups"},
		{"dest_ip_groups", "zia_firewall_filtering_destination_groups"},
		{"destination_groups", "zia_firewall_filtering_destination_groups"},

		// ZIA Network and Application Group Mappings
		{"nw_application_groups", "zia_firewall_filtering_network_application_groups"},
		{"nw_service_groups", "zia_firewall_filtering_network_service_groups"},
		{"static_location_groups", "zia_location_groups"},

		// ZIA Rule and Label Mappings
		{"labels", "zia_rule_labels"},
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

// CollectedDataSourceID represents a data source that needs to be created.
type CollectedDataSourceID struct {
	DataSourceType string
	ID             string
	UniqueName     string // e.g., "this_345645"
	Name           string // For workload_groups, stores the name value
}

// PostProcessDataSources performs data source replacement after all imports are complete.
// This function is designed to work alongside the existing PostProcessReferences without interference.
func PostProcessDataSources(workingDir string, showVerbose bool) error {
	if showVerbose {
		log.Printf("🔄 Starting data source post-processing...")
	}

	// Parse outputs.tf to get all available resource mappings (same as resource processing)
	resourceMap, err := ParseOutputsFile(workingDir)
	if err != nil {
		log.Printf("[WARNING] Failed to parse outputs.tf: %v", err)
		resourceMap = make(map[string]string)
	}
	return PostProcessDataSourcesWithResourceMap(workingDir, resourceMap, showVerbose)
}

// PostProcessDataSourcesWithResourceMap performs the data source post-processing operations with a provided resource map.
func PostProcessDataSourcesWithResourceMap(workingDir string, resourceMap map[string]string, showVerbose bool) error {
	if showVerbose {
		log.Printf("🔄 Starting data source post-processing...")
	}

	// Create a timeout context to prevent hanging (5 minutes timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run the processing in a goroutine with timeout protection
	done := make(chan error, 1)
	go func() {
		done <- processDataSourcesWithTimeout(workingDir, resourceMap, showVerbose)
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		if err != nil {
			return err
		}
		if showVerbose {
			log.Printf("🎯 Data source post-processing completed successfully")
		}
		return nil
	case <-ctx.Done():
		log.Printf("[ERROR] Data source post-processing timed out after 5 minutes")
		return fmt.Errorf("data source post-processing timed out")
	}
}

// processDataSourcesWithTimeout performs the actual data source processing.
func processDataSourcesWithTimeout(workingDir string, resourceMap map[string]string, showVerbose bool) error {
	// Step 1: Clean up empty data source attribute blocks first
	log.Printf("[DEBUG] Step 1: Cleaning up empty blocks...")
	err := CleanupEmptyDataSourceBlocks(workingDir)
	if err != nil {
		log.Printf("[WARNING] Failed to cleanup empty blocks: %v", err)
	}

	// Step 2: Collect all IDs that need data source references (excluding those with resource imports)
	log.Printf("[DEBUG] Step 2: Collecting data source IDs...")
	dataSourceIDs, err := CollectDataSourceIDs(workingDir, resourceMap, showVerbose)
	if err != nil {
		return fmt.Errorf("failed to collect data source IDs: %w", err)
	}

	// Step 3: Generate datasource.tf file (only for IDs without resource imports)
	if len(dataSourceIDs) > 0 {
		log.Printf("[DEBUG] Step 3: Generating datasource.tf file...")
		err = GenerateDataSourceFile(workingDir, dataSourceIDs, showVerbose)
		if err != nil {
			return fmt.Errorf("failed to generate datasource.tf: %w", err)
		}
	} else {
		log.Printf("[INFO] No data source IDs found to process - all IDs have resource imports")
	}

	// Step 4: Replace IDs with both resource references AND data source references in all .tf files
	log.Printf("[DEBUG] Step 4: Replacing references (resources and data sources)...")
	err = ReplaceAllReferences(workingDir, resourceMap, dataSourceIDs, showVerbose)
	if err != nil {
		return fmt.Errorf("failed to replace references: %w", err)
	}

	return nil
}

// CleanupEmptyDataSourceBlocks removes empty data source attribute blocks from .tf files.
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
		content, err := os.ReadFile(tfFile)
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
			err = os.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			log.Printf("🧹 Cleaned up empty blocks in %s", baseName)
		}
	}

	return nil
}

// DetectProviderFromFileName extracts the provider prefix (zia, zpa, ztc) from a Terraform file name.
// File names typically follow the pattern: zia_resource_name.tf, zpa_resource_name.tf, ztc_resource_name.tf.
func DetectProviderFromFileName(fileName string) string {
	baseName := filepath.Base(fileName)
	baseName = strings.TrimSuffix(baseName, ".tf")

	if strings.HasPrefix(baseName, "ztc_") {
		return "ztc"
	} else if strings.HasPrefix(baseName, "zpa_") {
		return "zpa"
	} else if strings.HasPrefix(baseName, "zia_") {
		return "zia"
	}
	return "" // Unknown provider
}

// CollectDataSourceIDs scans all .tf files and collects IDs that should be replaced with data source references.
// It excludes IDs that already have corresponding resource imports (found in resourceMap).
func CollectDataSourceIDs(workingDir string, resourceMap map[string]string, showVerbose bool) ([]CollectedDataSourceID, error) {
	var collectedIDs []CollectedDataSourceID
	idTracker := make(map[string]bool) // To avoid duplicates

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return nil, fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Detect provider from filename for context-aware mapping
		providerPrefix := DetectProviderFromFileName(tfFile)

		// Get provider-specific data source mappings
		mappings := GetDataSourceMappingsForProvider(providerPrefix)

		// Create a map for quick lookup (provider-specific)
		attributeToDataSource := make(map[string]string)
		for _, mapping := range mappings {
			attributeToDataSource[mapping.AttributeName] = mapping.DataSourceType
		}

		// Read the file
		content, err := os.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		fileContent := string(content)

		// Look for attribute blocks that match our mappings
		for attributeName, dataSourceType := range attributeToDataSource {
			var matches [][]string

			if attributeName == "workload_groups" || attributeName == "proxy_gateway" {
				// Special pattern for set-style blocks with id and name: capture both
				// Pattern: attribute_name { id = 123 name = "NAME" }
				pattern := fmt.Sprintf(`(?ms)\b%s\s*\{[^}]*?id\s*=\s*(\d+)[^}]*?name\s*=\s*"([^"]+)"[^}]*\}`, regexp.QuoteMeta(attributeName))
				re := regexp.MustCompile(pattern)
				matches = re.FindAllStringSubmatch(fileContent, -1)
			} else if strings.HasSuffix(attributeName, "_id") || strings.HasSuffix(attributeName, "_ids") {
				if strings.HasSuffix(attributeName, "_ids") {
					// Pattern for array ID attributes: attribute_name = ["123", "456"]
					pattern := fmt.Sprintf(`(?m)\b%s\s*=\s*\[([^\]]+)\]`, regexp.QuoteMeta(attributeName))
					re := regexp.MustCompile(pattern)
					matches = re.FindAllStringSubmatch(fileContent, -1)
				} else {
					// Pattern for single-value ID attributes: attribute_name = "123"
					pattern := fmt.Sprintf(`(?m)\b%s\s*=\s*"([^"]+)"`, regexp.QuoteMeta(attributeName))
					re := regexp.MustCompile(pattern)
					matches = re.FindAllStringSubmatch(fileContent, -1)
				}
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

				if attributeName == "workload_groups" || attributeName == "proxy_gateway" {
					// For set-style blocks (workload_groups, proxy_gateway), match[1] is the ID and match[2] is the name
					if len(match) >= 3 {
						id := match[1]
						name := match[2]

						// Skip if already processed or if it's already a resource reference
						if strings.Contains(id, ".") {
							continue // Already a reference
						}

						// Skip if this ID already has a corresponding resource import
						if resourceRef, exists := resourceMap[id]; exists {
							log.Printf("[DEBUG] Skipping %s ID %s - already has resource import: %s", attributeName, id, resourceRef)
							continue
						}

						uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
						if idTracker[uniqueKey] {
							continue // Already collected
						}

						collectedIDs = append(collectedIDs, CollectedDataSourceID{
							DataSourceType: dataSourceType,
							ID:             id,
							UniqueName:     fmt.Sprintf("this_%s", id),
							Name:           name, // Store the name for set-style blocks
						})
						idTracker[uniqueKey] = true
					}
				} else if strings.HasSuffix(attributeName, "_id") {
					if strings.HasSuffix(attributeName, "_ids") {
						// For array ID attributes, match[1] is the array content
						idsContent := match[1]
						ids := extractIDsFromContent(idsContent)

						for _, id := range ids {
							// Skip if already processed or if it's already a resource reference
							if strings.Contains(id, ".") {
								continue // Already a reference
							}

							// Skip if this ID already has a corresponding resource import
							if resourceRef, exists := resourceMap[id]; exists {
								log.Printf("[DEBUG] Skipping %s ID %s - already has resource import: %s", attributeName, id, resourceRef)
								continue
							}

							uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
							if idTracker[uniqueKey] {
								continue // Already collected
							}

							collectedIDs = append(collectedIDs, CollectedDataSourceID{
								DataSourceType: dataSourceType,
								ID:             id,
								UniqueName:     fmt.Sprintf("this_%s", id),
								Name:           "", // Empty for array ID attributes
							})
							idTracker[uniqueKey] = true
						}
					} else {
						// For single-value ID attributes, match[1] is the ID value
						id := match[1]

						// Skip if already processed or if it's already a resource reference
						if strings.Contains(id, ".") {
							continue // Already a reference
						}

						// Skip if this ID already has a corresponding resource import
						if resourceRef, exists := resourceMap[id]; exists {
							log.Printf("[DEBUG] Skipping %s ID %s - already has resource import: %s", attributeName, id, resourceRef)
							continue
						}

						uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
						if idTracker[uniqueKey] {
							continue // Already collected
						}

						collectedIDs = append(collectedIDs, CollectedDataSourceID{
							DataSourceType: dataSourceType,
							ID:             id,
							UniqueName:     fmt.Sprintf("this_%s", id),
							Name:           "", // Empty for single-value attributes
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

						// Skip if this ID already has a corresponding resource import
						if resourceRef, exists := resourceMap[id]; exists {
							log.Printf("[DEBUG] Skipping ID %s for %s - already has resource import: %s", id, dataSourceType, resourceRef)
							continue
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

	if showVerbose {
		log.Printf("📋 Collected %d unique data source IDs", len(collectedIDs))
	}
	return collectedIDs, nil
}

// extractIDsFromContent extracts individual IDs from content like "123, 456" or "123", "456".
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

// GenerateDataSourceFile creates a datasource.tf file with all required data sources.
func GenerateDataSourceFile(workingDir string, dataSourceIDs []CollectedDataSourceID, showVerbose bool) error {
	if len(dataSourceIDs) == 0 {
		return nil
	}

	datasourceFile := filepath.Join(workingDir, "datasource.tf")
	file, err := os.Create(datasourceFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Write header
	_, err = file.WriteString("# Data sources for attribute ID references\n")
	if err != nil {
		return err
	}
	_, err = file.WriteString("# Generated automatically by Zscaler Terraformer\n\n")
	if err != nil {
		return err
	}

	// Data source types that require both id and name attributes
	setStyleDataSources := map[string]bool{
		"zia_workload_groups":    true,
		"ztc_workload_groups":    true,
		"ztc_forwarding_gateway": true,
	}

	// Write each data source
	for _, dsID := range dataSourceIDs {
		var dataSourceBlock string

		if setStyleDataSources[dsID.DataSourceType] && dsID.Name != "" {
			// For set-style data sources, include both id and name (always quote the ID)
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  id   = "%s"
  name = "%s"
}

`, dsID.DataSourceType, dsID.UniqueName, dsID.ID, dsID.Name)
		} else {
			// For other data sources, only include id (always quote the ID)
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  id = "%s"
}

`, dsID.DataSourceType, dsID.UniqueName, dsID.ID)
		}

		_, err = file.WriteString(dataSourceBlock)
		if err != nil {
			return err
		}
	}

	if showVerbose {
		log.Printf("📁 Generated datasource.tf with %d data sources", len(dataSourceIDs))
	}
	return nil
}

// ReplaceDataSourceReferences replaces IDs with data source references in all .tf files.
func ReplaceDataSourceReferences(workingDir string, dataSourceIDs []CollectedDataSourceID, showVerbose bool) error {
	// Create a lookup map: ID -> data source reference (keyed by dataSourceType_id for uniqueness)
	idToReferenceByType := make(map[string]map[string]string) // dataSourceType -> (id -> reference)
	for _, dsID := range dataSourceIDs {
		reference := fmt.Sprintf("data.%s.%s.id", dsID.DataSourceType, dsID.UniqueName)
		if idToReferenceByType[dsID.DataSourceType] == nil {
			idToReferenceByType[dsID.DataSourceType] = make(map[string]string)
		}
		idToReferenceByType[dsID.DataSourceType][dsID.ID] = reference
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Detect provider from filename for context-aware mapping
		providerPrefix := DetectProviderFromFileName(tfFile)

		// Get provider-specific data source mappings and pre-compile regex patterns
		mappings := GetDataSourceMappingsForProvider(providerPrefix)
		attributePatterns := make(map[string]*regexp.Regexp)
		attributeToDataSource := make(map[string]string)

		for _, mapping := range mappings {
			attributeName := mapping.AttributeName
			attributeToDataSource[attributeName] = mapping.DataSourceType

			// Pre-compile regex patterns to avoid recompilation in loops
			pattern := fmt.Sprintf(`(?ms)(\b%s\s*\{[^}]*id\s*=\s*\[)([^\]]+)(\][^}]*\})`, regexp.QuoteMeta(attributeName))
			attributePatterns[attributeName] = regexp.MustCompile(pattern)
		}

		// Build ID to reference map for this provider's data source types
		idToReference := make(map[string]string)
		for _, mapping := range mappings {
			if refs, exists := idToReferenceByType[mapping.DataSourceType]; exists {
				for id, ref := range refs {
					idToReference[id] = ref
				}
			}
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
		content, err := os.ReadFile(tfFile)
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

		// Handle ID attributes (both single-value and array)
		for attributeName, expectedDataSourceType := range attributeToDataSource {
			if strings.HasSuffix(attributeName, "_id") || strings.HasSuffix(attributeName, "_ids") {
				if strings.HasSuffix(attributeName, "_ids") {
					// Pattern for array ID attributes: attribute_name = ["123", "456"]
					pattern := fmt.Sprintf(`(?m)(\b%s\s*=\s*\[)([^\]]+)(\])`, regexp.QuoteMeta(attributeName))
					re := regexp.MustCompile(pattern)

					processedContent = re.ReplaceAllStringFunc(processedContent, func(match string) string {
						submatches := re.FindStringSubmatch(match)
						if len(submatches) < 4 {
							return match
						}

						prefix := submatches[1]
						idsContent := submatches[2]
						suffix := submatches[3]

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
									processedIds = append(processedIds, `"`+id+`"`)
								}
							} else {
								// Keep original ID if no data source reference found
								processedIds = append(processedIds, `"`+id+`"`)
							}
						}

						// Only replace if we actually made changes
						if needsReplacement {
							hasChanges = true
							return prefix + strings.Join(processedIds, ", ") + suffix
						}

						return match
					})
				} else {
					// Pattern for single-value attributes: attribute_name = "123"
					pattern := fmt.Sprintf(`(?m)(\b%s\s*=\s*)"([^"]+)"`, regexp.QuoteMeta(attributeName))
					re := regexp.MustCompile(pattern)

					processedContent = re.ReplaceAllStringFunc(processedContent, func(match string) string {
						submatches := re.FindStringSubmatch(match)
						if len(submatches) < 3 {
							return match
						}

						prefix := submatches[1]
						id := submatches[2]

						// Skip if this is already a data source reference
						if strings.Contains(id, "data.") {
							return match
						}

						// Check if this ID should be replaced with a data source reference
						if reference, exists := idToReference[id]; exists {
							// Ensure the reference matches the expected data source type
							if strings.Contains(reference, expectedDataSourceType) {
								hasChanges = true
								return prefix + reference
							}
						}

						return match // No replacement found
					})
				}
			}
		}

		// Write back the processed content if it changed
		if hasChanges && processedContent != originalContent {
			err = os.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			if showVerbose {
				log.Printf("🔗 Updated data source references in %s", baseName)
			}
		}
	}

	return nil
}

// ReplaceAllReferences replaces IDs with both resource references AND data source references.
// Resource references take priority over data source references.
func ReplaceAllReferences(workingDir string, resourceMap map[string]string, dataSourceIDs []CollectedDataSourceID, showVerbose bool) error {
	// Create lookup maps for both resource references and data source references
	// Resource references: ID -> resourceType.resourceName.id
	// Data source references: ID -> data.dataSourceType.uniqueName.id

	// Data source lookup (from collected IDs)
	dataSourceLookup := make(map[string]string)
	for _, dsID := range dataSourceIDs {
		reference := fmt.Sprintf("data.%s.%s.id", dsID.DataSourceType, dsID.UniqueName)
		dataSourceLookup[dsID.ID] = reference
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Process each .tf file
	for _, tfFile := range tfFiles {
		// Skip special files
		baseName := filepath.Base(tfFile)
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		// Detect provider from filename for context-aware mapping
		providerPrefix := DetectProviderFromFileName(tfFile)

		// Get provider-specific data source mappings
		mappings := GetDataSourceMappingsForProvider(providerPrefix)

		// Build attribute patterns
		attributePatterns := make(map[string]*regexp.Regexp)
		attributeToDataSource := make(map[string]string)

		for _, mapping := range mappings {
			attributeName := mapping.AttributeName
			attributeToDataSource[attributeName] = mapping.DataSourceType

			// Pre-compile regex patterns
			pattern := fmt.Sprintf(`(?ms)(\b%s\s*\{[^}]*id\s*=\s*\[)([^\]]+)(\][^}]*\})`, regexp.QuoteMeta(attributeName))
			attributePatterns[attributeName] = regexp.MustCompile(pattern)
		}

		// Check file size
		fileInfo, err := os.Stat(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to get file info %s: %v", tfFile, err)
			continue
		}

		maxFileSize := int64(10 * 1024 * 1024) // 10MB
		if fileInfo.Size() > maxFileSize {
			log.Printf("[WARNING] Skipping large file %s (%d bytes)", baseName, fileInfo.Size())
			continue
		}

		// Read the file
		content, err := os.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		originalContent := string(content)
		processedContent := originalContent
		hasChanges := false

		// Special handling for set-style attributes like proxy_gateway { id = X name = "Y" }
		setStyleAttributes := map[string]string{
			"proxy_gateway": "ztc_forwarding_gateway",
		}

		for attrName, resourceType := range setStyleAttributes {
			// Pattern: proxy_gateway { id = 12345 name = "Name" }
			setPattern := fmt.Sprintf(`(?ms)(\b%s\s*\{[^}]*?)id\s*=\s*(\d+)([^}]*?)name\s*=\s*"([^"]+)"([^}]*?\})`, regexp.QuoteMeta(attrName))
			setRe := regexp.MustCompile(setPattern)
			setMatches := setRe.FindAllStringSubmatch(processedContent, -1)

			for j := len(setMatches) - 1; j >= 0; j-- {
				setMatch := setMatches[j]
				if len(setMatch) < 6 {
					continue
				}

				fullSetMatch := setMatch[0]
				prefix := setMatch[1]
				id := setMatch[2]
				middle := setMatch[3]
				// name := setMatch[4] // Original name (not used directly)
				suffix := setMatch[5]

				// Check if this ID has a resource import
				if resourceRef, exists := resourceMap[id]; exists {
					if strings.Contains(resourceRef, resourceType) {
						// Extract base reference (remove .id suffix)
						baseRef := strings.TrimSuffix(resourceRef, ".id")
						replacement := prefix + "id   = " + baseRef + ".id" + middle + "name = " + baseRef + ".name" + suffix
						processedContent = strings.Replace(processedContent, fullSetMatch, replacement, 1)
						hasChanges = true
						log.Printf("[DEBUG] Replacing %s ID %s with resource reference: %s", attrName, id, baseRef)
						continue
					}
				}

				// Check if this ID has a data source reference
				if dataSourceRef, exists := dataSourceLookup[id]; exists {
					if strings.Contains(dataSourceRef, resourceType) {
						// Extract base reference (remove .id suffix)
						baseRef := strings.TrimSuffix(dataSourceRef, ".id")
						replacement := prefix + "id   = " + baseRef + ".id" + middle + "name = " + baseRef + ".name" + suffix
						processedContent = strings.Replace(processedContent, fullSetMatch, replacement, 1)
						hasChanges = true
						log.Printf("[DEBUG] Replacing %s ID %s with data source reference: %s", attrName, id, baseRef)
					}
				}
			}
		}

		// Process each attribute
		for attributeName, expectedDataSourceType := range attributeToDataSource {
			re := attributePatterns[attributeName]
			matches := re.FindAllStringSubmatch(processedContent, -1)

			if len(matches) == 0 {
				continue
			}

			// Process matches in reverse order
			for i := len(matches) - 1; i >= 0; i-- {
				match := matches[i]

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
					// Skip if already a reference
					if strings.Contains(id, ".") {
						processedIds = append(processedIds, id)
						continue
					}

					// Priority 1: Check if this ID has a resource import (managed resource)
					if resourceRef, exists := resourceMap[id]; exists {
						// Verify the resource type matches the expected provider context
						if isResourceTypeCompatible(resourceRef, providerPrefix, expectedDataSourceType) {
							processedIds = append(processedIds, resourceRef)
							needsReplacement = true
							log.Printf("[DEBUG] Replacing ID %s with resource reference: %s", id, resourceRef)
							continue
						}
					}

					// Priority 2: Check if this ID has a data source reference
					if dataSourceRef, exists := dataSourceLookup[id]; exists {
						// Verify the data source type matches
						if strings.Contains(dataSourceRef, expectedDataSourceType) {
							processedIds = append(processedIds, dataSourceRef)
							needsReplacement = true
							log.Printf("[DEBUG] Replacing ID %s with data source reference: %s", id, dataSourceRef)
							continue
						}
					}

					// No replacement found, keep original ID
					processedIds = append(processedIds, id)
				}

				// Replace if changes were made
				if needsReplacement {
					replacement := prefix + strings.Join(processedIds, ", ") + suffix
					processedContent = strings.Replace(processedContent, fullMatch, replacement, 1)
					hasChanges = true
				}
			}
		}

		// Write back the processed content if changed
		if hasChanges && processedContent != originalContent {
			err = os.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write file %s: %v", tfFile, err)
				continue
			}
			if showVerbose {
				log.Printf("🔗 Updated references in %s", baseName)
			}
		}
	}

	return nil
}

// isResourceTypeCompatible checks if a resource reference is compatible with the expected provider and data source type.
func isResourceTypeCompatible(resourceRef, providerPrefix, expectedDataSourceType string) bool {
	// Extract resource type from reference (e.g., "ztc_ip_destination_groups.resource_name.id" -> "ztc_ip_destination_groups")
	parts := strings.Split(resourceRef, ".")
	if len(parts) < 1 {
		return false
	}
	resourceType := parts[0]

	// Check if the resource type starts with the same provider prefix
	if providerPrefix != "" && !strings.HasPrefix(resourceType, providerPrefix+"_") {
		return false
	}

	// Map resource types to their corresponding data source types for validation
	resourceToDataSourceMap := map[string]string{
		// ZTC mappings
		"ztc_ip_destination_groups":  "ztc_ip_destination_groups",
		"ztc_ip_source_groups":       "ztc_ip_source_groups",
		"ztc_ip_pool_groups":         "ztc_ip_pool_groups",
		"ztc_network_services":       "ztc_network_services",
		"ztc_network_service_groups": "ztc_network_service_groups",
		"ztc_location_management":    "ztc_location_management",
		"ztc_workload_groups":        "ztc_workload_groups",
		"ztc_forwarding_gateway":     "ztc_forwarding_gateway",

		// ZIA mappings
		"zia_firewall_filtering_destination_groups":     "zia_firewall_filtering_destination_groups",
		"zia_firewall_filtering_ip_source_groups":       "zia_firewall_filtering_ip_source_groups",
		"zia_firewall_filtering_network_service":        "zia_firewall_filtering_network_service",
		"zia_firewall_filtering_network_service_groups": "zia_firewall_filtering_network_service_groups",
		"zia_location_management":                       "zia_location_management",
		"zia_workload_groups":                           "zia_workload_groups",
	}

	// Check if the resource type maps to the expected data source type
	if mappedDataSource, exists := resourceToDataSourceMap[resourceType]; exists {
		return mappedDataSource == expectedDataSourceType
	}

	// If no explicit mapping, check if the resource type matches the expected data source type
	return resourceType == expectedDataSourceType
}
