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
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ZPAPolicyOperandMapping defines how ZPA policy operand fields map to data sources based on object_type
type ZPAPolicyOperandMapping struct {
	ObjectType    string            // e.g., "SCIM", "SAML", "POSTURE"
	FieldMappings map[string]string // e.g., "idp_id" -> "zpa_idp_controller"
}

// GetZPAPolicyMappings returns the mapping configuration for ZPA policy operands
func GetZPAPolicyMappings() []ZPAPolicyOperandMapping {
	return []ZPAPolicyOperandMapping{
		{
			ObjectType: "SCIM",
			FieldMappings: map[string]string{
				"idp_id": "zpa_idp_controller",
				"lhs":    "zpa_scim_attribute_header",
			},
		},
		{
			ObjectType: "SCIM_GROUP",
			FieldMappings: map[string]string{
				"idp_id": "zpa_idp_controller",
				"lhs":    "zpa_idp_controller",
				"rhs":    "zpa_scim_groups",
			},
		},
		{
			ObjectType: "SAML",
			FieldMappings: map[string]string{
				"idp_id": "zpa_idp_controller",
				"lhs":    "zpa_saml_attribute",           // Query by id, export id
				"name":   "zpa_saml_attribute@name.name", // Query by name, export name (@ indicates query field)
			},
		},
		{
			ObjectType: "POSTURE",
			FieldMappings: map[string]string{
				"lhs": "zpa_posture_profile.posture_udid", // Query by id, export posture_udid
			},
		},
		{
			ObjectType: "TRUSTED_NETWORK",
			FieldMappings: map[string]string{
				"lhs": "zpa_trusted_network.network_id", // Query by id, export network_id
			},
		},
		{
			ObjectType: "MACHINE_GRP",
			FieldMappings: map[string]string{
				"rhs": "zpa_machine_group",
			},
		},
	}
}

// ZPACollectedDataSource represents a ZPA data source that needs to be created
type ZPACollectedDataSource struct {
	DataSourceType  string
	ID              string
	UniqueName      string
	QueryFieldName  string // Field used to query the data source (usually "id")
	ExportFieldName string // Field to export from the data source (e.g., "posture_udid", "network_id")
	RequiresIDPName bool   // True if this data source requires idp_name parameter
	IDPControllerID string // The IDP controller ID to reference for idp_name
}

// PostProcessZPAPolicyDataSources processes ZPA policy data source references
func PostProcessZPAPolicyDataSources(workingDir string, resourceMap map[string]string) error {
	log.Printf("🔄 Starting ZPA policy data source processing...")

	// Step 1: Collect ZPA policy data source IDs
	log.Printf("[DEBUG] Collecting ZPA policy data source IDs...")
	zpaDataSources, err := CollectZPAPolicyDataSourceIDs(workingDir, resourceMap)
	if err != nil {
		return fmt.Errorf("failed to collect ZPA policy data source IDs: %w", err)
	}

	if len(zpaDataSources) == 0 {
		log.Printf("[INFO] No ZPA policy data source IDs found to process")
		return nil
	}

	// Step 2: Generate ZPA data sources in datasource.tf
	log.Printf("[DEBUG] Generating ZPA data sources...")
	err = AppendZPADataSources(workingDir, zpaDataSources)
	if err != nil {
		return fmt.Errorf("failed to generate ZPA data sources: %w", err)
	}

	// Step 3: Replace IDs with data source references
	log.Printf("[DEBUG] Replacing ZPA policy data source references...")
	err = ReplaceZPAPolicyReferences(workingDir, zpaDataSources)
	if err != nil {
		return fmt.Errorf("failed to replace ZPA policy references: %w", err)
	}

	log.Printf("🎯 ZPA policy data source processing completed successfully")
	return nil
}

// CollectZPAPolicyDataSourceIDs scans ZPA policy files and collects operand IDs that need data source references
func CollectZPAPolicyDataSourceIDs(workingDir string, resourceMap map[string]string) ([]ZPACollectedDataSource, error) {
	var collectedDataSources []ZPACollectedDataSource
	idTracker := make(map[string]bool)

	// Get ZPA policy resource types
	zpaResourceTypes := []string{
		"zpa_policy_access_rule",
		"zpa_policy_timeout_rule",
		"zpa_policy_forwarding_rule",
		"zpa_policy_inspection_rule",
		"zpa_policy_isolation_rule",
	}

	// Get ZPA policy mappings
	mappings := GetZPAPolicyMappings()

	// Process each ZPA policy resource file
	for _, resourceType := range zpaResourceTypes {
		tfFile := filepath.Join(workingDir, resourceType+".tf")

		// Check if file exists
		if _, err := os.Stat(tfFile); os.IsNotExist(err) {
			continue // Skip if file doesn't exist
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read file %s: %v", tfFile, err)
			continue
		}

		fileContent := string(content)

		// Process each mapping configuration
		for _, mapping := range mappings {
			// Find operands blocks with the specific object_type
			operandPattern := fmt.Sprintf(`(?ms)operands\s*\{[^}]*?object_type\s*=\s*"%s"[^}]*?\}`, mapping.ObjectType)
			operandRe := regexp.MustCompile(operandPattern)

			operandMatches := operandRe.FindAllString(fileContent, -1)

			for _, operandBlock := range operandMatches {
				// Extract idp_id if present (needed for data sources that require idp_name)
				idpIDPattern := `idp_id\s*=\s*"([^"]+)"`
				idpIDRe := regexp.MustCompile(idpIDPattern)
				idpIDMatches := idpIDRe.FindStringSubmatch(operandBlock)
				var idpControllerID string
				if len(idpIDMatches) >= 2 {
					idpControllerID = idpIDMatches[1]
				}

				// For each field mapping, extract the ID
				for fieldName, dataSourceType := range mapping.FieldMappings {
					// Extract the field value
					fieldPattern := fmt.Sprintf(`%s\s*=\s*"([^"]+)"`, fieldName)
					fieldRe := regexp.MustCompile(fieldPattern)

					fieldMatches := fieldRe.FindStringSubmatch(operandBlock)
					if len(fieldMatches) >= 2 {
						id := fieldMatches[1]

						// Skip if already processed or if it's already a resource reference
						if strings.Contains(id, ".") {
							continue
						}

						// Skip if this ID already has a corresponding resource import
						if resourceRef, exists := resourceMap[id]; exists {
							log.Printf("[DEBUG] Skipping ZPA policy ID %s for %s - already has resource import: %s", id, dataSourceType, resourceRef)
							continue
						}

						// Determine the field name for special cases
						var dsFieldName string
						var exportFieldName string

						if strings.Contains(dataSourceType, "@") {
							// Handle special syntax like "zpa_saml_attribute@name.name"
							// Format: dataSourceType@queryField.exportField
							parts := strings.Split(dataSourceType, "@")
							dataSourceType = parts[0]
							fieldParts := strings.Split(parts[1], ".")
							dsFieldName = fieldParts[0]     // Query field (e.g., "name")
							exportFieldName = fieldParts[1] // Export field (e.g., "name")
						} else if strings.Contains(dataSourceType, ".") {
							// Handle special cases like "zpa_posture_profile.posture_udid"
							parts := strings.Split(dataSourceType, ".")
							dataSourceType = parts[0]
							exportFieldName = parts[1] // Field to export from the data source
							dsFieldName = "id"         // Always query by id
						} else {
							dsFieldName = "id"     // Default field
							exportFieldName = "id" // Default export field
						}

						// Determine if this data source requires idp_name
						requiresIDPName := dataSourceType == "zpa_scim_groups" ||
							dataSourceType == "zpa_scim_attribute_header" ||
							dataSourceType == "zpa_saml_attribute"

						// For data sources that can be referenced by multiple fields (like SAML lhs and name),
						// use only the data source type and ID for uniqueness, not the field
						uniqueKey := fmt.Sprintf("%s_%s", dataSourceType, id)
						if idTracker[uniqueKey] {
							continue // Already collected
						}

						// Clean the ID for use in Terraform resource names (remove invalid characters)
						cleanID := strings.ReplaceAll(id, "-", "_")
						cleanID = strings.ReplaceAll(cleanID, ".", "_")
						cleanID = strings.ReplaceAll(cleanID, "@", "_")

						collectedDataSources = append(collectedDataSources, ZPACollectedDataSource{
							DataSourceType:  dataSourceType,
							ID:              id,
							UniqueName:      fmt.Sprintf("this_%s", cleanID),
							QueryFieldName:  dsFieldName,
							ExportFieldName: exportFieldName,
							RequiresIDPName: requiresIDPName,
							IDPControllerID: idpControllerID,
						})
						idTracker[uniqueKey] = true
					}
				}
			}
		}
	}

	log.Printf("📋 Collected %d unique ZPA policy data source IDs", len(collectedDataSources))
	return collectedDataSources, nil
}

// AppendZPADataSources appends ZPA data sources to the existing datasource.tf file
func AppendZPADataSources(workingDir string, zpaDataSources []ZPACollectedDataSource) error {
	if len(zpaDataSources) == 0 {
		return nil
	}

	datasourceFile := filepath.Join(workingDir, "datasource.tf")

	// Open file in append mode or create if it doesn't exist
	file, err := os.OpenFile(datasourceFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Add header if this is the first ZPA data source
	_, err = file.WriteString("\n# ZPA Policy Data Sources\n")
	if err != nil {
		return err
	}

	// Separate data sources into IDP controllers and dependent data sources
	var idpControllers []ZPACollectedDataSource
	var dependentDataSources []ZPACollectedDataSource

	for _, zpaDsID := range zpaDataSources {
		if zpaDsID.DataSourceType == "zpa_idp_controller" {
			idpControllers = append(idpControllers, zpaDsID)
		} else {
			dependentDataSources = append(dependentDataSources, zpaDsID)
		}
	}

	// Write IDP controllers first (these are referenced by dependent data sources)
	for _, zpaDsID := range idpControllers {
		dataSourceBlock := fmt.Sprintf(`data "%s" "%s" {
  id = "%s"
}

`, zpaDsID.DataSourceType, zpaDsID.UniqueName, zpaDsID.ID)

		_, err = file.WriteString(dataSourceBlock)
		if err != nil {
			return err
		}
	}

	// Write dependent data sources with idp_name references where needed
	for _, zpaDsID := range dependentDataSources {
		var dataSourceBlock string

		if zpaDsID.RequiresIDPName && zpaDsID.IDPControllerID != "" {
			// Data source requires idp_name parameter - use the appropriate query field
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  %-8s = "%s"
  idp_name = data.zpa_idp_controller.this_%s.name
}

`, zpaDsID.DataSourceType, zpaDsID.UniqueName, zpaDsID.QueryFieldName, zpaDsID.ID, zpaDsID.IDPControllerID)
		} else {
			// Standard data source without idp_name - use the appropriate query field
			dataSourceBlock = fmt.Sprintf(`data "%s" "%s" {
  %s = "%s"
}

`, zpaDsID.DataSourceType, zpaDsID.UniqueName, zpaDsID.QueryFieldName, zpaDsID.ID)
		}

		_, err = file.WriteString(dataSourceBlock)
		if err != nil {
			return err
		}
	}

	log.Printf("📁 Appended %d ZPA data sources to datasource.tf", len(zpaDataSources))
	return nil
}

// ReplaceZPAPolicyReferences replaces ZPA policy operand IDs with data source references
func ReplaceZPAPolicyReferences(workingDir string, zpaDataSources []ZPACollectedDataSource) error {
	// Create lookup maps for replacements
	idToReference := make(map[string]map[string]string) // objectType -> fieldName -> reference

	for _, zpaDsID := range zpaDataSources {
		// Always reference the export field (id, posture_udid, network_id, etc.)
		reference := fmt.Sprintf("data.%s.%s.%s", zpaDsID.DataSourceType, zpaDsID.UniqueName, zpaDsID.ExportFieldName)

		// We need to map this back to object_type and field for replacement
		// This is a reverse lookup based on our mapping configuration
		mappings := GetZPAPolicyMappings()
		for _, mapping := range mappings {
			for fieldName, dataSourceType := range mapping.FieldMappings {
				// Handle special cases with field specifiers
				dsType := dataSourceType
				if strings.Contains(dataSourceType, "@") {
					dsType = strings.Split(dataSourceType, "@")[0]
				} else if strings.Contains(dataSourceType, ".") {
					dsType = strings.Split(dataSourceType, ".")[0]
				}

				if dsType == zpaDsID.DataSourceType {
					if idToReference[mapping.ObjectType] == nil {
						idToReference[mapping.ObjectType] = make(map[string]string)
					}
					// Use the original ID (not cleaned) for lookup key matching
					idToReference[mapping.ObjectType][fieldName+"_"+zpaDsID.ID] = reference
				}
			}
		}
	}

	// Get ZPA policy resource types
	zpaResourceTypes := []string{
		"zpa_policy_access_rule",
		"zpa_policy_timeout_rule",
		"zpa_policy_forwarding_rule",
		"zpa_policy_inspection_rule",
		"zpa_policy_isolation_rule",
	}

	// Process each ZPA policy file
	for _, resourceType := range zpaResourceTypes {
		tfFile := filepath.Join(workingDir, resourceType+".tf")

		// Check if file exists
		if _, err := os.Stat(tfFile); os.IsNotExist(err) {
			continue
		}

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			log.Printf("[WARNING] Failed to read ZPA policy file %s: %v", tfFile, err)
			continue
		}

		originalContent := string(content)
		processedContent := originalContent
		hasChanges := false

		// Process each object type mapping
		mappings := GetZPAPolicyMappings()
		for _, mapping := range mappings {
			// Find and replace operands with the specific object_type
			operandPattern := fmt.Sprintf(`(?ms)(operands\s*\{[^}]*?object_type\s*=\s*"%s"[^}]*?)(\})`, mapping.ObjectType)
			operandRe := regexp.MustCompile(operandPattern)

			processedContent = operandRe.ReplaceAllStringFunc(processedContent, func(match string) string {
				submatches := operandRe.FindStringSubmatch(match)
				if len(submatches) < 3 {
					return match
				}

				operandContent := submatches[1]
				suffix := submatches[2]

				// Replace each mapped field
				for fieldName := range mapping.FieldMappings {
					fieldPattern := fmt.Sprintf(`(%s\s*=\s*)"([^"]+)"`, fieldName)
					fieldRe := regexp.MustCompile(fieldPattern)

					operandContent = fieldRe.ReplaceAllStringFunc(operandContent, func(fieldMatch string) string {
						fieldSubmatches := fieldRe.FindStringSubmatch(fieldMatch)
						if len(fieldSubmatches) < 3 {
							return fieldMatch
						}

						fieldPrefix := fieldSubmatches[1]
						id := fieldSubmatches[2]

						// Look up the replacement
						if objTypeMap, exists := idToReference[mapping.ObjectType]; exists {
							if reference, exists := objTypeMap[fieldName+"_"+id]; exists {
								hasChanges = true
								return fieldPrefix + reference
							}
						}

						return fieldMatch // No replacement found
					})
				}

				return operandContent + suffix
			})
		}

		// Write back the processed content if it changed
		if hasChanges && processedContent != originalContent {
			err = ioutil.WriteFile(tfFile, []byte(processedContent), 0644)
			if err != nil {
				log.Printf("[WARNING] Failed to write ZPA policy file %s: %v", tfFile, err)
				continue
			}
			log.Printf("🔗 Updated ZPA policy references in %s", filepath.Base(tfFile))
		}
	}

	return nil
}
