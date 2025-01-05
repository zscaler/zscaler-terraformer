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

package nesting

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
	"github.com/zclconf/go-cty/cty"
	"github.com/zscaler/zscaler-terraformer/teraformutils/conversion"
	"github.com/zscaler/zscaler-terraformer/teraformutils/helpers"
)

var log = logrus.New()

// nestBlocks takes a schema and generates all of the appropriate nesting of any.
// top-level blocks as well as nested lists or sets.
func NestBlocks(resourceType string, schemaBlock *tfjson.SchemaBlock, structData map[string]interface{}, parentID string, indexedNestedBlocks map[string][]string) string {
	output := ""

	// Nested blocks are used for configuration options where assignment.
	sortedNestedBlocks := make([]string, 0, len(schemaBlock.NestedBlocks))
	for k := range schemaBlock.NestedBlocks {
		sortedNestedBlocks = append(sortedNestedBlocks, k)
	}
	sort.Strings(sortedNestedBlocks)

	for _, block := range sortedNestedBlocks {
		apiBlock := MapTfFieldNameToAPI(resourceType, block)

		// Skip 'applications' block for 'zpa_segment_group' and `zpa_server_group` resource.
		if (resourceType == "zpa_segment_group" || resourceType == "zpa_server_group") && block == "applications" {
			continue // This skips the current iteration of the loop.
		}

		if block == "tcp_port_ranges" || block == "udp_port_ranges" {
			continue
		}

		// Special handling for zia_dlp_web_rules TypeSet blocks.
		if helpers.IsInList(resourceType, []string{"zia_dlp_web_rules"}) && helpers.IsInList(block, []string{
			"notification_template", "auditor", "icap_server",
		}) {
			blockOutput := helpers.TypeSetBlock(block, structData[apiBlock])
			if blockOutput != "" {
				output += blockOutput
			}
			continue
		}

		//Specific handling for zpa_pra_approval_controller resource.
		if resourceType == "zpa_pra_approval_controller" {
			if block == "working_hours" {
				if workingHours, ok := structData["workingHours"].(map[string]interface{}); ok {
					// Collect attribute names for the nested block.
					attributes := make([]string, 0, len(schemaBlock.NestedBlocks[block].Block.Attributes))
					for attrName := range schemaBlock.NestedBlocks[block].Block.Attributes {
						attributes = append(attributes, attrName)
					}
					sort.Strings(attributes)
					output += block + " {\n"
					output += WriteNestedBlock(resourceType, attributes, schemaBlock.NestedBlocks[block].Block, workingHours, parentID)
					// Adding handling for timezone here.
					if timeZone, ok := workingHours["timeZone"]; ok {
						output += fmt.Sprintf("timezone = %q\n", timeZone)
					}
					output += "}\n"
				}
				continue
			}
		}

		// special cases mapping.
		if resourceType == "zia_admin_users" && block == "admin_scope" {
			output += "admin_scope {\n"
			if structData["adminScopeType"] != nil {
				output += "type=\"" + structData["adminScopeType"].(string) + "\"\n"
			}
			if structData["adminScopeScopeEntities"] != nil && len(structData["adminScopeScopeEntities"].([]interface{})) >= 0 {
				output += "scope_entities {\n"
				output += "id = ["
				for i, v := range structData["adminScopeScopeEntities"].([]interface{}) {
					m, ok := v.(map[string]interface{})
					if !ok || m == nil || m["id"] == "" {
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
			if structData["adminScopescopeGroupMemberEntities"] != nil && len(structData["adminScopescopeGroupMemberEntities"].([]interface{})) >= 0 {
				output += "scope_group_member_entities={\n"
				output += "id = ["
				for i, v := range structData["adminScopescopeGroupMemberEntities"].([]interface{}) {
					m, ok := v.(map[string]interface{})
					if !ok || m == nil || m["id"] == "" {
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
			output += "}\n"
			continue
		} else if helpers.IsInList(resourceType, []string{"zia_firewall_filtering_network_service_groups", "zia_firewall_filtering_rule", "zia_url_filtering_rules", "zia_dlp_web_rules"}) && helpers.IsInList(block, []string{"departments",
			"groups",
			"locations",
			"dlp_engines",
			"location_groups",
			"url_categories",
			"users",
			"labels",
			"services",
			"users",
			"override_groups",
			"override_users",
			"device_groups",
			"source_ip_groups",
		}) {
			output += helpers.ListIdsIntBlock(block, structData[MapTfFieldNameToAPI(resourceType, block)])
			continue
		} else if helpers.IsInList(resourceType, []string{"zia_firewall_filtering_rule"}) && helpers.IsInList(block, []string{"dest_ip_groups", "nw_services",
			"departments",
			"groups",
			"time_windows",
			"users",
		}) {
			output += helpers.ListIdsIntBlock(block, structData[MapTfFieldNameToAPI(resourceType, block)])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_application_segment"}) && block == "server_groups" {
			output += helpers.ListIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_application_segment_browser_access"}) && block == "server_groups" {
			output += helpers.ListIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_application_segment_pra"}) {
			if block == "server_groups" {
				output += helpers.ListIdsStringBlock(block, structData["serverGroups"])
			} else if block == "common_apps_dto" {
				output += helpers.ListNestedBlock(block, structData["praApps"])
			}
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_application_segment_inspection"}) {
			if block == "server_groups" {
				output += helpers.ListIdsStringBlock(block, structData["serverGroups"])
			} else if block == "common_apps_dto" {
				output += helpers.ListNestedBlock(block, structData["inspectionApps"])
			}
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_pra_approval_controller"}) && block == "applications" {
			output += helpers.ListIdsStringBlock(block, structData["applications"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_pra_console_controller"}) && block == "pra_portals" {
			output += helpers.ListIdsStringBlock(block, structData["praPortals"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_pra_console_controller"}) && block == "pra_application" {
			output += helpers.TypeSetNestedBlock(block, structData["praApplication"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_server_group", "zpa_policy_access_rule"}) && block == "app_connector_groups" {
			output += helpers.ListIdsStringBlock(block, structData["appConnectorGroups"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_policy_access_rule"}) && block == "app_server_groups" {
			output += helpers.ListIdsStringBlock(block, structData["appServerGroups"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_service_edge_group"}) && helpers.IsInList(block, []string{"service_edges", "trusted_networks"}) {
			output += helpers.ListIdsStringBlock(block, structData[apiBlock])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_server_group", "zpa_segment_group"}) && block == "applications" {
			output += helpers.ListIdsStringBlock(block, structData["applications"])
			continue
		} else if helpers.IsInList(resourceType, []string{"zpa_lss_config_controller"}) && block == "connector_groups" {
			output += helpers.ListIdsStringBlock(block, structData["connectorGroups"])
			continue
		}
		if schemaBlock.NestedBlocks[block].NestingMode == "list" || schemaBlock.NestedBlocks[block].NestingMode == "set" {
			sortedInnerAttributes := make([]string, 0, len(schemaBlock.NestedBlocks[block].Block.Attributes))

			for k := range schemaBlock.NestedBlocks[block].Block.Attributes {
				sortedInnerAttributes = append(sortedInnerAttributes, k)
			}

			sort.Strings(sortedInnerAttributes)

			for attrName, attrConfig := range schemaBlock.NestedBlocks[block].Block.Attributes {
				if attrConfig.Computed && !attrConfig.Optional {
					schemaBlock.NestedBlocks[block].Block.Attributes[attrName].AttributeType = cty.NilType
				}
			}

			nestedBlockOutput := ""
			// If the attribute we're looking at has further nesting, we'll.
			// recursively call nestBlocks.
			if len(schemaBlock.NestedBlocks[block].Block.NestedBlocks) > 0 {
				if s, ok := structData[apiBlock]; ok {
					switch s := s.(type) {
					case map[string]interface{}:
						nestedBlockOutput += NestBlocks(resourceType, schemaBlock.NestedBlocks[block].Block, s, parentID, indexedNestedBlocks)
						indexedNestedBlocks[parentID] = append(indexedNestedBlocks[parentID], nestedBlockOutput)

					case []interface{}:
						for _, nestedItem := range s {
							parentID, exists := nestedItem.(map[string]interface{})["id"]
							if !exists {
								// if we fail to find an ID, we tag the current element with a uuid.
								log.Debugf("id not found for nestedItem %#v using uuid terraform_internal_id", nestedItem)
								parentID = uuid.New().String()
								nestedItem.(map[string]interface{})["terraform_internal_id"] = parentID
							}
							nestedBlockOutput += NestBlocks(resourceType, schemaBlock.NestedBlocks[block].Block, nestedItem.(map[string]interface{}), parentID.(string), indexedNestedBlocks)
							// The indexedNestedBlocks maps helps us know which parent we're rendering the nested block for.
							// So we append the current child's output to it, for when we render it out later.
							indexedNestedBlocks[parentID.(string)] = append(indexedNestedBlocks[parentID.(string)], nestedBlockOutput)
						}
					default:
						log.Debugf("unable to generate recursively nested blocks for %T", s)
					}
				}
			}
			switch attrStruct := structData[apiBlock].(type) {
			// Case for if the inner block's attributes are a map of interfaces, in.
			// which case we can directly add them to the config.
			case map[string]interface{}:
				if attrStruct != nil {
					nestedBlockOutput += WriteNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, attrStruct, parentID)
				}

				if nestedBlockOutput != "" || schemaBlock.NestedBlocks[block].MinItems > 0 {
					output += block + " {\n"
					output += nestedBlockOutput
					output += "}\n"
				}

			// Case for if the inner block's attributes are a list of map interfaces,
			// in which case this should be treated as a duplicating block.
			case []map[string]interface{}:
				for _, v := range attrStruct {
					repeatedBlockOutput := ""

					if attrStruct != nil {
						repeatedBlockOutput = WriteNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v, parentID)
					}

					// Write the block if we had data for it, or if it is a required block.
					if repeatedBlockOutput != "" || schemaBlock.NestedBlocks[block].MinItems > 0 {
						output += block + " {\n"
						output += repeatedBlockOutput

						if nestedBlockOutput != "" {
							output += nestedBlockOutput
						}

						output += "}\n"
					}
				}

			// Case for duplicated blocks that commonly end up as an array or list at.
			// the API level.
			case []interface{}:
				for _, v := range attrStruct {
					repeatedBlockOutput := ""
					if attrStruct != nil {
						repeatedBlockOutput = WriteNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v.(map[string]interface{}), parentID)
					}

					// Write the block if we had data for it, or if it is a required block.
					if repeatedBlockOutput != "" || schemaBlock.NestedBlocks[block].MinItems > 0 {
						output += block + " {\n"
						output += repeatedBlockOutput
						if nestedBlockOutput != "" {
							// We're processing the nested child blocks for currentId.
							currentID, exists := v.(map[string]interface{})["id"].(string)
							if !exists {
								currentID = v.(map[string]interface{})["terraform_internal_id"].(string)
							}
							if len(indexedNestedBlocks[currentID]) > 0 {
								currentNestIdx := len(indexedNestedBlocks[currentID]) - 1
								// Pull out the last nestedblock that we built for this parent.
								// We only need to render the last one because it holds every other all other nested blocks for this parent.
								currentNest := indexedNestedBlocks[currentID][currentNestIdx]

								for ID, nest := range indexedNestedBlocks {
									if ID != currentID && len(nest) > 0 {
										// Itereate over all other indexed nested blocks and remove anything from the current block.
										// that belongs to a different parent.
										currentNest = strings.Replace(currentNest, nest[len(nest)-1], "", 1)
									}
								}
								// currentNest is all that needs to be rendered for this parent.
								// re-index to make sure we capture the removal of the nested blocks that dont.
								// belong to this parent.
								indexedNestedBlocks[currentID][currentNestIdx] = currentNest
								output += currentNest
							}
						}
						output += "}\n"
					}
				}
			default:
				log.Debugf("unexpected attribute struct type %T for block %s", attrStruct, block)
			}
		} else {
			log.Debugf("nested mode %q for %s not recognised", schemaBlock.NestedBlocks[block].NestingMode, block)
		}
	}
	return output
}

func WriteNestedBlock(resourceType string, attributes []string, schemaBlock *tfjson.SchemaBlock, attrStruct map[string]interface{}, _ string) string {
	nestedBlockOutput := ""
	for _, attrName := range attributes {
		apiFieldName := MapTfFieldNameToAPI(resourceType, attrName)
		ty := schemaBlock.Attributes[attrName].AttributeType

		// Exclude specific computed attributes.
		if attrName == "id" || attrName == "appId" || attrName == "portal" || attrName == "hidden" || attrName == "certificate_name" {
			continue
		}

		// Convert attributes to snake_case.
		snakeCaseAttrName := strcase.ToSnake(attrName)

		switch {
		case ty.IsPrimitiveType():
			switch ty {
			case cty.String, cty.Bool, cty.Number:
				nestedBlockOutput += WriteAttrLine(snakeCaseAttrName, attrStruct[apiFieldName], false)
			default:
				log.Debugf("unexpected primitive type %q", ty.FriendlyName())
			}
		case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
			nestedBlockOutput += WriteAttrLine(snakeCaseAttrName, attrStruct[apiFieldName], true)
		default:
			log.Debugf("unexpected nested type %T for %s", ty, attrName)
		}
	}

	return nestedBlockOutput
}

// WriteAttrLine outputs a line of HCL configuration with a configurable depth.
// for known types.
func WriteAttrLine(key string, value interface{}, usedInBlock bool) string {
	// General handling for attributes that are returned as nil.
	if value == nil {
		return ""
	}

	// Handle `dest_countries` and `source_countries` for `zia_firewall_filtering_rule`
	if helpers.IsInList(key, []string{"dest_countries", "source_countries"}) {
		if countryList, ok := value.([]string); ok {
			// Strip the "COUNTRY_" prefix
			for i, country := range countryList {
				countryList[i] = strings.TrimPrefix(country, "COUNTRY_")
			}
			return fmt.Sprintf("%s = [%s]\n", key, formatList(countryList))
		}
	}

	// Handle multiline strings with Heredoc
	if strValue, ok := value.(string); ok {
		if strings.Contains(strValue, "\n") {
			// Use your existing formatHeredoc function
			return fmt.Sprintf("%s = <<EOT\n%sEOT\n", key, helpers.FormatHeredoc(strValue))
		}
		// Use standard string formatting for single-line strings
		return fmt.Sprintf("%s = %q\n", key, strValue)
	}

	if key == "id" {
		// Attempt to convert the value to an integer if it's a float.
		if floatValue, ok := value.(float64); ok {
			// Convert to int64 to handle large IDs, then format as a string.
			return fmt.Sprintf("%s = %d\n", key, int64(floatValue))
		}
	}

	// Special handling for start_time and end_time for zpa_pra_approval_controller.
	if key == "start_time" || key == "end_time" {
		if epochStr, ok := value.(string); ok {
			epoch, err := strconv.ParseInt(epochStr, 10, 64)
			if err == nil {
				return fmt.Sprintf("%s = %q\n", key, conversion.EpochToRFC1123(epoch))
			}
		}
	}

	// Special handling for timezone within working_hours block.
	if key == "timezone" {
		if timeZone, ok := value.(string); ok && timeZone != "" {
			return fmt.Sprintf("%s = %q\n", key, timeZone)
		}
	}

	// Special handling for validity_start_time and validity_end_time.
	if key == "validity_start_time" || key == "validity_end_time" {
		if floatValue, ok := value.(float64); ok {
			return fmt.Sprintf("%s = %q\n", key, conversion.EpochToRFC1123(int64(floatValue)))
		} else if intValue, ok := value.(int); ok {
			return fmt.Sprintf("%s = %q\n", key, conversion.EpochToRFC1123(int64(intValue)))
		}
	}

	switch values := value.(type) {
	case map[string]interface{}:
		sortedKeys := make([]string, 0, len(values))
		for k := range values {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		s := ""
		for _, v := range sortedKeys {
			s += WriteAttrLine(v, values[v], false)
		}

		if usedInBlock {
			if s != "" {
				return fmt.Sprintf("%s {\n%s}\n", key, s)
			}
		} else {
			if s != "" {
				return fmt.Sprintf("%s = {\n%s}\n", key, s)
			}
		}
	case []interface{}:
		var stringItems []string
		var intItems []int
		var interfaceItems []map[string]interface{}

		for _, item := range value.([]interface{}) {
			switch item := item.(type) {
			case string:
				stringItems = append(stringItems, item)
			case map[string]interface{}:
				interfaceItems = append(interfaceItems, item)
			case float64:
				intItems = append(intItems, int(item))
			}
		}
		if len(stringItems) > 0 {
			return WriteAttrLine(key, stringItems, false)
		}

		if len(intItems) > 0 {
			return WriteAttrLine(key, intItems, false)
		}

		if len(interfaceItems) > 0 {
			return WriteAttrLine(key, interfaceItems, false)
		}

	case []map[string]interface{}:
		var stringyInterfaces []string
		var op string
		var mapLen = len(value.([]map[string]interface{}))
		for i, item := range value.([]map[string]interface{}) {
			// Use an empty key to prevent rendering the key.
			op = WriteAttrLine("", item, true)
			// if condition handles adding new line for just the last element.
			if i != mapLen-1 {
				op = strings.TrimRight(op, "\n")
			}
			stringyInterfaces = append(stringyInterfaces, op)
		}
		return fmt.Sprintf("%s = [ \n%s ]\n", key, strings.Join(stringyInterfaces, ",\n"))

	case []int:
		stringyInts := []string{}
		for _, int := range value.([]int) {
			stringyInts = append(stringyInts, fmt.Sprintf("%d", int))
		}
		return fmt.Sprintf("%s = [ %s ]\n", key, strings.Join(stringyInts, ", "))
	case []string:
		var items []string
		for _, item := range value.([]string) {
			items = append(items, fmt.Sprintf("%q", item))
		}
		if len(items) > 0 {
			return fmt.Sprintf("%s = [ %s ]\n", key, strings.Join(items, ", "))
		}
	case string:
		if value != "" {
			return fmt.Sprintf("%s = %q\n", key, value)
		}
	case int:
		return fmt.Sprintf("%s = %d\n", key, value)
	case float64:
		return fmt.Sprintf("%s = %v\n", key, value)
	case bool:
		return fmt.Sprintf("%s = %t\n", key, value)
	default:
		log.Debugf("got unknown attribute configuration: key %s, value %v, value type %T", key, value, value)
		return ""
	}
	return ""
}

// Probably can be deprecated. Need to evaluate.
func MapTfFieldNameToAPI(resourceType, fieldName string) string {
	switch resourceType {
	case "zia_admin_users":
		switch fieldName {
		case "username":
			return "userName"
		}
	}
	result := strcase.ToLowerCamel(fieldName)
	return result
}

// Helper function to format a list of strings for HCL
func formatList(items []string) string {
	quotedItems := make([]string, len(items))
	for i, item := range items {
		quotedItems[i] = fmt.Sprintf("%q", item)
	}
	return strings.Join(quotedItems, ", ")
}
