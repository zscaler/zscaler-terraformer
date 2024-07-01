package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
	ziaServices "github.com/zscaler/zscaler-sdk-go/v2/zia/services"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/usermanagement/users"
	zpaServices "github.com/zscaler/zscaler-sdk-go/v2/zpa/services"

	"github.com/google/uuid"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
	"github.com/zscaler/zscaler-sdk-go/v2/zia"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa"
)

func executeCommandC(root *cobra.Command, args ...string) (c *cobra.Command, output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	c, err = root.ExecuteC()

	return c, buf.String(), err
}

// testDataFile slurps a local test case into memory and returns it while
// encapsulating the logic for finding it.
func testDataFile(filename, cloudType string) string {
	filename = strings.TrimSuffix(filename, "/")

	dirname, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	dir, err := os.Open(filepath.Join(dirname, "../../../../testdata/terraform/"+cloudType))
	if err != nil {
		panic(err)
	}

	fullpath := dir.Name() + "/" + filename + "/test.tf"
	if _, err := os.Stat(fullpath); os.IsNotExist(err) {
		panic(fmt.Errorf("terraform testdata file does not exist at %s", fullpath))
	}

	data, _ := ioutil.ReadFile(fullpath)

	return string(data)
}

func sharedPreRun(cmd *cobra.Command, args []string) {
	// Don't initialise a client in CI as this messes with VCR and the ability to
	// mock out the HTTP interactions.
	if os.Getenv("CI") != "true" {
		if strings.HasPrefix(resourceType_, "zpa_") || strings.Contains(resources, "zpa_") || resources == "*" || resources == "zpa" {
			// init zpa
			zpa_cloud = viper.GetString("zpa_cloud")
			if zpa_client_id = viper.GetString("zpa_client_id"); zpa_client_id == "" {
				log.Fatal("'zpa_client_id' must be set.")
			}
			if zpa_client_secret = viper.GetString("zpa_client_secret"); zpa_client_secret == "" {
				log.Fatal("'zpa_client_secret' must be set.")
			}
			if zpa_customer_id = viper.GetString("zpa_customer_id"); zpa_customer_id == "" {
				log.Fatal("'zpa_customer_id' must be set.")
			}

			log.WithFields(logrus.Fields{
				"zpa_client_id":   zpa_client_id,
				"zpa_customer_id": "zpa_customer_id",
				"zpa_cloud":       "zpa_cloud",
			}).Debug("initializing zscaler-sdk-go[ZPA]")
		}
		if strings.HasPrefix(resourceType_, "zia_") || strings.Contains(resources, "zia_") || resources == "*" || resources == "zia" {
			// init zia
			zia_cloud = viper.GetString("zia_cloud")
			if zia_username = viper.GetString("zia_username"); zia_username == "" {
				log.Fatal("'zia_username' must be set.")
			}
			if zia_password = viper.GetString("zia_password"); zia_password == "" {
				log.Fatal("'zia_password' must be set.")
			}
			if zia_api_key = viper.GetString("zia_api_key"); zia_api_key == "" {
				log.Fatal("'zia_api_key' must be set.")
			}

			log.WithFields(logrus.Fields{
				"zia_username": zia_username,
				"zia_cloud":    "zia_cloud",
			}).Debug("initializing zscaler-sdk-go[ZIA]")
		}
		api = &Client{}
		if strings.HasPrefix(resourceType_, "zpa_") || strings.Contains(resources, "zpa_") || resources == "*" || resources == "zpa" {
			zpaConfig, err := zpa.NewConfig(zpa_client_id, zpa_client_secret, zpa_customer_id, zpa_cloud, "zscaler-terraformer")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zpa)", err)
			}
			zpaClient := zpa.NewClient(zpaConfig)
			api.zpa = &ZPAClient{
				appconnectorgroup:              zpaServices.New(zpaClient),
				applicationsegment:             zpaServices.New(zpaClient),
				applicationsegmentinspection:   zpaServices.New(zpaClient),
				applicationsegmentpra:          zpaServices.New(zpaClient),
				appservercontroller:            zpaServices.New(zpaClient),
				browseraccess:                  zpaServices.New(zpaClient),
				bacertificate:                  zpaServices.New(zpaClient),
				lssconfigcontroller:            zpaServices.New(zpaClient),
				policysetcontroller:            zpaServices.New(zpaClient),
				policysetcontrollerv2:          zpaServices.New(zpaClient),
				pracredential:                  zpaServices.New(zpaClient),
				praportal:                      zpaServices.New(zpaClient),
				provisioningkey:                zpaServices.New(zpaClient),
				segmentgroup:                   zpaServices.New(zpaClient),
				servergroup:                    zpaServices.New(zpaClient),
				serviceedgegroup:               zpaServices.New(zpaClient),
				inspection_custom_controls:     zpaServices.New(zpaClient),
				inspection_predefined_controls: zpaServices.New(zpaClient),
				inspection_profile:             zpaServices.New(zpaClient),
				microtenants:                   zpaServices.New(zpaClient),
			}
		}
		if strings.HasPrefix(resourceType_, "zia_") || strings.Contains(resources, "zia_") || resources == "*" || resources == "zia" {
			// init zia
			ziaClient, err := zia.NewClient(zia_username, zia_password, zia_api_key, zia_cloud, "zscaler-terraformer")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zia)", err)
			}
			api.zia = &ZIAClient{
				admins:                       ziaServices.New(ziaClient),
				filteringrules:               ziaServices.New(ziaClient),
				ipdestinationgroups:          ziaServices.New(ziaClient),
				ipsourcegroups:               ziaServices.New(ziaClient),
				networkapplicationgroups:     ziaServices.New(ziaClient),
				networkservicegroups:         ziaServices.New(ziaClient),
				networkservices:              ziaServices.New(ziaClient),
				urlcategories:                ziaServices.New(ziaClient),
				urlfilteringpolicies:         ziaServices.New(ziaClient),
				users:                        users.New(ziaClient),
				vpncredentials:               ziaServices.New(ziaClient),
				gretunnels:                   ziaServices.New(ziaClient),
				staticips:                    ziaServices.New(ziaClient),
				locationmanagement:           ziaServices.New(ziaClient),
				dlpdictionaries:              ziaServices.New(ziaClient),
				dlp_engines:                  ziaServices.New(ziaClient),
				dlp_notification_templates:   ziaServices.New(ziaClient),
				dlp_web_rules:                ziaServices.New(ziaClient),
				rule_labels:                  ziaServices.New(ziaClient),
				security_policy_settings:     ziaServices.New(ziaClient),
				sandbox_settings:             ziaServices.New(ziaClient),
				user_authentication_settings: ziaServices.New(ziaClient),
				forwarding_rules:             ziaServices.New(ziaClient),
				zpa_gateways:                 zpa_gateways.New(ziaClient),
			}
		}
	}
}

func epochToRFC1123(epoch int64) string {
	t := time.Unix(epoch, 0).UTC()
	return t.Format(time.RFC1123)
}

func isInList(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

func listIdsIntBlockIDExtentionsSingle(fieldName string, obj interface{}) string {
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

func listIdsIntBlock(fieldName string, obj interface{}) string {
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

func listIdsStringBlock(fieldName string, obj interface{}) string {
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

// / Custom function to Removes attributes from ZPA StateFile
func removeTcpPortRangesFromState(stateFile string) {
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

	// Traverse the state file structure to remove tcp_port_ranges
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

			// Remove the tcp_port_ranges and udp_port_ranges attribute
			delete(attributes, "tcp_port_ranges")
			delete(attributes, "udp_port_ranges")
		}
	}

	// Marshal the modified state back to JSON
	modifiedStateData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal modified state file: %s", err)
	}

	// Write the modified state back to the file
	if err := ioutil.WriteFile(stateFile, modifiedStateData, 0644); err != nil {
		log.Fatalf("failed to write modified state file: %s", err)
	}
}

// / Custom function to manipulate generate and import of ZPA application segments
func listNestedBlock(fieldName string, obj interface{}) string {
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
				if isComputedAttribute(snakeKey) {
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

				// Inject app_types based on application_protocol
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

// / Remove computed from ZPA Application Segments
func isComputedAttribute(attr string) bool {
	computedAttributes := []string{"portal", "app_id", "hidden", "id", "certificate_name"}
	for _, computed := range computedAttributes {
		if attr == computed {
			return true
		}
	}
	return false
}

// nestBlocks takes a schema and generates all of the appropriate nesting of any
// top-level blocks as well as nested lists or sets.
func nestBlocks(resourceType string, schemaBlock *tfjson.SchemaBlock, structData map[string]interface{}, parentID string, indexedNestedBlocks map[string][]string) string {
	output := ""

	// Nested blocks are used for configuration options where assignment
	// isn't required.
	sortedNestedBlocks := make([]string, 0, len(schemaBlock.NestedBlocks))
	for k := range schemaBlock.NestedBlocks {
		sortedNestedBlocks = append(sortedNestedBlocks, k)
	}
	sort.Strings(sortedNestedBlocks)

	for _, block := range sortedNestedBlocks {
		apiBlock := mapTfFieldNameToApi(resourceType, block)

		// Skip 'applications' block for 'zpa_segment_group' resource
		if (resourceType == "zpa_segment_group" || resourceType == "zpa_server_group") && block == "applications" {
			continue // This skips the current iteration of the loop
		}

		if block == "tcp_port_ranges" {
			continue
		}
		if block == "udp_port_ranges" {
			continue
		}
		// special cases mapping
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
		} else if isInList(resourceType, []string{"zia_firewall_filtering_network_service_groups", "zia_firewall_filtering_rule", "zia_url_filtering_rules", "zia_dlp_web_rules"}) && isInList(block, []string{"departments",
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
			output += listIdsIntBlock(block, structData[mapTfFieldNameToApi(resourceType, block)])
			continue
		} else if isInList(resourceType, []string{"zia_dlp_web_rules"}) && isInList(block, []string{
			"notification_template",
		}) {
			output += listIdsIntBlockIDExtentionsSingle(block, structData[mapTfFieldNameToApi(resourceType, block)])
			continue
		} else if isInList(resourceType, []string{"zia_firewall_filtering_rule"}) && isInList(block, []string{"dest_ip_groups", "nw_services",
			"departments",
			"groups",
			"time_windows",
			"users",
		}) {
			output += listIdsIntBlock(block, structData[mapTfFieldNameToApi(resourceType, block)])
			continue

		} else if isInList(resourceType, []string{"zpa_application_segment"}) && block == "server_groups" {
			output += listIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_application_segment_browser_access"}) && block == "server_groups" {
			output += listIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_application_segment_pra"}) {
			if block == "server_groups" {
				output += listIdsStringBlock(block, structData["serverGroups"])
			} else if block == "common_apps_dto" {
				output += listNestedBlock(block, structData["praApps"])
			}
			continue
		} else if isInList(resourceType, []string{"zpa_application_segment_inspection"}) {
			if block == "server_groups" {
				output += listIdsStringBlock(block, structData["serverGroups"])
			} else if block == "common_apps_dto" {
				output += listNestedBlock(block, structData["inspectionApps"])
			}
			continue
		} else if isInList(resourceType, []string{"zpa_server_group", "zpa_policy_access_rule"}) && block == "app_connector_groups" {
			output += listIdsStringBlock(block, structData["appConnectorGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_service_edge_group"}) && isInList(block, []string{"service_edges", "trusted_networks"}) {
			output += listIdsStringBlock(block, structData[apiBlock])
			continue
		} else if isInList(resourceType, []string{"zpa_server_group", "zpa_segment_group"}) && block == "applications" {
			output += listIdsStringBlock(block, structData["applications"])
			continue
		} else if isInList(resourceType, []string{"zpa_policy_access_rule"}) && block == "app_server_groups" {
			output += listIdsStringBlock(block, structData["appServerGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_inspection_custom_controls"}) && block == "associated_inspection_profile_names" {
			output += listIdsStringBlock(block, structData["associatedInspectionProfileNames"])
			continue
		} else if isInList(resourceType, []string{"zpa_lss_config_controller"}) && block == "connector_groups" {
			output += listIdsStringBlock(block, structData["connectorGroups"])
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

			// If the attribute we're looking at has further nesting, we'll
			// recursively call nestBlocks.
			if len(schemaBlock.NestedBlocks[block].Block.NestedBlocks) > 0 {
				if s, ok := structData[apiBlock]; ok {

					switch s := s.(type) {
					case map[string]interface{}:
						nestedBlockOutput += nestBlocks(resourceType, schemaBlock.NestedBlocks[block].Block, s, parentID, indexedNestedBlocks)
						indexedNestedBlocks[parentID] = append(indexedNestedBlocks[parentID], nestedBlockOutput)

					case []interface{}:
						for _, nestedItem := range s {
							parentID, exists := nestedItem.(map[string]interface{})["id"]
							if !exists {
								// if we fail to find an ID, we tag the current element with a uuid
								log.Debugf("id not found for nestedItem %#v using uuid terraform_internal_id", nestedItem)
								parentID = uuid.New().String()
								nestedItem.(map[string]interface{})["terraform_internal_id"] = parentID
							}

							nestedBlockOutput += nestBlocks(resourceType, schemaBlock.NestedBlocks[block].Block, nestedItem.(map[string]interface{}), parentID.(string), indexedNestedBlocks)
							// The indexedNestedBlocks maps helps us know which parent we're rendering the nested block for
							// So we append the current child's output to it, for when we render it out later
							indexedNestedBlocks[parentID.(string)] = append(indexedNestedBlocks[parentID.(string)], nestedBlockOutput)
						}

					default:
						log.Debugf("unable to generate recursively nested blocks for %T", s)
					}

				}
			}

			switch attrStruct := structData[apiBlock].(type) {

			// Case for if the inner block's attributes are a map of interfaces, in
			// which case we can directly add them to the config.
			case map[string]interface{}:
				if attrStruct != nil {
					nestedBlockOutput += writeNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, attrStruct, parentID)
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
						repeatedBlockOutput = writeNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v, parentID)
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

			// Case for duplicated blocks that commonly end up as an array or list at
			// the API level.
			case []interface{}:
				for _, v := range attrStruct {
					repeatedBlockOutput := ""
					if attrStruct != nil {
						repeatedBlockOutput = writeNestedBlock(resourceType, sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v.(map[string]interface{}), parentID)
					}

					// Write the block if we had data for it, or if it is a required block.
					if repeatedBlockOutput != "" || schemaBlock.NestedBlocks[block].MinItems > 0 {
						output += block + " {\n"
						output += repeatedBlockOutput
						if nestedBlockOutput != "" {
							// We're processing the nested child blocks for currentId
							currentID, exists := v.(map[string]interface{})["id"].(string)
							if !exists {
								currentID = v.(map[string]interface{})["terraform_internal_id"].(string)
							}

							if len(indexedNestedBlocks[currentID]) > 0 {

								currentNestIdx := len(indexedNestedBlocks[currentID]) - 1
								// Pull out the last nestedblock that we built for this parent
								// We only need to render the last one because it holds every other all other nested blocks for this parent
								currentNest := indexedNestedBlocks[currentID][currentNestIdx]

								for ID, nest := range indexedNestedBlocks {
									if ID != currentID && len(nest) > 0 {
										// Itereate over all other indexed nested blocks and remove anything from the current block
										// that belongs to a different parent
										currentNest = strings.Replace(currentNest, nest[len(nest)-1], "", 1)
									}
								}
								// currentNest is all that needs to be rendered for this parent
								// re-index to make sure we capture the removal of the nested blocks that dont
								// belong to this parent
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

func writeNestedBlock(resourceType string, attributes []string, schemaBlock *tfjson.SchemaBlock, attrStruct map[string]interface{}, parentID string) string {
	nestedBlockOutput := ""

	for _, attrName := range attributes {
		apiFieldName := mapTfFieldNameToApi(resourceType, attrName)
		ty := schemaBlock.Attributes[attrName].AttributeType

		// Exclude specific computed attributes
		if attrName == "id" || attrName == "appId" || attrName == "portal" || attrName == "hidden" || attrName == "certificate_name" {
			continue
		}

		// Convert attributes to snake_case
		snakeCaseAttrName := strcase.ToSnake(attrName)

		switch {
		case ty.IsPrimitiveType():
			switch ty {
			case cty.String, cty.Bool, cty.Number:
				nestedBlockOutput += writeAttrLine(snakeCaseAttrName, attrStruct[apiFieldName], false)
			default:
				log.Debugf("unexpected primitive type %q", ty.FriendlyName())
			}
		case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
			nestedBlockOutput += writeAttrLine(snakeCaseAttrName, attrStruct[apiFieldName], true)
		default:
			log.Debugf("unexpected nested type %T for %s", ty, attrName)
		}
	}

	return nestedBlockOutput
}

// writeAttrLine outputs a line of HCL configuration with a configurable depth
// for known types.
func writeAttrLine(key string, value interface{}, usedInBlock bool) string {
	if key == "id" {
		// Attempt to convert the value to an integer if it's a float
		if floatValue, ok := value.(float64); ok {
			// Convert to int64 to handle large IDs, then format as a string
			return fmt.Sprintf("%s = %d\n", key, int64(floatValue))
		}
	}

	// Special handling for validity_start_time and validity_end_time
	if key == "validity_start_time" || key == "validity_end_time" {
		if floatValue, ok := value.(float64); ok {
			return fmt.Sprintf("%s = %q\n", key, epochToRFC1123(int64(floatValue)))
		} else if intValue, ok := value.(int); ok {
			return fmt.Sprintf("%s = %q\n", key, epochToRFC1123(int64(intValue)))
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
			s += writeAttrLine(v, values[v], false)
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
			return writeAttrLine(key, stringItems, false)
		}

		if len(intItems) > 0 {
			return writeAttrLine(key, intItems, false)
		}

		if len(interfaceItems) > 0 {
			return writeAttrLine(key, interfaceItems, false)
		}

	case []map[string]interface{}:
		var stringyInterfaces []string
		var op string
		var mapLen = len(value.([]map[string]interface{}))
		for i, item := range value.([]map[string]interface{}) {
			// Use an empty key to prevent rendering the key
			op = writeAttrLine("", item, true)
			// if condition handles adding new line for just the last element
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
func mapTfFieldNameToApi(resourceType, fieldName string) string {
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

func strip(s string) string {
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

func generateOutputs(resourceType string, resourceID string, workingDir string) {
	// Define the output file path
	outputsFile := fmt.Sprintf("%s/outputs.tf", strings.TrimSuffix(workingDir, "/"))

	// Exclude specified resources from generating outputs
	excludedResources := []string{
		"zia_auth_settings_urls",
		"zia_sandbox_behavioral_analysis",
		"zia_security_settings",
	}

	// Check if the resourceType is in the excluded list
	for _, excludedResource := range excludedResources {
		if resourceType == excludedResource {
			return
		}
	}

	// Read the existing outputs.tf file content if it exists
	existingOutputs := ""
	if _, err := os.Stat(outputsFile); err == nil {
		content, err := os.ReadFile(outputsFile)
		if err != nil {
			log.Fatalf("failed to read outputs file: %s", err)
		}
		existingOutputs = string(content)
	}

	// Create the output block string
	outputBlock := fmt.Sprintf(`output "%s_%s_id" {
  value = "${%s.%s.id}"
}

`, resourceType, resourceID, resourceType, resourceID)

	// Check if the output block already exists
	if strings.Contains(existingOutputs, fmt.Sprintf(`output "%s_%s_id"`, resourceType, resourceID)) {
		return
	}

	// Open the file in append mode or create it if it doesn't exist
	f, err := os.OpenFile(outputsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open outputs file: %s", err)
	}
	defer f.Close()

	// Write the output block to the file
	if _, err := f.WriteString(outputBlock); err != nil {
		log.Fatalf("failed to write to outputs file: %s", err)
	}
}
