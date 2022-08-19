package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/iancoleman/strcase"

	"github.com/sirupsen/logrus"
	"github.com/zscaler/zscaler-sdk-go/zia/services/activation"
	"github.com/zscaler/zscaler-sdk-go/zia/services/adminuserrolemgmt"
	"github.com/zscaler/zscaler-sdk-go/zia/services/devicegroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/networkapplications"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/timewindow"
	"github.com/zscaler/zscaler-sdk-go/zia/services/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/zia/services/locationmanagement/locationgroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/greinternalipranges"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/gretunnelinfo"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/virtualipaddresslist"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/usermanagement"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/browseraccess"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/cloudconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/customerversionprofile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/enrollmentcert"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_predefined_controls"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_profile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/machinegroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/samlattribute"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/serviceedgecontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/trustednetwork"

	"github.com/google/uuid"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
	"github.com/zscaler/zscaler-sdk-go/zia"
	"github.com/zscaler/zscaler-sdk-go/zpa"
)

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

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
	if strings.HasPrefix(resourceType, "zpa_") {
		// init zpa
		zpaCloud = viper.GetString("zpaCloud")
		if zpaClientID = viper.GetString("zpaClientID"); zpaClientID == "" {
			log.Fatal("'zpaClientID' must be set.")
		}
		if zpaClientSecret = viper.GetString("zpaClientSecret"); zpaClientSecret == "" {
			log.Fatal("'zpaClientSecret' must be set.")
		}
		if zpaCustomerID = viper.GetString("zpaCustomerID"); zpaCustomerID == "" {
			log.Fatal("'zpaCustomerID' must be set.")
		}

		log.WithFields(logrus.Fields{
			"zpaClientID":   zpaClientID,
			"zpaCustomerID": "zpaCustomerID",
			"zpaCloud":      "zpaCloud",
		}).Debug("initializing zscaler-sdk-go[ZPA]")
	} else if strings.HasPrefix(resourceType, "zia_") {
		// init zia
		ziaCloud = viper.GetString("ziaCloud")
		if ziaUsername = viper.GetString("ziaUsername"); ziaUsername == "" {
			log.Fatal("'ziaUsername' must be set.")
		}
		if ziaPassword = viper.GetString("ziaPassword"); ziaPassword == "" {
			log.Fatal("'ziaPassword' must be set.")
		}
		if ziaApiKey = viper.GetString("ziaApiKey"); ziaApiKey == "" {
			log.Fatal("'ziaApiKey' must be set.")
		}

		log.WithFields(logrus.Fields{
			"ziaUsername": ziaUsername,
			"ziaCloud":    "ziaCloud",
		}).Debug("initializing zscaler-sdk-go[ZIA]")
	} else {
		log.Fatal("failed to initialize zscaler-sdk-go (zpa): Uknwon resource type prefix, expecting zpa_ or zia_: " + resourceType)
	}

	// Don't initialise a client in CI as this messes with VCR and the ability to
	// mock out the HTTP interactions.
	if os.Getenv("CI") != "true" {
		if strings.HasPrefix(resourceType, "zpa_") {
			zpaConfig, err := zpa.NewConfig(zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud, "zscaler-terraforming")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zpa)", err)
			}
			zpaClient := zpa.NewClient(zpaConfig)
			api = &Client{
				zpa: &ZPAClient{
					appconnectorgroup:              appconnectorgroup.New(zpaClient),
					appconnectorcontroller:         appconnectorcontroller.New(zpaClient),
					applicationsegment:             applicationsegment.New(zpaClient),
					applicationsegmentpra:          applicationsegmentpra.New(zpaClient),
					applicationsegmentinspection:   applicationsegmentinspection.New(zpaClient),
					appservercontroller:            appservercontroller.New(zpaClient),
					bacertificate:                  bacertificate.New(zpaClient),
					cloudconnectorgroup:            cloudconnectorgroup.New(zpaClient),
					customerversionprofile:         customerversionprofile.New(zpaClient),
					enrollmentcert:                 enrollmentcert.New(zpaClient),
					idpcontroller:                  idpcontroller.New(zpaClient),
					lssconfigcontroller:            lssconfigcontroller.New(zpaClient),
					machinegroup:                   machinegroup.New(zpaClient),
					postureprofile:                 postureprofile.New(zpaClient),
					policysetcontroller:            policysetcontroller.New(zpaClient),
					provisioningkey:                provisioningkey.New(zpaClient),
					samlattribute:                  samlattribute.New(zpaClient),
					scimgroup:                      scimgroup.New(zpaClient),
					scimattributeheader:            scimattributeheader.New(zpaClient),
					segmentgroup:                   segmentgroup.New(zpaClient),
					servergroup:                    servergroup.New(zpaClient),
					serviceedgegroup:               serviceedgegroup.New(zpaClient),
					serviceedgecontroller:          serviceedgecontroller.New(zpaClient),
					trustednetwork:                 trustednetwork.New(zpaClient),
					browseraccess:                  browseraccess.New(zpaClient),
					inspection_custom_controls:     inspection_custom_controls.New(zpaClient),
					inspection_predefined_controls: inspection_predefined_controls.New(zpaClient),
					inspection_profile:             inspection_profile.New(zpaClient),
				},
			}
		} else if strings.HasPrefix(resourceType, "zia_") {
			// init zia
			ziaClient, err := zia.NewClient(ziaUsername, ziaPassword, ziaApiKey, ziaCloud, "zscaler-terraforming")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zia)", err)
			}
			api = &Client{
				zia: &ZIAClient{
					adminuserrolemgmt:            adminuserrolemgmt.New(ziaClient),
					filteringrules:               filteringrules.New(ziaClient),
					ipdestinationgroups:          ipdestinationgroups.New(ziaClient),
					ipsourcegroups:               ipsourcegroups.New(ziaClient),
					networkapplications:          networkapplications.New(ziaClient),
					networkservices:              networkservices.New(ziaClient),
					timewindow:                   timewindow.New(ziaClient),
					urlcategories:                urlcategories.New(ziaClient),
					urlfilteringpolicies:         urlfilteringpolicies.New(ziaClient),
					usermanagement:               usermanagement.New(ziaClient),
					virtualipaddresslist:         virtualipaddresslist.New(ziaClient),
					vpncredentials:               vpncredentials.New(ziaClient),
					gretunnels:                   gretunnels.New(ziaClient),
					gretunnelinfo:                gretunnelinfo.New(ziaClient),
					greinternalipranges:          greinternalipranges.New(ziaClient),
					staticips:                    staticips.New(ziaClient),
					locationmanagement:           locationmanagement.New(ziaClient),
					locationgroups:               locationgroups.New(ziaClient),
					activation:                   activation.New(ziaClient),
					devicegroups:                 devicegroups.New(ziaClient),
					dlpdictionaries:              dlpdictionaries.New(ziaClient),
					dlp_engines:                  dlp_engines.New(ziaClient),
					dlp_notification_templates:   dlp_notification_templates.New(ziaClient),
					dlp_web_rules:                dlp_web_rules.New(ziaClient),
					rule_labels:                  rule_labels.New(ziaClient),
					security_policy_settings:     security_policy_settings.New(ziaClient),
					user_authentication_settings: user_authentication_settings.New(ziaClient),
				},
			}
		}
	}
}

// sanitiseTerraformResourceName ensures that a Terraform resource name matches
// the restrictions imposed by core.
func sanitiseTerraformResourceName(s string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_]+`)
	return re.ReplaceAllString(s, "_")
}

// flattenAttrMap takes a list of attributes defined as a list of maps comprising of {"id": "attrId", "value": "attrValue"}
// and flattens it to a single map of {"attrId": "attrValue"}
func flattenAttrMap(l []interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	attrID := ""
	var attrVal interface{}

	for _, elem := range l {
		switch t := elem.(type) {
		case map[string]interface{}:
			if id, ok := t["id"]; ok {
				attrID = id.(string)
			} else {
				log.Debug("no 'id' in map when attempting to flattenAttrMap")
			}

			if val, ok := t["value"]; ok {
				if val == nil {
					log.Debugf("Found nil 'value' for %s attempting to flattenAttrMap, coercing to true", attrID)
					attrVal = true
				} else {
					attrVal = val
				}
			} else {
				log.Debug("no 'value' in map when attempting to flattenAttrMap")
			}

			result[attrID] = attrVal
		default:
			log.Debugf("got unknown element type %T when attempting to flattenAttrMap", elem)
		}
	}

	return result
}

func isInList(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
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

// nestBlocks takes a schema and generates all of the appropriate nesting of any
// top-level blocks as well as nested lists or sets.
func nestBlocks(schemaBlock *tfjson.SchemaBlock, structData map[string]interface{}, parentID string, indexedNestedBlocks map[string][]string) string {
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
		} else if isInList(resourceType, []string{"zia_firewall_filtering_network_service_groups", "zia_url_filtering_rules", "zia_dlp_web_rules"}) && isInList(block, []string{"departments",
			"groups",
			"locations",
			"dlp_engines",
			"location_groups",
			"url_categories",
			"users",
			"labels",
			"services"}) {
			output += listIdsIntBlock(block, structData[mapTfFieldNameToApi(resourceType, block)])
			continue
		} else if isInList(resourceType, []string{"zpa_application_segment",
			"zpa_application_segment_inspection",
			"zpa_application_segment_pra",
			"zpa_browser_access",
		}) && block == "server_groups" {
			output += listIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_server_group", "zpa_policy_access_rule"}) && block == "app_connector_groups" {
			output += listIdsStringBlock(block, structData["appConnectorGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_server_group"}) && block == "applications" {
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
					switch s.(type) {
					case map[string]interface{}:
						nestedBlockOutput += nestBlocks(schemaBlock.NestedBlocks[block].Block, s.(map[string]interface{}), parentID, indexedNestedBlocks)
						indexedNestedBlocks[parentID] = append(indexedNestedBlocks[parentID], nestedBlockOutput)

					case []interface{}:
						for _, nestedItem := range s.([]interface{}) {
							parentID, exists := nestedItem.(map[string]interface{})["id"]
							if !exists {
								// if we fail to find an ID, we tag the current element with a uuid
								log.Debugf("id not found for nestedItem %#v using uuid terraform_internal_id", nestedItem)
								parentID = uuid.New().String()
								nestedItem.(map[string]interface{})["terraform_internal_id"] = parentID
							}

							nestedBlockOutput += nestBlocks(schemaBlock.NestedBlocks[block].Block, nestedItem.(map[string]interface{}), parentID.(string), indexedNestedBlocks)
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
					nestedBlockOutput += writeNestedBlock(sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, attrStruct, parentID)
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
						repeatedBlockOutput = writeNestedBlock(sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v, parentID)
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
						repeatedBlockOutput = writeNestedBlock(sortedInnerAttributes, schemaBlock.NestedBlocks[block].Block, v.(map[string]interface{}), parentID)
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

func writeNestedBlock(attributes []string, schemaBlock *tfjson.SchemaBlock, attrStruct map[string]interface{}, parentID string) string {
	nestedBlockOutput := ""

	for _, attrName := range attributes {
		apiFieldName := mapTfFieldNameToApi(resourceType, attrName)
		ty := schemaBlock.Attributes[attrName].AttributeType

		switch {
		case ty.IsPrimitiveType():
			switch ty {
			case cty.String, cty.Bool, cty.Number:
				nestedBlockOutput += writeAttrLine(attrName, attrStruct[apiFieldName], false)
			default:
				log.Debugf("unexpected primitive type %q", ty.FriendlyName())
			}
		case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
			nestedBlockOutput += writeAttrLine(attrName, attrStruct[apiFieldName], true)
		default:
			log.Debugf("unexpected nested type %T for %s", ty, attrName)
		}
	}

	return nestedBlockOutput
}

// writeAttrLine outputs a line of HCL configuration with a configurable depth
// for known types.
func writeAttrLine(key string, value interface{}, usedInBlock bool) string {
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
			switch item.(type) {
			case string:
				stringItems = append(stringItems, item.(string))
			case map[string]interface{}:
				interfaceItems = append(interfaceItems, item.(map[string]interface{}))
			case float64:
				intItems = append(intItems, int(item.(float64)))
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
		return fmt.Sprintf("%s = %0.f\n", key, value)
	case bool:
		return fmt.Sprintf("%s = %t\n", key, value)
	default:
		log.Debugf("got unknown attribute configuration: key %s, value %v, value type %T", key, value, value)
		return ""
	}
	return ""
}

var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

func mapApiFieldNameToTf(resourceType, fieldName string) string {
	snake := matchFirstCap.ReplaceAllString(fieldName, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func mapTfFieldNameToApi(resourceType, apiFieldName string) string {
	switch resourceType {
	case "zia_admin_users":
		switch apiFieldName {
		case "username":
			return "userName"
		}
	}
	result := strcase.ToLowerCamel(apiFieldName)
	return result
}
