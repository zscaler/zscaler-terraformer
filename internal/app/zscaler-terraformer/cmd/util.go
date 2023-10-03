package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/iancoleman/strcase"

	"github.com/sirupsen/logrus"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/adminuserrolemgmt"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/devicegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkapplications"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/timewindow"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/locationmanagement/locationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/greinternalipranges"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/gretunnelinfo"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/virtualipaddresslist"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/usermanagement/usermanagement"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/browseraccess"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/customerversionprofile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/enrollmentcert"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_predefined_controls"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_profile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/machinegroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/samlattribute"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/serviceedgecontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/trustednetwork"

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
		}
		if strings.HasPrefix(resourceType_, "zia_") || strings.Contains(resources, "zia_") || resources == "*" || resources == "zia" {
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
		}
		api = &Client{}
		if strings.HasPrefix(resourceType_, "zpa_") || strings.Contains(resources, "zpa_") || resources == "*" || resources == "zpa" {
			zpaConfig, err := zpa.NewConfig(zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud, "zscaler-terraformer")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zpa)", err)
			}
			zpaClient := zpa.NewClient(zpaConfig)
			api.zpa = &ZPAClient{
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
			}
		}
		if strings.HasPrefix(resourceType_, "zia_") || strings.Contains(resources, "zia_") || resources == "*" || resources == "zia" {
			// init zia
			ziaClient, err := zia.NewClient(ziaUsername, ziaPassword, ziaApiKey, ziaCloud, "zscaler-terraformer")
			if err != nil {
				log.Fatal("failed to initialize zscaler-sdk-go (zia)", err)
			}
			api.zia = &ZIAClient{
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
				devicegroups:                 devicegroups.New(ziaClient),
				dlpdictionaries:              dlpdictionaries.New(ziaClient),
				dlp_engines:                  dlp_engines.New(ziaClient),
				dlp_notification_templates:   dlp_notification_templates.New(ziaClient),
				dlp_web_rules:                dlp_web_rules.New(ziaClient),
				rule_labels:                  rule_labels.New(ziaClient),
				security_policy_settings:     security_policy_settings.New(ziaClient),
				user_authentication_settings: user_authentication_settings.New(ziaClient),
			}
		}
	}
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
		} else if isInList(resourceType, []string{"zia_firewall_filtering_network_service_groups", "zia_url_filtering_rules", "zia_dlp_web_rules", "zia_user_management"}) && isInList(block, []string{"departments",
			"groups",
			"locations",
			"dlp_engines",
			"location_groups",
			"url_categories",
			"users",
			"labels",
			"services",
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
			"time_windows"}) {
			output += listIdsIntBlock(block, structData[mapTfFieldNameToApi(resourceType, block)])
			continue
		} else if isInList(resourceType, []string{"zpa_application_segment",
			"zpa_application_segment_inspection",
			"zpa_application_segment_pra",
			"zpa_application_segment_browser_access",
		}) && block == "server_groups" {
			output += listIdsStringBlock(block, structData["serverGroups"])
			continue
		} else if isInList(resourceType, []string{"zpa_server_group", "zpa_policy_access_rule"}) && block == "app_connector_groups" {
			output += listIdsStringBlock(block, structData["appConnectorGroups"])
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
