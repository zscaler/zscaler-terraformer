package cmd

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
	"github.com/zscaler/zscaler-sdk-go/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/user_authentication_settings"

	"fmt"
)

var resourceType string

func init() {
	rootCmd.AddCommand(generateCmd)
}

var generateCmd = &cobra.Command{
	Use:    "generate",
	Short:  "Fetch resources from the Cloudflare API and generate the respective Terraform stanzas",
	Run:    generateResources(),
	PreRun: sharedPreRun,
}

func generateResources() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if resourceType == "" {
			log.Fatal("you must define a resource type to generate")
		}
		tmpDir, err := ioutil.TempDir("", "tfinstall")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)
		installer := &releases.ExactVersion{
			Product: product.Terraform,
			Version: version.Must(version.NewVersion("1.2.6")),
		}
		log.Debugf("installing Terraform")
		execPath, err := installer.Install(context.Background())
		if err != nil {
			log.Fatalf("error installing Terraform: %s", err)
		}
		log.Debugf("Terraform installed")
		cloudType := ""
		if strings.HasPrefix(resourceType, "zpa_") {
			cloudType = "zpa"
		} else if strings.HasPrefix(resourceType, "zia_") {
			cloudType = "zia"
		}
		workingDir := viper.GetString(cloudType + "-terraform-install-path")
		// Setup and configure Terraform to operate in the temporary directory where
		// the provider is already configured.
		if workingDir == "" {
			workingDir = viper.GetString("terraform-install-path")
		}
		log.Debugf("initializing Terraform in %s", workingDir)
		tf, err := tfexec.NewTerraform(workingDir, execPath)
		if err != nil {
			log.Fatal(err)
		}

		err = tf.Init(context.Background(), tfexec.Upgrade(true))
		if err != nil {
			log.Fatal(err)
		}
		log.Debug("reading Terraform schema for " + cloudType + " provider")
		ps, err := tf.ProvidersSchema(context.Background())
		if err != nil {
			log.Fatal("failed to read provider schema", err)
		}
		providerNames := []string{
			fmt.Sprintf("zscaler.com/%s/%s", cloudType, cloudType),
			fmt.Sprintf("zscaler/%s", cloudType),
			fmt.Sprintf("registry.terraform.io/zscaler/%s", cloudType),
		}
		var s *tfjson.ProviderSchema
		log.Debug("ps.Schemas:", ps.Schemas)
		for _, p := range providerNames {
			if ps, ok := ps.Schemas[p]; ok {
				s = ps
				break
			}
		}
		if s == nil {
			log.Fatal("failed to detect " + cloudType + " provider installation")
		}

		r := s.ResourceSchemas[resourceType]
		log.Debugf("beginning to read and build %s resources", resourceType)

		// Initialise `resourceCount` outside of the switch for supported resources
		// to allow it to be referenced further down in the loop that outputs the
		// newly generated resources.
		resourceCount := 0

		// Lazy approach to restrict support to known resources due to Go's type
		// restrictions and the need to explicitly map out the structs.
		var jsonStructData []interface{}

		switch resourceType {
		case "zpa_app_connector_group":
			jsonPayload, _, err := api.zpa.appconnectorgroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_server":
			jsonPayload, _, err := api.zpa.appservercontroller.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment":
			jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment_pra":
			jsonPayload, _, err := api.zpa.applicationsegmentpra.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment_inspection":
			jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_segment_group":
			jsonPayload, _, err := api.zpa.segmentgroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_server_group":
			jsonPayload, _, err := api.zpa.servergroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_browser_access":
			jsonPayload, _, err := api.zpa.browseraccess.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_access_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("ACCESS_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_inspection_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("INSPECTION_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_timeout_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("TIMEOUT_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_forwarding_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("CLIENT_FORWARDING_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_provisioning_key":
			jsonPayload, err := api.zpa.provisioningkey.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_service_edge_group":
			jsonPayload, _, err := api.zpa.serviceedgegroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_lss_config_controller":
			jsonPayload, _, err := api.zpa.lssconfigcontroller.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_inspection_custom_controls":
			jsonPayload, _, err := api.zpa.inspection_custom_controls.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_inspection_profile":
			jsonPayload, _, err := api.zpa.inspection_profile.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_admin_users":
			jsonPayload, err := api.zia.adminuserrolemgmt.GetAllAdminUsers()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_dictionaries":
			jsonPayload, err := api.zia.dlpdictionaries.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_notification_templates":
			jsonPayload, err := api.zia.dlp_notification_templates.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_web_rules":
			jsonPayload, err := api.zia.dlp_web_rules.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_rule":
			jsonPayload, err := api.zia.filteringrules.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_destination_groups":
			jsonPayload, err := api.zia.ipdestinationgroups.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_ip_source_groups":
			jsonPayload, err := api.zia.ipsourcegroups.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_service":
			jsonPayload, err := api.zia.networkservices.GetAllNetworkServices()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_service_groups":
			jsonPayload, err := api.zia.networkservices.GetAllNetworkServiceGroups()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_application_groups":
			jsonPayload, err := api.zia.networkapplications.GetAllNetworkApplicationGroups()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_gre_tunnel":
			jsonPayload, err := api.zia.gretunnels.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_static_ip":
			jsonPayload, err := api.zia.staticips.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_vpn_credentials":
			jsonPayload, err := api.zia.vpncredentials.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_location_management":
			jsonPayload, err := api.zia.locationmanagement.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_url_categories":
			jsonPayload, err := api.zia.urlcategories.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_url_filtering_rules":
			jsonPayload, err := api.zia.urlfilteringpolicies.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_user_management":
			jsonPayload, err := api.zia.usermanagement.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_rule_labels":
			jsonPayload, err := api.zia.rule_labels.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_auth_settings_urls":
			exemptedUrls, err := api.zia.user_authentication_settings.Get()
			if err != nil {
				log.Fatal(err)
			}
			jsonPayload := []*user_authentication_settings.ExemptedUrls{exemptedUrls}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_security_settings":
			urls, err := api.zia.security_policy_settings.GetListUrls()
			if err != nil {
				log.Fatal(err)
			}
			jsonPayload := []*security_policy_settings.ListUrls{urls}
			resourceCount = len(jsonPayload)
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "%q is not yet supported for automatic generation", resourceType)
			return
		}
		// If we don't have any resources to generate, just bail out early.
		if resourceCount == 0 {
			fmt.Fprint(cmd.OutOrStdout(), "no resources found to generate. Exiting...")
			return
		}

		output := ""

		for i := 0; i < resourceCount; i++ {
			structData := jsonStructData[i].(map[string]interface{})

			resourceID := ""
			if os.Getenv("USE_STATIC_RESOURCE_IDS") == "true" {
				resourceID = "terraform_managed_resource"
			} else {
				id := ""
				if structData["id"] != nil {
					switch structData["id"].(type) {
					case float64:
						id = fmt.Sprintf("%d", int64(structData["id"].(float64)))
					default:
						id = structData["id"].(string)
					}
				}

				resourceID = fmt.Sprintf("terraform_managed_resource_%s", id)
			}

			output += fmt.Sprintf(`resource "%s" "%s" {`+"\n", resourceType, resourceID)
			sortedBlockAttributes := make([]string, 0, len(r.Block.Attributes))
			for k := range r.Block.Attributes {
				sortedBlockAttributes = append(sortedBlockAttributes, k)
			}
			sort.Strings(sortedBlockAttributes)

			// Block attributes are for any attributes where assignment is involved.
			for _, attrName := range sortedBlockAttributes {
				apiAttrName := mapApiFieldNameToTf(resourceType, attrName)
				// Don't bother outputting the ID for the resource as that is only for
				// internal use (such as importing state).
				if attrName == "id" {
					continue
				}

				// No need to output computed attributes that are also not
				// optional.
				if r.Block.Attributes[attrName].Computed && !r.Block.Attributes[attrName].Optional {
					continue
				}

				ty := r.Block.Attributes[attrName].AttributeType
				switch {
				case ty.IsPrimitiveType():
					switch ty {
					case cty.String, cty.Bool, cty.Number:
						output += writeAttrLine(attrName, structData[apiAttrName], false)
					default:
						log.Debugf("unexpected primitive type %q", ty.FriendlyName())
					}
				case ty.IsCollectionType():
					switch {
					case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
						output += writeAttrLine(attrName, structData[apiAttrName], false)
					default:
						log.Debugf("unexpected collection type %q", ty.FriendlyName())
					}
				case ty.IsTupleType():
					fmt.Printf("tuple found. attrName %s\n", attrName)
				case ty.IsObjectType():
					fmt.Printf("object found. attrName %s\n", attrName)
				default:
					log.Debugf("attribute %q (attribute type of %q) has not been generated", attrName, ty.FriendlyName())
				}
			}

			output += nestBlocks(r.Block, jsonStructData[i].(map[string]interface{}), uuid.New().String(), map[string][]string{})
			output += "}\n\n"
		}

		output, err = tf.FormatString(context.Background(), output)
		if err != nil {
			log.Fatalf("failed to format output: %s", err)
		}

		fmt.Fprint(cmd.OutOrStdout(), output)

	}
}
