package cmd

import (
	"encoding/json"
	"strings"

	"strconv"

	"github.com/spf13/cobra"
	"github.com/zscaler/zscaler-sdk-go/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/user_authentication_settings"

	"fmt"
)

// resourceImportStringFormats contains a mapping of the resource type to the
// composite ID that is compatible with performing an import.
var resourceImportStringFormats = map[string]string{
	"zpa_app_connector_group":                           ":id",
	"zpa_application_server":                            ":id",
	"zpa_application_segment":                           ":id",
	"zpa_application_segment_pra":                       ":id",
	"zpa_application_segment_inspection":                ":id",
	"zpa_segment_group":                                 ":id",
	"zpa_server_group":                                  ":id",
	"zpa_browser_access":                                ":id",
	"zpa_policy_access_rule":                            ":id",
	"zpa_policy_inspection_rule":                        ":id",
	"zpa_policy_timeout_rule":                           ":id",
	"zpa_policy_forwarding_rule":                        ":id",
	"zpa_provisioning_key":                              ":id",
	"zpa_service_edge_group":                            ":id",
	"zpa_lss_config_controller":                         ":id",
	"zpa_inspection_custom_controls":                    ":id",
	"zpa_inspection_profile":                            ":id",
	"zia_admin_users":                                   ":id",
	"zia_dlp_dictionaries":                              ":id",
	"zia_dlp_notification_templates":                    ":id",
	"zia_dlp_web_rules":                                 ":id",
	"zia_firewall_filtering_rule":                       ":id",
	"zia_firewall_filtering_destination_groups":         ":id",
	"zia_firewall_filtering_ip_source_groups":           ":id",
	"zia_firewall_filtering_network_service":            ":id",
	"zia_firewall_filtering_network_service_groups":     ":id",
	"zia_firewall_filtering_network_application_groups": ":id",
	"zia_traffic_forwarding_gre_tunnel":                 ":id",
	"zia_traffic_forwarding_static_ip":                  ":id",
	"zia_traffic_forwarding_vpn_credentials":            ":id",
	"zia_location_management":                           ":id",
	"zia_url_categories":                                ":id",
	"zia_url_filtering_rules":                           ":id",
	"zia_user_management":                               ":id",
	"zia_activation_status":                             ":id",
	"zia_rule_labels":                                   ":id",
	"zia_auth_settings_urls":                            ":id",
	"zia_security_settings":                             ":id",
}

func init() {
	rootCmd.AddCommand(importCommand)
}

var importCommand = &cobra.Command{
	Use:    "import",
	Short:  "Output `terraform import` compatible commands in order to import resources into state",
	Run:    runImport(),
	PreRun: sharedPreRun,
}

func runImport() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		var jsonStructData []interface{}
		switch resourceType {
		case "zpa_app_connector_group":
			jsonPayload, _, err := api.zpa.appconnectorgroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_server":
			jsonPayload, _, err := api.zpa.appservercontroller.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment":
			jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment_pra":
			jsonPayload, _, err := api.zpa.applicationsegmentpra.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_application_segment_inspection":
			jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_segment_group":
			jsonPayload, _, err := api.zpa.segmentgroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_server_group":
			jsonPayload, _, err := api.zpa.servergroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_browser_access":
			jsonPayload, _, err := api.zpa.browseraccess.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_access_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("ACCESS_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_inspection_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("INSPECTION_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_timeout_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("TIMEOUT_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_policy_forwarding_rule":
			jsonPayload, _, err := api.zpa.policysetcontroller.GetAllByType("CLIENT_FORWARDING_POLICY")
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_provisioning_key":
			jsonPayload, err := api.zpa.provisioningkey.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_service_edge_group":
			jsonPayload, _, err := api.zpa.serviceedgegroup.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_lss_config_controller":
			jsonPayload, _, err := api.zpa.lssconfigcontroller.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_inspection_custom_controls":
			jsonPayload, _, err := api.zpa.inspection_custom_controls.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zpa_inspection_profile":
			jsonPayload, _, err := api.zpa.inspection_profile.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_admin_users":
			jsonPayload, err := api.zia.adminuserrolemgmt.GetAllAdminUsers()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_dictionaries":
			jsonPayload, err := api.zia.dlpdictionaries.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_notification_templates":
			jsonPayload, err := api.zia.dlp_notification_templates.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_dlp_web_rules":
			jsonPayload, err := api.zia.dlp_web_rules.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_rule":
			jsonPayload, err := api.zia.filteringrules.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_destination_groups":
			jsonPayload, err := api.zia.ipdestinationgroups.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_ip_source_groups":
			jsonPayload, err := api.zia.ipsourcegroups.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_service":
			jsonPayload, err := api.zia.networkservices.GetAllNetworkServices()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_service_groups":
			jsonPayload, err := api.zia.networkservices.GetAllNetworkServiceGroups()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_firewall_filtering_network_application_groups":
			jsonPayload, err := api.zia.networkapplications.GetAllNetworkApplicationGroups()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_gre_tunnel":
			jsonPayload, err := api.zia.gretunnels.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_static_ip":
			jsonPayload, err := api.zia.staticips.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_traffic_forwarding_vpn_credentials":
			jsonPayload, err := api.zia.vpncredentials.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_location_management":
			jsonPayload, err := api.zia.locationmanagement.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_url_categories":
			jsonPayload, err := api.zia.urlcategories.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_url_filtering_rules":
			jsonPayload, err := api.zia.urlfilteringpolicies.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_user_management":
			jsonPayload, err := api.zia.usermanagement.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_rule_labels":
			jsonPayload, err := api.zia.rule_labels.GetAll()
			if err != nil {
				log.Fatal(err)
			}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_auth_settings_urls":
			exemptedUrls, err := api.zia.user_authentication_settings.Get()
			if err != nil {
				log.Fatal(err)
			}
			jsonPayload := []*user_authentication_settings.ExemptedUrls{exemptedUrls}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		case "zia_security_settings":
			urls, err := api.zia.security_policy_settings.GetListUrls()
			if err != nil {
				log.Fatal(err)
			}
			jsonPayload := []*security_policy_settings.ListUrls{urls}
			m, _ := json.Marshal(jsonPayload)
			json.Unmarshal(m, &jsonStructData)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "%q is not yet supported for state import", resourceType)
			return
		}

		for _, data := range jsonStructData {
			resourceID, ok := data.(map[string]interface{})["id"].(string)
			if !ok {
				resourceIDInt, ok := data.(map[string]interface{})["id"].(int)
				if ok {
					resourceID = strconv.Itoa(resourceIDInt)
				} else {
					resourceIDFloat64, ok := data.(map[string]interface{})["id"].(float64)
					if ok {
						resourceID = strconv.FormatInt(int64(resourceIDFloat64), 10)
					}
				}
			}
			if resourceID != "" {
				fmt.Fprint(cmd.OutOrStdout(), buildCompositeID(resourceType, resourceID))
			}
		}
	}
}

// buildCompositeID takes the resourceType and resourceID in order to lookup the
// resource type import string and then return a suitable composite value that
// is compatible with `terraform import`.
func buildCompositeID(resourceType, resourceID string) string {
	if _, ok := resourceImportStringFormats[resourceType]; !ok {
		log.Fatalf("%s does not have an import format defined", resourceType)
	}
	s := fmt.Sprintf("%s %s.%s_%s %s", terraformImportCmdPrefix, resourceType, terraformResourceNamePrefix, resourceID, resourceImportStringFormats[resourceType])
	replacer := strings.NewReplacer(
		":id", resourceID,
	)
	s += "\n"

	return replacer.Replace(s)
}
