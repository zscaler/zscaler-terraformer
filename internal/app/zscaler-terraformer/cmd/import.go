package cmd

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"strconv"

	"fmt"

	"github.com/spf13/cobra"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkapplicationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/forwarding_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/sandbox/sandbox_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/servergroup"
)

// resourceImportStringFormats contains a mapping of the resource type to the
// composite ID that is compatible with performing an import.
var resourceImportStringFormats = map[string]string{
	"zpa_app_connector_group":                           ":id",
	"zpa_application_server":                            ":id",
	"zpa_application_segment":                           ":id",
	"zpa_application_segment_pra":                       ":id",
	"zpa_application_segment_inspection":                ":id",
	"zpa_application_segment_browser_access":            ":id",
	"zpa_cloud_browser_isolation_banner":                ":id",
	"zpa_cloud_browser_isolation_certificate":           ":id",
	"zpa_cloud_browser_isolation_external_profile":      ":id",
	"zpa_segment_group":                                 ":id",
	"zpa_server_group":                                  ":id",
	"zpa_policy_access_rule":                            ":id",
	"zpa_policy_inspection_rule":                        ":id",
	"zpa_policy_timeout_rule":                           ":id",
	"zpa_policy_forwarding_rule":                        ":id",
	"zpa_provisioning_key":                              ":id",
	"zpa_service_edge_group":                            ":id",
	"zpa_lss_config_controller":                         ":id",
	"zpa_inspection_custom_controls":                    ":id",
	"zpa_inspection_profile":                            ":id",
	"zpa_microtenant_controller":                        ":id",
	"zia_admin_users":                                   ":id",
	"zia_dlp_dictionaries":                              ":id",
	"zia_dlp_engines":                                   ":id",
	"zia_dlp_notification_templates":                    ":id",
	"zia_dlp_web_rules":                                 ":id",
	"zia_firewall_filtering_rule":                       ":id",
	"zia_firewall_filtering_destination_groups":         ":id",
	"zia_firewall_filtering_ip_source_groups":           ":id",
	"zia_firewall_filtering_network_service":            ":id",
	"zia_firewall_filtering_network_service_groups":     ":id",
	"zia_firewall_filtering_network_application_groups": ":id",
	"zia_forwarding_control_rule":                       ":id",
	"zia_forwarding_control_zpa_gateway":                ":id",
	"zia_traffic_forwarding_static_ip":                  ":id",
	"zia_traffic_forwarding_vpn_credentials":            ":id",
	"zia_traffic_forwarding_gre_tunnel":                 ":id",
	"zia_location_management":                           ":id",
	"zia_url_categories":                                ":id",
	"zia_url_filtering_rules":                           ":id",
	"zia_user_management":                               ":id",
	"zia_rule_labels":                                   ":id",
	"zia_auth_settings_urls":                            ":id",
	"zia_security_settings":                             ":id",
	"zia_sandbox_behavioral_analysis":                   ":id",
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

type APIError struct {
	Params []string `json:"params"`
	ID     string   `json:"id"`
	Reason string   `json:"reason"`
}

// Check if the error is due to license issue
func isLicenseError(err error) (bool, string) {
	const licenseErrorMsg = "authz.featureflag.permission.denied"
	if strings.Contains(err.Error(), licenseErrorMsg) {
		apiErr := &APIError{}
		json.Unmarshal([]byte(err.Error()), apiErr)
		return true, apiErr.Reason
	}
	return false, ""
}

func runImport() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if resources != "" {
			var resourceTypes []string
			if resources == "*" {
				for resource := range resourceImportStringFormats {
					resourceTypes = append(resourceTypes, resource)
				}
			} else if resources == "zia" || resources == "zpa" {
				for resource := range resourceImportStringFormats {
					if strings.HasPrefix(resource, resources) {
						resourceTypes = append(resourceTypes, resource)
					}
				}
			} else {
				resourceTypes = strings.Split(resources, ",")
			}
			// Split the excludedResources string on commas to get a slice of excluded resource names.
			excludedResourcesTypes := strings.Split(excludedResources, ",")

			for _, rt := range resourceTypes {
				resourceTyp := strings.Trim(rt, " ")
				// Check if the current resource type is in the slice of excluded resources.
				if isInList(resourceTyp, excludedResourcesTypes) {
					continue
				}
				importResource(cmd, cmd.OutOrStdout(), resourceTyp)
			}
			return
		}
		importResource(cmd, cmd.OutOrStdout(), resourceType_)
	}
}

func importResource(cmd *cobra.Command, writer io.Writer, resourceType string) {
	var jsonStructData []interface{}
	resourceCount := 0
	switch resourceType {
	case "zpa_app_connector_group":
		list, _, err := api.zpa.appconnectorgroup.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		jsonPayload := []appconnectorgroup.AppConnectorGroup{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_server":
		jsonPayload, _, err := api.zpa.appservercontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment":
		jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_pra":
		jsonPayload, _, err := api.zpa.applicationsegmentpra.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_inspection":
		jsonPayload, _, err := api.zpa.applicationsegmentinspection.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_ba_certificate":
		jsonPayload, _, err := api.zpa.bacertificate.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_banner":
		jsonPayload, _, err := api.zpa.cbibannercontroller.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_external_profile":
		jsonPayload, _, err := api.zpa.cbiprofilecontroller.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_certificate":
		jsonPayload, _, err := api.zpa.cbicertificatecontroller.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_segment_group":
		list, _, err := api.zpa.segmentgroup.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []segmentgroup.SegmentGroup{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_server_group":
		list, _, err := api.zpa.servergroup.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []servergroup.ServerGroup{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_browser_access":
		jsonPayload, _, err := api.zpa.browseraccess.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_policy_access_rule":
		list, _, err := api.zpa.policysetcontroller.GetAllByType("ACCESS_POLICY")
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []policysetcontroller.PolicyRule{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_policy_inspection_rule":
		list, _, err := api.zpa.policysetcontroller.GetAllByType("INSPECTION_POLICY")
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []policysetcontroller.PolicyRule{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_policy_isolation_rule":
		list, _, err := api.zpa.policysetcontroller.GetAllByType("ISOLATION_POLICY")
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []policysetcontroller.PolicyRule{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_policy_timeout_rule":
		list, _, err := api.zpa.policysetcontroller.GetAllByType("TIMEOUT_POLICY")
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []policysetcontroller.PolicyRule{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" || i.Name == "Default_Rule" || i.DefaultRule {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_policy_forwarding_rule":
		list, _, err := api.zpa.policysetcontroller.GetAllByType("CLIENT_FORWARDING_POLICY")
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []policysetcontroller.PolicyRule{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" || i.Name == "Default_Rule" || i.DefaultRule {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_provisioning_key":
		jsonPayload, err := api.zpa.provisioningkey.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_service_edge_group":
		jsonPayload, _, err := api.zpa.serviceedgegroup.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_lss_config_controller":
		jsonPayload, _, err := api.zpa.lssconfigcontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		jsonPayload, _, err := api.zpa.inspection_custom_controls.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_profile":
		jsonPayload, _, err := api.zpa.inspection_profile.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_microtenant_controller":
		jsonPayload, _, err := api.zpa.microtenants.GetAll()
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_admin_users":
		jsonPayload, err := api.zia.admins.GetAllAdminUsers()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_dictionaries":
		list, err := api.zia.dlpdictionaries.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []dlpdictionaries.DlpDictionary{}
		for _, i := range list {
			if !i.Custom {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_engines":
		list, err := api.zia.dlp_engines.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []dlp_engines.DLPEngines{}
		for _, i := range list {
			if !i.CustomDlpEngine {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_notification_templates":
		jsonPayload, err := api.zia.dlp_notification_templates.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_web_rules":
		jsonPayload, err := api.zia.dlp_web_rules.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_rule":
		rules, err := api.zia.filteringrules.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []filteringrules.FirewallFilteringRules{}
		for _, rule := range rules {
			if isInList(rule.Name, []string{"Office 365 One Click Rule", "UCaaS One Click Rule", "Default Firewall Filtering Rule", "Recommended Firewall Rule", "Block All IPv6", "Block malicious IPs and domains", "Zscaler Proxy Traffic"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_destination_groups":
		groups, err := api.zia.ipdestinationgroups.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []ipdestinationgroups.IPDestinationGroups{}
		for _, group := range groups {
			if isInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_ip_source_groups":
		groups, err := api.zia.ipsourcegroups.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []ipsourcegroups.IPSourceGroups{}
		for _, group := range groups {
			if isInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_service":
		services, err := api.zia.networkservices.GetAllNetworkServices()
		if err != nil {
			log.Fatal(err)
		}
		servicesFiltered := []networkservices.NetworkServices{}
		for _, service := range services {
			if isInList(service.Type, []string{"STANDARD", "PREDEFINED"}) {
				continue
			}
			servicesFiltered = append(servicesFiltered, service)
		}
		m, _ := json.Marshal(servicesFiltered)
		resourceCount = len(servicesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_service_groups":
		jsonPayload, err := api.zia.networkservicegroups.GetAllNetworkServiceGroups()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_application_groups":
		groups, err := api.zia.networkapplicationgroups.GetAllNetworkApplicationGroups()
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []networkapplicationgroups.NetworkApplicationGroups{}
		for _, rule := range groups {
			if isInList(rule.Name, []string{"Microsoft Office365"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, rule)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_gre_tunnel":
		jsonPayload, err := api.zia.gretunnels.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_static_ip":
		jsonPayload, err := api.zia.staticips.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_vpn_credentials":
		jsonPayload, err := api.zia.vpncredentials.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_location_management":
		// Get all parent locations
		jsonPayload, err := api.zia.locationmanagement.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

		// Get all sublocations
		sublocationsPayload, err := api.zia.locationmanagement.GetAllSublocations()
		if err != nil {
			log.Fatal(err)
		}
		m, _ = json.Marshal(sublocationsPayload)
		subResourceCount := len(sublocationsPayload)
		var subJsonStructData []interface{}
		_ = json.Unmarshal(m, &subJsonStructData)

		// Append sublocations to the main jsonStructData slice
		jsonStructData = append(jsonStructData, subJsonStructData...)

		resourceCount += subResourceCount
	case "zia_url_categories":
		list, err := api.zia.urlcategories.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		items := []urlcategories.URLCategory{}
		for _, i := range list {
			if i.SuperCategory == "USER_DEFINED" ||
				i.UrlsRetainingParentCategoryCount > 0 ||
				len(i.KeywordsRetainingParentCategory) > 0 ||
				len(i.Keywords) > 0 ||
				len(i.Urls) > 0 {
				items = append(items, i)
			}
		}
		for i := range items {
			details, err := api.zia.urlcategories.Get(items[i].ID)
			if err != nil {
				continue
			}
			items[i] = *details
		}
		m, _ := json.Marshal(items)
		resourceCount = len(items)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_url_filtering_rules":
		jsonPayload, err := api.zia.urlfilteringpolicies.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_user_management":
		jsonPayload, err := api.zia.users.GetAllUsers()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_rule_labels":
		jsonPayload, err := api.zia.rule_labels.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_auth_settings_urls":
		exemptedUrls, err := api.zia.user_authentication_settings.Get()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*user_authentication_settings.ExemptedUrls{exemptedUrls}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_sandbox_behavioral_analysis":
		hashes, err := api.zia.sandbox_settings.Get()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*sandbox_settings.BaAdvancedSettings{hashes}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_security_settings":
		urls, err := api.zia.security_policy_settings.GetListUrls()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*security_policy_settings.ListUrls{urls}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_rule":
		rules, err := api.zia.forwarding_rules.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []forwarding_rules.ForwardingRules{}
		for _, rule := range rules {
			if isInList(rule.Name, []string{"Client Connector Traffic Direct", "ZPA Pool For Stray Traffic", "ZIA Inspected ZPA Apps", "Fallback mode of ZPA Forwarding"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_zpa_gateway":
		gws, err := api.zia.zpa_gateways.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		gwsFiltered := []zpa_gateways.ZPAGateways{}
		for _, gw := range gws {
			if isInList(gw.Name, []string{"Auto ZPA Gateway"}) {
				continue
			}
			gwsFiltered = append(gwsFiltered, gw)
		}
		m, _ := json.Marshal(gwsFiltered)
		resourceCount = len(gwsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	default:
		log.Printf("%q is not yet supported for state import", resourceType)
		return
	}

	if resourceCount == 0 {
		return
	}

	tf, _, workingDir := initTf(resourceType)
	f, err := os.Create(strings.TrimSuffix(workingDir, "/") + "/" + resourceType + ".tf")
	if err != nil {
		log.Fatal(err)
	}
	generate(cmd, f, resourceType)
	f.Close()

	for _, data := range jsonStructData {
		strcutData := data.(map[string]interface{})
		resourceID, ok := strcutData["id"].(string)
		if !ok {
			resourceIDInt, ok := strcutData["id"].(int)
			if ok {
				resourceID = strconv.Itoa(resourceIDInt)
			} else {
				resourceIDFloat64, ok := strcutData["id"].(float64)
				if ok {
					resourceID = strconv.FormatInt(int64(resourceIDFloat64), 10)
				}
			}
		}
		if resourceID != "" {
			name := buildResourceName(resourceType, strcutData)
			fmt.Fprint(writer, buildCompositeID(resourceType, resourceID, name))
			err := tf.Import(cmd.Context(), resourceType+"."+name, resourceID)
			if err != nil {
				log.Printf("[ERROR] error while running import:%v", err)
			}
		}
	}
}

// buildCompositeID takes the resourceType and resourceID in order to lookup the
// resource type import string and then return a suitable composite value that
// is compatible with `terraform import`.
func buildCompositeID(resourceType, resourceID, name string) string {
	if _, ok := resourceImportStringFormats[resourceType]; !ok {
		log.Fatalf("%s does not have an import format defined", resourceType)
	}
	s := fmt.Sprintf("%s %s.%s %s", terraformImportCmdPrefix, resourceType, name, resourceImportStringFormats[resourceType])
	replacer := strings.NewReplacer(
		":id", resourceID,
	)
	s += "\n"

	return replacer.Replace(s)
}
