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
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkapplicationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservicegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/forwarding_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/location/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/sandbox/sandbox_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/browseraccess"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/microtenants"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/privilegedremoteaccess/praapproval"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/privilegedremoteaccess/praconsole"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/privilegedremoteaccess/pracredential"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/privilegedremoteaccess/praportal"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-terraformer/teraformutils/helpers"
)

// resourceImportStringFormats contains a mapping of the resource type to the
// composite ID that is compatible with performing an import.
var resourceImportStringFormats = map[string]string{
	"zpa_app_connector_group":                           ":id",
	"zpa_application_server":                            ":id",
	"zpa_application_segment":                           ":id",
	"zpa_application_segment_browser_access":            ":id",
	"zpa_application_segment_inspection":                ":id",
	"zpa_application_segment_pra":                       ":id",
	"zpa_segment_group":                                 ":id",
	"zpa_server_group":                                  ":id",
	"zpa_policy_access_rule":                            ":id",
	"zpa_policy_timeout_rule":                           ":id",
	"zpa_policy_forwarding_rule":                        ":id",
	"zpa_policy_inspection_rule":                        ":id",
	"zpa_policy_isolation_rule":                         ":id",
	"zpa_pra_approval_controller":                       ":id",
	"zpa_pra_credential_controller":                     ":id",
	"zpa_pra_console_controller":                        ":id",
	"zpa_pra_portal_controller":                         ":id",
	"zpa_provisioning_key":                              ":id",
	"zpa_service_edge_group":                            ":id",
	"zpa_lss_config_controller":                         ":id",
	"zpa_inspection_custom_controls":                    ":id",
	"zpa_microtenant_controller":                        ":id",
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

func isLicenseError(err error) (bool, string) {
	const licenseErrorMsg = "authz.featureflag.permission.denied"
	if strings.Contains(err.Error(), licenseErrorMsg) {
		apiErr := &APIError{}
		_ = json.Unmarshal([]byte(err.Error()), apiErr)
		return true, apiErr.Reason
	}
	return false, ""
}

func runImport() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		managedResourceTypes := make(map[string]bool)
		includedSensitiveResources := make(map[string]bool)
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
			excludedResourcesTypes := strings.Split(excludedResources, ",")

			for _, rt := range resourceTypes {
				resourceTyp := strings.Trim(rt, " ")
				if helpers.IsInList(resourceTyp, excludedResourcesTypes) {
					continue
				}
				importResource(cmd, cmd.OutOrStdout(), resourceTyp, managedResourceTypes, includedSensitiveResources)
			}
			if len(managedResourceTypes) > 0 {
				fmt.Println("\033[33mThe following resources are already managed by Terraform:\033[0m")
				for resource := range managedResourceTypes {
					fmt.Println(resource)
				}
			} else {
				fmt.Println("\033[32mImport successful!\033[0m")
				fmt.Println("\033[32mThe resources imported via Zscaler Terraformer are shown above.\033[0m")
				fmt.Println("\033[32mThese resources are now in your Terraform state and will be managed by Terraform.\033[0m")
			}
			if includedSensitiveResources["zpa_pra_credential_controller"] {
				fmt.Println("\033[33mThe resource zpa_pra_credential_controller contains sensitive values not included in the generated code.\033[0m")
			}
			return
		}
		importResource(cmd, cmd.OutOrStdout(), resourceType_, managedResourceTypes, includedSensitiveResources)
		if len(managedResourceTypes) > 0 {
			fmt.Println("\033[33mThe following resources are already managed by Terraform:\033[0m")
			for resource := range managedResourceTypes {
				fmt.Println(resource)
			}
		} else {
			fmt.Println("\033[32mImport successful!\033[0m")
			fmt.Println("\033[32mThe resources imported via Zscaler Terraformer are shown above.\033[0m")
			fmt.Println("\033[32mThese resources are now in your Terraform state and will be managed by Terraform.\033[0m")
		}
		if includedSensitiveResources["zpa_pra_credential_controller"] {
			fmt.Println("\033[33mThe resource zpa_pra_credential_controller contains sensitive values not included in the generated code.\033[0m")
		}
	}
}
func importResource(cmd *cobra.Command, writer io.Writer, resourceType string, managedResourceTypes map[string]bool, includedSensitiveResources map[string]bool) {
	var jsonStructData []interface{}
	resourceCount := 0
	switch resourceType {
	case "zpa_app_connector_group":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.AppConnectorGroup
		list, _, err := appconnectorgroup.GetAll(zpaClient)
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.AppServerController
		jsonPayload, _, err := appservercontroller.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ApplicationSegment
		jsonPayload, _, err := applicationsegment.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		jsonStructData = make([]interface{}, len(jsonPayload))
		for i, item := range jsonPayload {
			m, _ := json.Marshal(item)
			var mapItem map[string]interface{}
			_ = json.Unmarshal(m, &mapItem)
			jsonStructData[i] = mapItem
		}
		resourceCount = len(jsonStructData)
	case "zpa_application_segment_browser_access":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.BrowserAccess
		jsonPayload, _, err := browseraccess.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		jsonStructData = make([]interface{}, len(jsonPayload))
		for i, item := range jsonPayload {
			m, _ := json.Marshal(item)
			var mapItem map[string]interface{}
			_ = json.Unmarshal(m, &mapItem)
			jsonStructData[i] = mapItem
		}
		resourceCount = len(jsonStructData)
	case "zpa_application_segment_inspection":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ApplicationSegmentInspection
		jsonPayload, _, err := applicationsegmentinspection.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_pra":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ApplicationSegmentPRA
		jsonPayload, _, err := applicationsegmentpra.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_ba_certificate":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.BACertificate
		jsonPayload, _, err := bacertificate.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_pra_approval_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PRAApproval
		jsonPayload, _, err := praapproval.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_pra_console_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PRAConsole
		jsonPayload, _, err := praconsole.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_pra_credential_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PRACredential
		jsonPayload, _, err := pracredential.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		includedSensitiveResources[resourceType] = true
	case "zpa_pra_portal_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PRAPortal
		jsonPayload, _, err := praportal.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_segment_group":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.SegmentGroup
		list, _, err := segmentgroup.GetAll(zpaClient)
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ServerGroup
		list, _, err := servergroup.GetAll(zpaClient)
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
	case "zpa_policy_access_rule":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PolicySetController
		list, _, err := policysetcontroller.GetAllByType(zpaClient, "ACCESS_POLICY")
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
	case "zpa_policy_timeout_rule":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PolicySetController
		list, _, err := policysetcontroller.GetAllByType(zpaClient, "TIMEOUT_POLICY")
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PolicySetController
		list, _, err := policysetcontroller.GetAllByType(zpaClient, "CLIENT_FORWARDING_POLICY")
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
	case "zpa_policy_inspection_rule":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PolicySetController
		list, _, err := policysetcontroller.GetAllByType(zpaClient, "INSPECTION_POLICY")
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.PolicySetController
		list, _, err := policysetcontroller.GetAllByType(zpaClient, "ISOLATION_POLICY")
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_provisioning_key":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ProvisioningKey
		jsonPayload, err := provisioningkey.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_service_edge_group":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.ServiceEdgeGroup
		jsonPayload, _, err := serviceedgegroup.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_lss_config_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.LSSConfigController
		jsonPayload, _, err := lssconfigcontroller.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.InspectionCustomControls
		jsonPayload, _, err := inspection_custom_controls.GetAll(zpaClient)
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.MicroTenants
		jsonPayload, _, err := microtenants.GetAll(zpaClient)
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		var filteredPayload []microtenants.MicroTenant
		for _, item := range jsonPayload {
			if item.ID != "0" {
				filteredPayload = append(filteredPayload, item)
			}
		}
		m, _ := json.Marshal(filteredPayload)
		resourceCount = len(filteredPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_dictionaries":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.DLPDictionaries
		list, err := dlpdictionaries.GetAll(ziaClient)
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
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.DLPEngines
		list, err := dlp_engines.GetAll(ziaClient)
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
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.DLPNotificationTemplates
		jsonPayload, err := dlp_notification_templates.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_web_rules":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.DLPWebRules
		jsonPayload, err := dlp_web_rules.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_rule":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.FilteringRules
		rules, err := filteringrules.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []filteringrules.FirewallFilteringRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Office 365 One Click Rule", "UCaaS One Click Rule", "Default Firewall Filtering Rule", "Recommended Firewall Rule", "Block All IPv6", "Block malicious IPs and domains", "Zscaler Proxy Traffic"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_destination_groups":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.IPDestinationGroups
		groups, err := ipdestinationgroups.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []ipdestinationgroups.IPDestinationGroups{}
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_ip_source_groups":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.IPSourceGroups
		groups, err := ipsourcegroups.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []ipsourcegroups.IPSourceGroups{}
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_service":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.NetworkServices
		services, err := networkservices.GetAllNetworkServices(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		servicesFiltered := []networkservices.NetworkServices{}
		for _, service := range services {
			if helpers.IsInList(service.Type, []string{"STANDARD", "PREDEFINED"}) {
				continue
			}
			servicesFiltered = append(servicesFiltered, service)
		}
		m, _ := json.Marshal(servicesFiltered)
		resourceCount = len(servicesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_service_groups":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.NetworkServiceGroups
		jsonPayload, err := networkservicegroups.GetAllNetworkServiceGroups(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_application_groups":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.NetworkApplicationGroups
		groups, err := networkapplicationgroups.GetAllNetworkApplicationGroups(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []networkapplicationgroups.NetworkApplicationGroups{}
		for _, rule := range groups {
			if helpers.IsInList(rule.Name, []string{"Microsoft Office365"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, rule)
		}
		m, _ := json.Marshal(groupsFiltered)
		resourceCount = len(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_gre_tunnel":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.GRETunnels
		jsonPayload, err := gretunnels.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_static_ip":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.StaticIPs
		jsonPayload, err := staticips.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_vpn_credentials":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.VPNCredentials
		jsonPayload, err := vpncredentials.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_location_management":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.LocationManagement
		// Get all parent locations
		jsonPayload, err := locationmanagement.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

		// Get all sublocations
		sublocationsPayload, err := locationmanagement.GetAllSublocations(ziaClient)
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
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.URLCategories
		list, err := urlcategories.GetAll(ziaClient)
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
			details, err := urlcategories.Get(ziaClient, items[i].ID)
			if err != nil {
				continue
			}
			items[i] = *details
		}
		m, _ := json.Marshal(items)
		resourceCount = len(items)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_url_filtering_rules":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.URLFilteringPolicies
		jsonPayload, err := urlfilteringpolicies.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_rule_labels":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.RuleLabels
		jsonPayload, err := rule_labels.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_auth_settings_urls":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.UserAuthenticationSettings
		exemptedUrls, err := user_authentication_settings.Get(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*user_authentication_settings.ExemptedUrls{exemptedUrls}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_sandbox_behavioral_analysis":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.SandboxSettings
		hashes, err := sandbox_settings.Get(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*sandbox_settings.BaAdvancedSettings{hashes}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_security_settings":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.SecurityPolicySettings
		urls, err := security_policy_settings.GetListUrls(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*security_policy_settings.ListUrls{urls}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_rule":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.ForwardingRules
		rules, err := forwarding_rules.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []forwarding_rules.ForwardingRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Client Connector Traffic Direct", "ZPA Pool For Stray Traffic", "ZIA Inspected ZPA Apps", "Fallback mode of ZPA Forwarding"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_zpa_gateway":
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.ZpaGateways
		gws, err := ziaClient.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		gwsFiltered := []zpa_gateways.ZPAGateways{}
		for _, gw := range gws {
			if helpers.IsInList(gw.Name, []string{"Auto ZPA Gateway"}) {
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
		structData := data.(map[string]interface{})

		resourceID, ok := structData["id"].(string)
		if !ok {
			resourceIDInt, ok := structData["id"].(int)
			if ok {
				resourceID = strconv.Itoa(resourceIDInt)
			} else {
				resourceIDFloat64, ok := structData["id"].(float64)
				if ok {
					resourceID = strconv.FormatInt(int64(resourceIDFloat64), 10)
				}
			}
		}
		if resourceID != "" {
			name := buildResourceName(resourceType, structData)
			fmt.Fprint(writer, buildCompositeID(resourceType, resourceID, name))
			err := tf.Import(cmd.Context(), resourceType+"."+name, resourceID)
			if err != nil {
				if strings.Contains(err.Error(), "Resource already managed by Terraform") {
					managedResourceTypes[resourceType] = true
				} else {
					log.Printf("[ERROR] error while running import: %v", err)
				}
			}
		}
	}

	stateFile := workingDir + "/terraform.tfstate"
	helpers.RemoveTcpPortRangesFromState(stateFile)
}

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
