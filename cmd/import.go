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

package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"strconv"

	"fmt"

	"github.com/spf13/cobra"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/advanced_settings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/advancedthreatsettings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/dlp/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/dlp/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/dlp/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/dlp/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/end_user_notification"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/filetypecontrol"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewalldnscontrolpolicies"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallipscontrolpolicies"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/networkapplicationgroups"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/networkservicegroups"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/forwarding_control_policy/forwarding_rules"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/location/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/malware_protection"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/sandbox/sandbox_rules"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/sandbox/sandbox_settings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/sslinspection"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentbrowseraccess"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbibannercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbicertificatecontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbiprofilecontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/microtenants"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praapproval"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praconsole"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/pracredential"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praportal"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
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
	"zpa_cloud_browser_isolation_banner":                ":id",
	"zpa_cloud_browser_isolation_certificate":           ":id",
	"zpa_cloud_browser_isolation_external_profile":      ":id",
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
	"zia_sandbox_rules":                                 ":id",
	"zia_file_type_control_rules":                       ":id",
	"zia_ssl_inspection_rules":                          ":id",
	"zia_firewall_dns_rule":                             ":id",
	"zia_firewall_ips_rule":                             ":id",
	"zia_advanced_settings":                             ":id",
	"zia_atp_malicious_urls":                            ":id",
	"zia_atp_security_exceptions":                       ":id",
	"zia_advanced_threat_settings":                      ":id",
	"zia_atp_malware_inspection":                        ":id",
	"zia_atp_malware_protocols":                         ":id",
	"zia_atp_malware_settings":                          ":id",
	"zia_atp_malware_policy":                            ":id",
	"zia_url_filtering_and_cloud_app_settings":          ":id",
	"zia_end_user_notification":                         ":id",
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

type ZPAAPIErrorResponse struct {
	Params []string `json:"params"`
	ID     string   `json:"id"`
	Reason string   `json:"reason"`
}

func isLicenseError(err error) (bool, string) {
	const licenseErrorMsg = "authz.featureflag.permission.denied"
	if strings.Contains(err.Error(), licenseErrorMsg) {
		apiErr := &ZPAAPIErrorResponse{}
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
				importResource(cmd.Context(), cmd, cmd.OutOrStdout(), resourceTyp, managedResourceTypes, includedSensitiveResources)

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
		importResource(cmd.Context(), cmd, cmd.OutOrStdout(), resourceType_, managedResourceTypes, includedSensitiveResources)

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

func importResource(ctx context.Context, cmd *cobra.Command, writer io.Writer, resourceType string, managedResourceTypes map[string]bool, includedSensitiveResources map[string]bool) {
	var jsonStructData []interface{}
	resourceCount := 0
	switch resourceType {
	case "zpa_app_connector_group":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		list, _, err := appconnectorgroup.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		jsonPayload, _, err := appservercontroller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := applicationsegment.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := applicationsegmentbrowseraccess.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := applicationsegmentinspection.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_pra":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := applicationsegmentpra.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_external_profile":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		allProfiles, _, err := cbiprofilecontroller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}

		for _, profile := range allProfiles {
			profileDetails, _, err := cbiprofilecontroller.GetByNameOrID(ctx, service, profile.ID)
			if err != nil {
				log.Printf("error retrieving profile %s: %v", profile.ID, err)
				continue
			}
			data, _ := json.Marshal(profileDetails)
			var profileMap map[string]interface{}
			_ = json.Unmarshal(data, &profileMap)
			helpers.ConvertAttributes(profileMap) // Convert attributes here
			jsonStructData = append(jsonStructData, profileMap)
		}

		resourceCount = len(jsonStructData)
	case "zpa_cloud_browser_isolation_banner":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		// Retrieve all resources using GetAll
		allBanners, _, err := cbibannercontroller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}

		// Collect the payload data
		for _, banner := range allBanners {
			// Use the ID or name to get the full details of the banner
			bannerDetails, _, err := cbibannercontroller.GetByNameOrID(ctx, service, banner.ID)
			if err != nil {
				log.Printf("error retrieving banner %s: %v", banner.ID, err)
				continue
			}
			data, _ := json.Marshal(bannerDetails)
			var bannerMap map[string]interface{}
			_ = json.Unmarshal(data, &bannerMap)
			jsonStructData = append(jsonStructData, bannerMap)
		}

		resourceCount = len(jsonStructData)
	case "zpa_cloud_browser_isolation_certificate":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		// Retrieve all resources using GetAll
		allCerts, _, err := cbicertificatecontroller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}

		for _, certificate := range allCerts {
			// Skip the certificate named "Zscaler Root Certificate"
			if certificate.Name == "Zscaler Root Certificate" {
				continue
			}
			certDetails, _, err := cbicertificatecontroller.GetByNameOrID(ctx, service, certificate.ID)
			if err != nil {
				log.Printf("error retrieving certificate %s: %v", certificate.ID, err)
				continue
			}
			data, _ := json.Marshal(certDetails)
			var certMap map[string]interface{}
			_ = json.Unmarshal(data, &certMap)
			jsonStructData = append(jsonStructData, certMap)
		}

		resourceCount = len(jsonStructData)
	case "zpa_pra_approval_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := praapproval.GetAll(ctx, service)
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
	case "zpa_pra_console_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := praconsole.GetAll(ctx, service)
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
	case "zpa_pra_credential_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := pracredential.GetAll(ctx, service)
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
			} else {
				log.Fatal(err)
			}
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		includedSensitiveResources[resourceType] = true
	case "zpa_pra_portal_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := praportal.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := segmentgroup.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := servergroup.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := policysetcontroller.GetAllByType(ctx, service, "ACCESS_POLICY")
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := policysetcontroller.GetAllByType(ctx, service, "TIMEOUT_POLICY")
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := policysetcontroller.GetAllByType(ctx, service, "CLIENT_FORWARDING_POLICY")
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := policysetcontroller.GetAllByType(ctx, service, "INSPECTION_POLICY")
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		list, _, err := policysetcontroller.GetAllByType(ctx, service, "ISOLATION_POLICY")
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, err := provisioningkey.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_service_edge_group":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		edgeGroups, _, err := serviceedgegroup.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		for i, group := range edgeGroups {
			if !group.GraceDistanceEnabled {
				// Remove or nullify these attributes if grace_distance_enabled is false
				edgeGroups[i].GraceDistanceEnabled = false // Assuming you can set this false for simplicity in output
				edgeGroups[i].GraceDistanceValue = ""      // Making empty as we don't output if false
				edgeGroups[i].GraceDistanceValueUnit = ""
			}
		}
		resourceCount = len(edgeGroups)
		m, _ := json.Marshal(edgeGroups)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_lss_config_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := lssconfigcontroller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := inspection_custom_controls.GetAll(ctx, service)
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
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := microtenants.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		list, err := dlpdictionaries.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		list, err := dlp_engines.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := dlp_notification_templates.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_web_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := dlp_web_rules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_rule":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := filteringrules.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		groups, err := ipdestinationgroups.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		groups, err := ipsourcegroups.GetAll(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		services, err := networkservices.GetAllNetworkServices(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := networkservicegroups.GetAllNetworkServiceGroups(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_application_groups":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		groups, err := networkapplicationgroups.GetAllNetworkApplicationGroups(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := gretunnels.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_static_ip":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := staticips.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_vpn_credentials":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := vpncredentials.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_location_management":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := locationmanagement.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

		// Get all sublocations
		sublocationsPayload, err := locationmanagement.GetAllSublocations(ctx, service)
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
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		list, err := urlcategories.GetAll(ctx, service)
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
			details, err := urlcategories.Get(ctx, service, items[i].ID)
			if err != nil {
				continue
			}
			items[i] = *details
		}
		m, _ := json.Marshal(items)
		resourceCount = len(items)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_url_filtering_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := urlfilteringpolicies.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_rule_labels":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := rule_labels.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "zia_auth_settings_urls":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := user_authentication_settings.Get(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*user_authentication_settings.ExemptedUrls{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "all_urls"
		}
	case "zia_sandbox_behavioral_analysis":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		hashes, err := sandbox_settings.Get(ctx, service)
		if err != nil {
			// Handle the error response body and parse it for ZIA-specific errors
			apiErrorResponse := err.Error() // Assuming error contains response
			shouldSkip, message := helpers.HandleZIAError([]byte(apiErrorResponse))
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		jsonPayload := []*sandbox_settings.BaAdvancedSettings{hashes}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "sandbox_settings"
		}
	case "zia_security_settings":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := security_policy_settings.GetListUrls(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*security_policy_settings.ListUrls{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "all_urls"
		}
	case "zia_forwarding_control_rule":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := forwarding_rules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []forwarding_rules.ForwardingRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Client Connector Traffic Direct", "ZPA Pool For Stray Traffic", "ZIA Inspected ZPA Apps", "Fallback mode of ZPA Forwarding"}) {
				continue
			}
			// Process dest_countries to remove "COUNTRY_" prefix
			for i, country := range rule.DestCountries {
				rule.DestCountries[i] = strings.TrimPrefix(country, "COUNTRY_")
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_zpa_gateway":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		service := api.ZIAService
		gws, err := zpa_gateways.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		gwsFiltered := []zpa_gateways.ZPAGateways{}
		for _, gw := range gws {
			if helpers.IsInList(gw.Name, []string{"Auto ZPA Gateway"}) {
				continue
			}
			// Ensure type is always "ZPA"
			gw.Type = "ZPA"
			gwsFiltered = append(gwsFiltered, gw)
		}
		resourceCount = len(gwsFiltered)
		m, _ := json.Marshal(gwsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_sandbox_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := sandbox_rules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []sandbox_rules.SandboxRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Default BA Rule"}) {
				continue
			}
			rule.Order = 127
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_ssl_inspection_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := sslinspection.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []sslinspection.SSLInspectionRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{
				"Office365 Inspection", "Zscaler Recommended Exemptions", "Inspect Remote Users",
				"Office 365 One Click", "UCaaS One Click", "Default SSL Inspection Rule"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_file_type_control_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := filetypecontrol.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_ips_rule":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := firewallipscontrolpolicies.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []firewallipscontrolpolicies.FirewallIPSRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Default Cloud IPS Rule"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_dns_rule":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := firewalldnscontrolpolicies.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		rulesFiltered := []firewalldnscontrolpolicies.FirewallDNSRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"ZPA Resolver for Road Warrior",
				"ZPA Resolver for Locations", "Critical risk DNS categories", "Critical risk DNS tunnels",
				"High risk DNS categories", "High risk DNS tunnels", "Risky DNS categories",
				"Risky DNS tunnels", "Office 365 One Click Rule", "Block DNS Tunnels",
				"Block Filesharing DNS", "Block Gaming DNS", "UCaaS One Click Rule",
				"Fallback ZPA Resolver for Locations", "Fallback ZPA Resolver for Road Warrior", "Unknown DNS Traffic",
				"Default Firewall DNS Rule"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "zia_advanced_settings":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		advSettings, err := advanced_settings.GetAdvancedSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*advanced_settings.AdvancedSettings{advSettings}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		// Force the "id" to be "advanced_settings"
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "advanced_settings"
		}

	case "zia_atp_malicious_urls":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := advancedthreatsettings.GetMaliciousURLs(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*advancedthreatsettings.MaliciousURLs{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "all_urls"
		}

	case "zia_atp_security_exceptions":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := advancedthreatsettings.GetSecurityExceptions(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*advancedthreatsettings.SecurityExceptions{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "bypass_url"
		}

	case "zia_advanced_threat_settings":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := advancedthreatsettings.GetAdvancedThreatSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*advancedthreatsettings.AdvancedThreatSettings{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "advanced_threat_settings"
		}

	case "zia_atp_malware_inspection":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := malware_protection.GetATPMalwareInspection(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*malware_protection.ATPMalwareInspection{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "inspection"
		}

	case "zia_atp_malware_protocols":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := malware_protection.GetATPMalwareProtocols(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*malware_protection.ATPMalwareProtocols{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "protocol"
		}

	case "zia_atp_malware_settings":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := malware_protection.GetATPMalwareSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*malware_protection.MalwareSettings{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "malware_settings"
		}

	case "zia_atp_malware_policy":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := malware_protection.GetATPMalwarePolicy(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*malware_protection.MalwarePolicy{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "policy"
		}
	case "zia_url_filtering_and_cloud_app_settings":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		urls, err := urlfilteringpolicies.GetUrlAndAppSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*urlfilteringpolicies.URLAdvancedPolicySettings{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "app_setting"
		}
	case "zia_end_user_notification":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		notification, err := end_user_notification.GetUserNotificationSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*end_user_notification.UserNotificationSettings{notification}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "enduser_notification"
		}
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
	generate(ctx, cmd, f, resourceType)
	// Ensure the file is closed and check for errors when closing
	if err := f.Close(); err != nil {
		log.Fatalf("failed to close file: %v", err)
	}

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
