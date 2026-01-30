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
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/alerts"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/cloudapplications/risk_profiles"
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
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/forwarding_control_policy/proxies"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/ftp_control_policy"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/location/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/malware_protection"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/mobile_threat_settings"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/nat_control_policies"
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
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/vzen_clusters"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/vzen_nodes"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zia/services/workloadgroups"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentbrowseraccess"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/c2c_ip_ranges"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbibannercontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbicertificatecontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/cloudbrowserisolation/cbiprofilecontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/microtenants"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/private_cloud_group"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praapproval"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praconsole"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/pracredential"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/pracredentialpool"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/privilegedremoteaccess/praportal"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/userportal/portal_controller"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa/services/userportal/portal_link"
	ztwdnsforwardinggw "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/forwarding_gateways/dns_forwarding_gateway"
	ztwziaforwardinggw "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/forwarding_gateways/zia_forwarding_gateway"
	ztwlocationtemplate "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/locationmanagement/locationtemplate"
	ztwaccountgroups "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/partner_integrations/account_groups"
	ztwpubliccloudinfo "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/partner_integrations/public_cloud_info"
	ztwforwardingrules "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policy_management/forwarding_rules"
	ztwtrafficdnsrules "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policy_management/traffic_dns_rules"
	ztwtrafficlogrules "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policy_management/traffic_log_rules"
	ztwipdestinationgroups "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policyresources/ipdestinationgroups"
	ztwipgroups "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policyresources/ipgroups"
	ztwipsourcegroups "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policyresources/ipsourcegroups"
	ztwnetworkservicegroups "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policyresources/networkservicegroups"
	ztwnetworkservices "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/policyresources/networkservices"
	ztwprovisioningurl "github.com/zscaler/zscaler-sdk-go/v3/zscaler/ztw/services/provisioning/provisioning_url"
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
	"zpa_pra_credential_pool":                           ":id",
	"zpa_pra_console_controller":                        ":id",
	"zpa_pra_portal_controller":                         ":id",
	"zpa_provisioning_key":                              ":id",
	"zpa_service_edge_group":                            ":id",
	"zpa_lss_config_controller":                         ":id",
	"zpa_inspection_custom_controls":                    ":id",
	"zpa_microtenant_controller":                        ":id",
	"zpa_user_portal_controller":                        ":id",
	"zpa_user_portal_link":                              ":id",
	"zpa_c2c_ip_ranges":                                 ":id",
	"zpa_private_cloud_group":                           ":id",
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
	"zia_nat_control_rules":                             ":id",
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
	"zia_virtual_service_edge_cluster":                  ":id",
	"zia_virtual_service_edge_node":                     ":id",
	"zia_risk_profiles":                                 ":id",
	"zia_workload_groups":                               ":id",
	"zia_ftp_control_policy":                            ":id",
	"zia_subscription_alert":                            ":id",
	"zia_forwarding_control_proxies":                    ":id",
	"zia_mobile_malware_protection_policy":              ":id",
	"ztc_ip_destination_groups":                         ":id",
	"ztc_ip_source_groups":                              ":id",
	"ztc_ip_pool_groups":                                ":id",
	"ztc_network_services":                              ":id",
	"ztc_network_service_groups":                        ":id",
	"ztc_account_groups":                                ":id",
	"ztc_public_cloud_info":                             ":id",
	"ztc_location_template":                             ":id",
	"ztc_provisioning_url":                              ":id",
	"ztc_traffic_forwarding_rule":                       ":id",
	"ztc_traffic_forwarding_dns_rule":                   ":id",
	"ztc_traffic_forwarding_log_rule":                   ":id",
	"ztc_forwarding_gateway":                            ":id",
	"ztc_dns_forwarding_gateway":                        ":id",
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
	errorString := err.Error()

	if strings.Contains(errorString, licenseErrorMsg) {
		// Try to extract JSON from the error string
		jsonStart := strings.Index(errorString, "{")
		jsonEnd := strings.LastIndex(errorString, "}")

		if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
			jsonStr := errorString[jsonStart : jsonEnd+1]
			apiErr := &ZPAAPIErrorResponse{}
			if jsonErr := json.Unmarshal([]byte(jsonStr), &apiErr); jsonErr == nil {
				// Check if it's a feature flag permission denied error
				if apiErr.ID == "authz.featureflag.permission.denied" {
					// Check if the reason contains feature flag information
					if strings.Contains(apiErr.Reason, "feature.") || strings.Contains(apiErr.Reason, "Feature flag") {
						return true, apiErr.Reason
					}
					// Also check params if they exist
					for _, param := range apiErr.Params {
						if strings.HasPrefix(param, "feature.") {
							return true, apiErr.Reason
						}
					}
				}
			}
		}
	}
	return false, ""
}

func runImport() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		managedResourceTypes := make(map[string]bool)
		includedSensitiveResources := make(map[string]bool)
		if resources != "" {
			var resourceTypes []string
			switch resources {
			case "*":
				for resource := range resourceImportStringFormats {
					resourceTypes = append(resourceTypes, resource)
				}
			case "zia", "zpa", "ztc":
				for resource := range resourceImportStringFormats {
					if strings.HasPrefix(resource, resources) {
						resourceTypes = append(resourceTypes, resource)
					}
				}
			default:
				resourceTypes = strings.Split(resources, ",")
			}
			excludedResourcesTypes := strings.Split(excludedResources, ",")

			// Filter out excluded resources for accurate progress count
			filteredResourceTypes := []string{}
			for _, rt := range resourceTypes {
				resourceTyp := strings.Trim(rt, " ")
				if !helpers.IsInList(resourceTyp, excludedResourcesTypes) {
					filteredResourceTypes = append(filteredResourceTypes, resourceTyp)
				}
			}

			// Initialize progress tracker if enabled (resource imports + 3 post-processing steps)
			if progress && len(filteredResourceTypes) > 0 {
				totalSteps := len(filteredResourceTypes) + 3 // +3 for post-processing steps
				progressTracker = NewProgressTracker(totalSteps)
				fmt.Printf("🎯 Starting import of \033[33m%d resources\033[0m with progress tracking\n\n", len(filteredResourceTypes))
			}

			for _, resourceTyp := range filteredResourceTypes {
				if progress {
					progressTracker.UpdateWithOutput(fmt.Sprintf("Importing %s", resourceTyp))
				}
				importResource(cmd.Context(), cmd, cmd.OutOrStdout(), resourceTyp, managedResourceTypes, includedSensitiveResources)
			}

			// Post-process reference replacement after all imports are complete
			// This includes both requested resources and automatically imported referenced resources
			if len(resourceTypes) > 0 {
				// Get the working directory from the first resource type
				_, _, workingDir := initTf(cmd.Context(), resourceTypes[0])

				// Set up log collection if enabled (now that we know the working directory)
				if collectLogs {
					setupLogCollection(workingDir)
				}

				if !progress {
					log.Printf("🔄 Running final post-processing after all imports are complete...")
				}

				// First: Process resource-to-resource references
				if progress {
					progressTracker.UpdateWithOutput("Processing resource references")
				}
				err := helpers.PostProcessReferences(workingDir, verbose)
				if err != nil {
					log.Printf("⚠️  Resource post-processing failed: %v", err)
				}

				// Second: Parse the resource map first
				if !progress {
					log.Printf("🔄 Parsing resource outputs for intelligent reference resolution...")
				}
				resourceMap, parseErr := helpers.ParseOutputsFile(workingDir)
				if parseErr != nil {
					log.Printf("[WARNING] Failed to parse outputs.tf: %v", parseErr)
					resourceMap = make(map[string]string)
				}

				// Third: Process data source references (only once, at the very end) with resource map
				if progress {
					progressTracker.UpdateWithOutput("Processing data source references")
				}
				if !progress {
					log.Printf("🔄 Running data source post-processing after all imports are complete...")
				}
				err = helpers.PostProcessDataSourcesWithResourceMap(workingDir, resourceMap, verbose)
				if err != nil {
					log.Printf("⚠️  Data source post-processing failed: %v", err)
				}

				// Fourth: Process ZPA policy data source references (only for ZPA resources)
				hasZPAResources := false
				for _, rt := range resourceTypes {
					if strings.HasPrefix(rt, "zpa_") || rt == "zpa" {
						hasZPAResources = true
						break
					}
				}
				if hasZPAResources {
					if progress {
						progressTracker.UpdateWithOutput("Processing ZPA policy references")
					}
					err = helpers.PostProcessZPAPolicyDataSources(workingDir, resourceMap, verbose)
					if err != nil {
						log.Printf("⚠️  ZPA policy data source post-processing failed: %v", err)
					}
				}

				// Finish progress tracking
				if progress {
					progressTracker.Finish()
				}
			}

			if len(managedResourceTypes) > 0 {
				fmt.Println("\033[33mThe following resources are already managed by Terraform:\033[0m")
				for resource := range managedResourceTypes {
					fmt.Println(resource)
				}
			}

			// Generate and display comprehensive import summary
			if len(resourceTypes) > 0 {
				_, _, workingDir := initTf(cmd.Context(), resourceTypes[0])
				helpers.PrintImportSummary(workingDir)

				// Run terraform validate if requested
				if validateTerraform {
					err := validateGeneratedFiles(workingDir)
					if err != nil {
						log.Printf("⚠️  Validation completed with errors: %v", err)
					}
				}
			}
			if includedSensitiveResources["zpa_pra_credential_controller"] {
				fmt.Println("\033[33mThe resource zpa_pra_credential_controller contains sensitive values not included in the generated code.\033[0m")
			}

			// Cleanup log collection if it was enabled
			if collectLogs {
				cleanupLogCollection()
			}
			return
		}

		// Set up log collection and progress tracking for single resource import if enabled
		_, _, workingDir := initTf(cmd.Context(), resourceType_)

		if collectLogs {
			setupLogCollection(workingDir)
		}

		// Initialize progress tracker for single resource import
		if progress {
			progressTracker = NewProgressTracker(1) // Single resource
			fmt.Printf("🎯 Starting single resource import with progress tracking\n\n")
			progressTracker.UpdateWithOutput(fmt.Sprintf("Importing %s", resourceType_))
		}

		importResource(cmd.Context(), cmd, cmd.OutOrStdout(), resourceType_, managedResourceTypes, includedSensitiveResources)

		// Finish progress tracking for single resource
		if progress {
			progressTracker.Finish()
		}

		// Cleanup log collection if it was enabled for single resource import
		if collectLogs {
			cleanupLogCollection()
		}

		// Post-processing is handled by the main runImport function after all imports are complete

		if len(managedResourceTypes) > 0 {
			fmt.Println("\033[33mThe following resources are already managed by Terraform:\033[0m")
			for resource := range managedResourceTypes {
				fmt.Println(resource)
			}
		}

		// Generate and display comprehensive import summary for single resource (reuse workingDir)
		helpers.PrintImportSummary(workingDir)
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

		// First get the list to know what IDs exist
		list, _, err := appconnectorgroup.GetAll(ctx, service)
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
			} else {
				log.Fatal(err)
			}
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
				return
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
				return
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
				return
			} else {
				log.Fatal(err)
			}
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		includedSensitiveResources[resourceType] = true
	case "zpa_pra_credential_pool":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := pracredentialpool.GetAll(ctx, service)
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
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
				return
			} else {
				log.Fatal(err)
			}
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_user_portal_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := portal_controller.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_user_portal_link":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := portal_link.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_c2c_ip_ranges":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := c2c_ip_ranges.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_private_cloud_group":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := private_cloud_group.GetAll(ctx, service)
		if err != nil {
			isLicErr, reason := isLicenseError(err)
			// If it's a license error, log and continue, otherwise, terminate.
			if isLicErr {
				log.Printf("[WARNING] License error encountered: %s. Continuing with the import.", reason)
				return
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
				return
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
				return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
		rules, err := filteringrules.GetAll(ctx, service, nil)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		rulesFiltered := []filteringrules.FirewallFilteringRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Default Firewall Filtering Rule"}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		m, _ := json.Marshal(rulesFiltered)
		resourceCount = len(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_nat_control_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := nat_control_policies.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_destination_groups":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		groups, err := ipdestinationgroups.GetAll(ctx, service, "")
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
		services, err := networkservices.GetAllNetworkServices(ctx, service, nil, nil)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
		jsonPayload, err := networkapplicationgroups.GetAllNetworkApplicationGroups(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "zia_traffic_forwarding_gre_tunnel":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := gretunnels.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

		// Get all sublocations
		sublocationsPayload, err := locationmanagement.GetAllSublocations(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ = json.Marshal(sublocationsPayload)
		subResourceCount := len(sublocationsPayload)
		var subJsonStructData []interface{}
		_ = json.Unmarshal(m, &subJsonStructData)

		// Process sublocations to ensure state field is preserved
		for i, subLocation := range subJsonStructData {
			if subLocationMap, ok := subLocation.(map[string]interface{}); ok {
				// If state is null or missing in sublocation, set it to empty string
				if stateValue, exists := subLocationMap["state"]; !exists || stateValue == nil {
					subLocationMap["state"] = ""
				}
				subJsonStructData[i] = subLocationMap
			}
		}

		// Append sublocations to the main jsonStructData slice
		jsonStructData = append(jsonStructData, subJsonStructData...)

		resourceCount += subResourceCount

	case "zia_url_categories":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := urlcategories.GetAll(ctx, service, true, false, "ALL")
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "zia_url_filtering_rules":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := urlfilteringpolicies.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		jsonPayload := []*security_policy_settings.ListUrls{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "all_urls"
		}
	case "zia_forwarding_control_proxies":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := proxies.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		rulesFiltered := []proxies.Proxies{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{}) {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_forwarding_control_rule":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := forwarding_rules.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		rulesFiltered := []sandbox_rules.SandboxRules{}
		for _, rule := range rules {
			if helpers.IsInList(rule.Name, []string{"Default BA Rule"}) {
				continue
			}
			// rule.Order = 127
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
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
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		jsonPayload := []*end_user_notification.UserNotificationSettings{notification}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "enduser_notification"
		}
	case "zia_mobile_malware_protection_policy":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		mobileSettings, err := mobile_threat_settings.GetMobileThreatSettings(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		jsonPayload := []*mobile_threat_settings.MobileAdvanceThreatSettings{mobileSettings}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "mobile_settings"
		}
	case "zia_ftp_control_policy":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		ftpControl, err := ftp_control_policy.GetFTPControlPolicy(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		jsonPayload := []*ftp_control_policy.FTPControlPolicy{ftpControl}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "ftp_control"
		}
	case "zia_virtual_service_edge_cluster":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := vzen_clusters.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_virtual_service_edge_node":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := vzen_nodes.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_risk_profiles":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := risk_profiles.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_workload_groups":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := workloadgroups.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_subscription_alert":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := alerts.GetAll(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_ip_destination_groups":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZTCService
		groups, err := ztwipdestinationgroups.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []ztwipdestinationgroups.IPDestinationGroups{}
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_ip_source_groups":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZTCService
		groups, err := ztwipsourcegroups.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(groups)
		_ = json.Unmarshal(m, &jsonStructData)
		groupsFiltered := []ztwipsourcegroups.IPSourceGroups{}
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		resourceCount = len(groupsFiltered)
		m, _ = json.Marshal(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_ip_pool_groups":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZTCService
		groups, err := ztwipgroups.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(groups)
		_ = json.Unmarshal(m, &jsonStructData)
		groupsFiltered := []ztwipgroups.IPGroups{}
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"All IPv4"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		resourceCount = len(groupsFiltered)
		m, _ = json.Marshal(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_network_services":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZTCService
		services, err := ztwnetworkservices.GetAllNetworkServices(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		servicesFiltered := []ztwnetworkservices.NetworkServices{}
		for _, service := range services {
			if helpers.IsInList(service.Type, []string{"STANDARD", "PREDEFINED"}) {
				continue
			}
			servicesFiltered = append(servicesFiltered, service)
		}
		m, _ := json.Marshal(servicesFiltered)
		resourceCount = len(servicesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "ztc_network_service_groups":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZTCService
		jsonPayload, err := ztwnetworkservicegroups.GetAllNetworkServiceGroups(ctx, service)
		if err != nil {
			shouldSkip, message := helpers.HandleZIAAPIError(err, resourceType)
			if shouldSkip {
				log.Printf("[WARN] Skipping resource import for %s: %s", resourceType, message)
				return
			}
			// If not a handled error, log it and skip gracefully
			log.Printf("[ERROR] error occurred while fetching resource %s: %v", resourceType, err)
			return
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_location_template":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		templates, err := ztwlocationtemplate.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(templates)
		m, _ := json.Marshal(templates)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_provisioning_url":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		provURLs, err := ztwprovisioningurl.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(provURLs)
		m, _ := json.Marshal(provURLs)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_traffic_forwarding_rule":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		rules, err := ztwforwardingrules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		// Filter out default rules
		rulesFiltered := []ztwforwardingrules.ForwardingRules{}
		for _, rule := range rules {
			if rule.DefaultRule {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_traffic_forwarding_dns_rule":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		rules, err := ztwtrafficdnsrules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		// Filter out default/predefined rules
		rulesFiltered := []ztwtrafficdnsrules.ECDNSRules{}
		for _, rule := range rules {
			if rule.DefaultRule || rule.Predefined {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_traffic_forwarding_log_rule":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		rules, err := ztwtrafficlogrules.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		// Filter out default rules
		rulesFiltered := []ztwtrafficlogrules.ECTrafficLogRules{}
		for _, rule := range rules {
			if rule.DefaultRule {
				continue
			}
			rulesFiltered = append(rulesFiltered, rule)
		}
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_forwarding_gateway":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		gateways, err := ztwziaforwardinggw.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(gateways)
		m, _ := json.Marshal(gateways)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_dns_forwarding_gateway":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		gateways, err := ztwdnsforwardinggw.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(gateways)
		m, _ := json.Marshal(gateways)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_account_groups":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		groups, err := ztwaccountgroups.GetAllAccountGroups(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(groups)
		m, _ := json.Marshal(groups)
		_ = json.Unmarshal(m, &jsonStructData)

	case "ztc_public_cloud_info":
		if api.ZTCService == nil {
			log.Fatal("ZTC service is not initialized")
		}
		service := api.ZTCService
		cloudInfo, err := ztwpubliccloudinfo.GetAllPublicCloudInfo(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(cloudInfo)
		m, _ := json.Marshal(cloudInfo)
		_ = json.Unmarshal(m, &jsonStructData)

	default:
		log.Printf("%q is not yet supported for state import", resourceType)
		return
	}

	if resourceCount == 0 {
		return
	}

	tf, _, workingDir := initTf(ctx, resourceType)
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
			// Only print terraform import commands when progress bar is disabled
			if !progress || noProgress {
				_, _ = fmt.Fprint(writer, buildCompositeID(resourceType, resourceID, name))
			}
			err := tf.Import(ctx, resourceType+"."+name, resourceID)
			if err != nil {
				if strings.Contains(err.Error(), "Resource already managed by Terraform") {
					managedResourceTypes[resourceType] = true
				} else {
					log.Printf("[ERROR] error while running import: %v", err)
				}
			}
		}
	}

	// Automatically import referenced resources
	// TEMPORARILY DISABLED to prevent recursive loops and multiple post-processing runs
	// importReferencedResources(ctx, cmd, writer, resourceType, jsonStructData, managedResourceTypes, includedSensitiveResources)

	stateFile := workingDir + "/terraform.tfstate"
	helpers.RemoveTcpPortRangesFromState(stateFile)
}

// importReferencedResources is currently unused but kept for potential future use
//
//nolint:unused // importReferencedResources automatically imports resources that are referenced by the imported resource
func importReferencedResources(ctx context.Context, cmd *cobra.Command, writer io.Writer, resourceType string, jsonStructData []interface{}, managedResourceTypes map[string]bool, includedSensitiveResources map[string]bool) {
	// Define resource reference mappings (using API field names)
	referenceMappings := map[string]map[string]string{
		"zpa_server_group": {
			"appConnectorGroups": "zpa_app_connector_group",
		},
		"zpa_application_segment": {
			"serverGroups": "zpa_server_group",
		},
	}

	// Get the reference mappings for this resource type
	mappings, exists := referenceMappings[resourceType]
	if !exists {
		return // No referenced resources to import
	}

	// Collect all referenced resource IDs
	referencedResourceIDs := make(map[string][]string) // resourceType -> []resourceIDs

	for _, data := range jsonStructData {
		structData := data.(map[string]interface{})

		// Check each reference mapping
		for attributeName, referencedResourceType := range mappings {
			if referencedData, exists := structData[attributeName]; exists {
				// Handle both single objects and arrays
				var referencedItems []interface{}
				if referencedArray, ok := referencedData.([]interface{}); ok {
					referencedItems = referencedArray
				} else if referencedObject, ok := referencedData.(map[string]interface{}); ok {
					referencedItems = []interface{}{referencedObject}
				}

				// Extract IDs from referenced items
				for _, item := range referencedItems {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if id, exists := itemMap["id"]; exists {
							var resourceID string
							switch v := id.(type) {
							case string:
								resourceID = v
							case int:
								resourceID = strconv.Itoa(v)
							case float64:
								resourceID = strconv.FormatInt(int64(v), 10)
							}
							if resourceID != "" {
								referencedResourceIDs[referencedResourceType] = append(referencedResourceIDs[referencedResourceType], resourceID)
							}
						}
					}
				}
			}
		}
	}

	// Import each referenced resource type
	for referencedResourceType, resourceIDs := range referencedResourceIDs {
		// Remove duplicates
		uniqueIDs := make(map[string]bool)
		var uniqueResourceIDs []string
		for _, id := range resourceIDs {
			if !uniqueIDs[id] {
				uniqueIDs[id] = true
				uniqueResourceIDs = append(uniqueResourceIDs, id)
			}
		}

		if len(uniqueResourceIDs) > 0 {
			log.Printf("[INFO] Auto-importing %d referenced %s resources", len(uniqueResourceIDs), referencedResourceType)
			// Import the referenced resources directly without calling importResource
			// to prevent recursive loops and multiple post-processing runs
			directImportReferencedResource(ctx, cmd, writer, referencedResourceType, uniqueResourceIDs, managedResourceTypes, includedSensitiveResources)
		}
	}

	// Post-processing will be handled by the main runImport function after all resource types are processed
}

// This prevents recursive loops when importing referenced resources.
//
//nolint:unused // directImportReferencedResource imports referenced resources directly without triggering automatic reference detection
func directImportReferencedResource(_ context.Context, _ *cobra.Command, _ io.Writer, resourceType string, resourceIDs []string, _ map[string]bool, _ map[string]bool) {
	// For now, just log that we would import these resources
	// The actual import logic will be handled by the main importResource function
	// This prevents the recursive loop while still allowing the referenced resources to be imported
	log.Printf("[DEBUG] Would import %d %s resources with IDs: %v", len(resourceIDs), resourceType, resourceIDs)

	// The referenced resources will be imported when the user explicitly imports them
	// or when they are imported as part of a broader import command
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
