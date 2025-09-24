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
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
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
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/conversion"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/nesting"
)

var allGeneratableResources = []string{
	// ZPA Resources
	"zpa_app_connector_group",
	"zpa_application_server",
	"zpa_application_segment",
	"zpa_application_segment_browser_access",
	"zpa_application_segment_inspection",
	"zpa_application_segment_pra",
	"zpa_cloud_browser_isolation_banner",
	"zpa_cloud_browser_isolation_certificate",
	"zpa_cloud_browser_isolation_external_profile",
	"zpa_segment_group",
	"zpa_server_group",
	"zpa_policy_access_rule",
	"zpa_policy_timeout_rule",
	"zpa_policy_forwarding_rule",
	"zpa_policy_inspection_rule",
	"zpa_policy_isolation_rule",
	"zpa_pra_approval_controller",
	"zpa_pra_console_controller",
	"zpa_pra_credential_controller",
	"zpa_pra_credential_pool",
	"zpa_pra_portal_controller",
	"zpa_provisioning_key",
	"zpa_service_edge_group",
	"zpa_lss_config_controller",
	"zpa_inspection_custom_controls",
	"zpa_microtenant_controller",
	"zpa_user_portal_controller",
	"zpa_user_portal_link",
	"zpa_c2c_ip_ranges",
	"zpa_private_cloud_group",

	// ZIA Resources
	"zia_dlp_dictionaries",
	"zia_dlp_engines",
	"zia_dlp_notification_templates",
	"zia_dlp_web_rules",
	"zia_firewall_filtering_rule",
	"zia_firewall_filtering_destination_groups",
	"zia_firewall_filtering_ip_source_groups",
	"zia_firewall_filtering_network_service",
	"zia_firewall_filtering_network_service_groups",
	"zia_firewall_filtering_network_application_groups",
	"zia_traffic_forwarding_gre_tunnel",
	"zia_traffic_forwarding_static_ip",
	"zia_traffic_forwarding_vpn_credentials",
	"zia_location_management",
	"zia_url_categories",
	"zia_url_filtering_rules",
	"zia_nat_control_rules",
	"zia_rule_labels",
	"zia_auth_settings_urls",
	"zia_sandbox_behavioral_analysis",
	"zia_security_settings",
	"zia_file_type_control_rules",
	"zia_forwarding_control_zpa_gateway",
	"zia_forwarding_control_rule",
	"zia_sandbox_rules",
	"zia_ssl_inspection_rules",
	"zia_firewall_dns_rule",
	"zia_firewall_ips_rule",
	"zia_advanced_settings",
	"zia_atp_security_exceptions",
	"zia_advanced_threat_settings",
	"zia_atp_malware_inspection",
	"zia_atp_malware_protocols",
	"zia_atp_malware_settings",
	"zia_atp_malware_policy",
	"zia_atp_malicious_urls",
	"zia_url_filtering_and_cloud_app_settings",
	"zia_end_user_notification",
	"zia_virtual_service_edge_cluster",
	"zia_virtual_service_edge_node",
	"zia_risk_profiles",
	"zia_workload_groups",
	"zia_ftp_control_policy",
	"zia_subscription_alert",
	"zia_forwarding_control_proxies",
	"zia_mobile_malware_protection_policy",
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

var generateCmd = &cobra.Command{
	Use:    "generate",
	Short:  "Fetch resources from the ZIA and Or ZPA API and generate the respective Terraform stanzas",
	Run:    generateResources(),
	PreRun: sharedPreRun,
}

func generateResources() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if resources != "" {
			var resourceTypes []string
			switch resources {
			case "*":
				resourceTypes = allGeneratableResources
			case "zia", "zpa":
				for _, resource := range resourceImportStringFormats {
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

			// Initialize progress tracker if enabled
			if progress && len(filteredResourceTypes) > 0 {
				progressTracker = NewProgressTracker(len(filteredResourceTypes))
				fmt.Printf("🎯 Starting generation of \033[33m%d resources\033[0m with progress tracking\n\n", len(filteredResourceTypes))
			}

			for _, resourceTyp := range filteredResourceTypes {
				if progress {
					progressTracker.UpdateWithOutput(fmt.Sprintf("Generating %s", resourceTyp))
				}
				// Pass cmd.Context() as the new ctx argument:
				generate(cmd.Context(), cmd, cmd.OutOrStdout(), resourceTyp)
			}

			// Finish progress tracking for generation
			if progress && len(filteredResourceTypes) > 0 {
				progressTracker.Finish()
			}

			// Set up log collection and run validation if requested and we generated resources
			if len(filteredResourceTypes) > 0 {
				// Get working directory from first resource type
				_, _, workingDir := initTf(filteredResourceTypes[0])

				// Set up log collection if enabled (now that we know the working directory)
				if collectLogs {
					setupLogCollection(workingDir)
				}

				// Run terraform validate if requested
				if validateTerraform {
					err := validateGeneratedFiles(workingDir)
					if err != nil {
						log.Printf("⚠️  Validation completed with errors: %v", err)
					}
				}
			}

			// Cleanup log collection if it was enabled
			if collectLogs {
				cleanupLogCollection()
			}
			return
		}

		// Set up log collection, progress tracking and validation for single resource generation
		if resourceType_ != "" {
			_, _, workingDir := initTf(resourceType_)

			// Set up log collection if enabled
			if collectLogs {
				setupLogCollection(workingDir)
			}

			// Initialize progress tracker for single resource generation
			if progress {
				progressTracker = NewProgressTracker(1) // Single resource
				fmt.Printf("🎯 Starting single resource generation with progress tracking\n\n")
				progressTracker.UpdateWithOutput(fmt.Sprintf("Generating %s", resourceType_))
			}

			// Generate the resource
			generate(cmd.Context(), cmd, cmd.OutOrStdout(), resourceType_)

			// Finish progress tracking for single resource
			if progress {
				progressTracker.Finish()
			}

			// Run terraform validate if requested
			if validateTerraform {
				err := validateGeneratedFiles(workingDir)
				if err != nil {
					log.Printf("⚠️  Validation completed with errors: %v", err)
				}
			}
		}

		// Cleanup log collection if it was enabled
		if collectLogs {
			cleanupLogCollection()
		}
	}
}

func buildResourceName(resourceType string, structData map[string]interface{}) string {
	// Define a variable for the short UUID.
	var shortUUID string

	// For resources that typically lack a unique identifier, generate a short UUID.
	resourcesRequiringShortID := []string{}
	if helpers.IsInList(resourceType, resourcesRequiringShortID) {
		// Generate a UUID and use the first 8 characters.
		shortUUID = uuid.New().String()[:8]
	}

	// Construct the resource ID using only the short UUID for specific resources, or use the existing logic for others.
	var resID string
	if shortUUID != "" {
		resID = fmt.Sprintf("resource_%s", shortUUID)
	} else if structData["id"] != nil {
		var resourceID string
		switch structData["id"].(type) {
		case float64:
			resourceID = fmt.Sprintf("%d", int64(structData["id"].(float64)))
		default:
			resourceID = structData["id"].(string)
		}

		// If we didn't set resID for the special case, use the default logic
		if resID == "" {
			resID = fmt.Sprintf("resource_%s_%s", resourceType, resourceID)
		}
	} else if structData["name"] != nil {
		name := structData["name"].(string)
		if name != "" {
			id := strings.ReplaceAll(strings.ToLower(helpers.Strip(name)), " ", "_")
			resID = fmt.Sprintf("resource_%s_%s", resourceType, id)
		}
	}

	if resID == "" {
		// Fallback to using the short UUID if no other identifier is available.
		resID = fmt.Sprintf("resource_%s", shortUUID)
	}

	resID = strings.ReplaceAll(resID, `"`, "")
	resID = strings.ReplaceAll(resID, `'`, "")
	resID = strings.ReplaceAll(resID, "`", "")
	resID = strings.ReplaceAll(resID, "__", "_")

	return resID
}

func initTf(resourceType string) (tf *tfexec.Terraform, r *tfjson.Schema, workingDir string) {
	// [1] Install or locate terraform as before
	execPath, err := exec.LookPath("terraform")
	if err != nil {
		log.Debugf("Terraform not found, installing...")
		// etc...
	} else {
		log.Debugf("Terraform already installed at: %s", execPath)
	}

	// [2] Determine workingDir from viper config
	cloudType := ""
	if strings.HasPrefix(resourceType, "zpa_") {
		cloudType = "zpa"
	} else if strings.HasPrefix(resourceType, "zia_") {
		cloudType = "zia"
	}
	workingDir = viper.GetString(cloudType + "-terraform-install-path")
	if workingDir == "" {
		workingDir = viper.GetString("terraform-install-path")
	}
	if workingDir == "" || workingDir == "." {
		workingDir = "./" + cloudType
	}
	log.Debugf("initializing Terraform in %s", workingDir)
	if _, err := os.Stat(workingDir); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(workingDir, 0750)
		if err != nil {
			log.Fatal("failed creating dir:"+workingDir, err)
		}
	}

	tf, err = tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		log.Fatal("NewTerraform failed", err)
	}

	// [3] Build the top block of provider config
	providerNamespace := viper.GetString(cloudType + "-provider-namespace")
	var providerConfig string
	if providerNamespace != "" {
		log.Debugf("Using custom provider namespace: %s", providerNamespace)
		providerConfig = fmt.Sprintf(`terraform {
  required_providers {
    %s = {
      source = "%s"
    }
  }
}
provider "%s" {
`, cloudType, providerNamespace, cloudType)
	} else {
		log.Debug("Using default provider namespace")
		providerConfig = fmt.Sprintf(`terraform {
  required_providers {
    %s = {
      source = "zscaler/%s"
    }
  }
}
provider "%s" {
`, cloudType, cloudType, cloudType)
	}

	// [4] Now handle credentials or advanced fields:
	// useLegacy := viper.GetString("use_legacy_client")

	switch cloudType {
	case "zpa":
		zpaClientID := viper.GetString("zpa_client_id")
		zpaClientSecret := viper.GetString("zpa_client_secret")
		zpaCustomerID := viper.GetString("zpa_customer_id")
		zpaCloud := viper.GetString("zpa_cloud")
		useLegacy := viper.GetString("use_legacy_client")

		// For OneAPI:
		clientID := viper.GetString("client_id")
		clientSecret := viper.GetString("client_secret")
		privateKey := viper.GetString("private_key")
		vanityDomain := viper.GetString("vanity_domain")
		zscalerCloud := viper.GetString("zscaler_cloud")
		customerID := viper.GetString("customer_id")
		microtenantID := viper.GetString("microtenant_id")

		// If the user is relying on environment variables for these, skip writing them inline
		if os.Getenv("ZPA_CLIENT_ID") == "" &&
			os.Getenv("ZPA_CLIENT_SECRET") == "" &&
			os.Getenv("ZPA_CUSTOMER_ID") == "" &&
			os.Getenv("ZPA_CLOUD") == "" &&
			os.Getenv("ZSCALER_USE_LEGACY_CLIENT") == "" &&
			os.Getenv("ZSCALER_CLIENT_ID") == "" &&
			os.Getenv("ZSCALER_CLIENT_SECRET") == "" &&
			os.Getenv("ZSCALER_PRIVATE_KEY") == "" &&
			os.Getenv("ZSCALER_VANITY_DOMAIN") == "" &&
			os.Getenv("ZSCALER_CLOUD") == "" &&
			os.Getenv("ZPA_MICROTENANT_ID") == "" {
			// [4.1] If use_legacy_client == "true", write the legacy block
			if strings.EqualFold(useLegacy, "true") {
				if zpaClientID != "" && zpaClientSecret != "" && zpaCustomerID != "" && zpaCloud != "" {
					providerConfig += fmt.Sprintf(`
  zpa_client_id       = "%s"
  zpa_client_secret   = "%s"
  zpa_customer_id     = "%s"
  zpa_cloud           = "%s"
  use_legacy_client   = true
`, zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud)
				}
			} else {
				// [4.2] OneAPI scenario for ZPA
				// For example, we do "client_id, client_secret/private_key, vanity_domain, customer_id, microtenant_id, zscaler_cloud"
				// We'll only write lines that are non-empty:
				if clientID != "" {
					providerConfig += fmt.Sprintf("  client_id      = \"%s\"\n", clientID)
				}
				if clientSecret != "" {
					providerConfig += fmt.Sprintf("  client_secret  = \"%s\"\n", clientSecret)
				} else if privateKey != "" {
					providerConfig += fmt.Sprintf("  private_key    = \"%s\"\n", privateKey)
				}
				if vanityDomain != "" {
					providerConfig += fmt.Sprintf("  vanity_domain  = \"%s\"\n", vanityDomain)
				}
				if zscalerCloud != "" {
					providerConfig += fmt.Sprintf("  cloud          = \"%s\"\n", zscalerCloud)
				}
				if customerID != "" {
					providerConfig += fmt.Sprintf("  customer_id    = \"%s\"\n", customerID)
				}
				if microtenantID != "" {
					providerConfig += fmt.Sprintf("  microtenant_id = \"%s\"\n", microtenantID)
				}
				// If user explicitly sets "use_legacy_client=false", we can write it:
				if strings.EqualFold(useLegacy, "false") {
					providerConfig += `  use_legacy_client = false
`
				}
			}
		}

	case "zia":
		ziaUsername := viper.GetString("zia_username")
		ziaPassword := viper.GetString("zia_password")
		ziaApiKey := viper.GetString("zia_api_key")
		ziaCloud := viper.GetString("zia_cloud")
		useLegacy := viper.GetString("use_legacy_client")

		clientID := viper.GetString("client_id")
		clientSecret := viper.GetString("client_secret")
		privateKey := viper.GetString("private_key")
		vanityDomain := viper.GetString("vanity_domain")
		zscalerCloud := viper.GetString("zscaler_cloud")

		if os.Getenv("ZIA_USERNAME") == "" &&
			os.Getenv("ZIA_PASSWORD") == "" &&
			os.Getenv("ZIA_API_KEY") == "" &&
			os.Getenv("ZIA_CLOUD") == "" &&
			os.Getenv("ZSCALER_CLIENT_ID") == "" &&
			os.Getenv("ZSCALER_CLIENT_SECRET") == "" &&
			os.Getenv("ZSCALER_PRIVATE_KEY") == "" &&
			os.Getenv("ZSCALER_VANITY_DOMAIN") == "" &&
			os.Getenv("ZSCALER_CLOUD") == "" &&
			os.Getenv("ZSCALER_USE_LEGACY_CLIENT") == "" {
			if strings.EqualFold(useLegacy, "true") {
				// Legacy V2 for ZIA
				if ziaUsername != "" && ziaPassword != "" && ziaApiKey != "" && ziaCloud != "" {
					providerConfig += fmt.Sprintf(`
  username            = "%s"
  password            = "%s"
  api_key             = "%s"
  zia_cloud           = "%s"
  use_legacy_client   = true
`, ziaUsername, ziaPassword, ziaApiKey, ziaCloud)
				}
			} else {
				// OneAPI for ZIA:
				// Typically: client_id + client_secret (or private_key) + vanity_domain, optional zscaler_cloud
				if clientID != "" {
					providerConfig += fmt.Sprintf("  client_id      = \"%s\"\n", clientID)
				}
				if clientSecret != "" {
					providerConfig += fmt.Sprintf("  client_secret  = \"%s\"\n", clientSecret)
				} else if privateKey != "" {
					providerConfig += fmt.Sprintf("  private_key    = \"%s\"\n", privateKey)
				}
				if vanityDomain != "" {
					providerConfig += fmt.Sprintf("  vanity_domain  = \"%s\"\n", vanityDomain)
				}
				if zscalerCloud != "" {
					providerConfig += fmt.Sprintf("  zscaler_cloud          = \"%s\"\n", zscalerCloud)
				}
				if strings.EqualFold(useLegacy, "false") {
					providerConfig += `  use_legacy_client = false
`
				}
			}
		}
	}

	// Close out the provider block
	providerConfig += "\n}\n"

	// [5] Write the providerConfig to disk
	filename := fmt.Sprintf("%s/%s-provider.tf", workingDir, cloudType)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal("failed creating "+filename, err)
	}
	n, err := f.WriteString(providerConfig)
	if err != nil {
		log.Fatalf("failed writing to %s: %s", filename, err)
	} else if n < len(providerConfig) {
		log.Fatalf("incomplete write to %s: wrote %d of %d bytes", filename, n, len(providerConfig))
	}
	if err := f.Close(); err != nil {
		log.Fatalf("failed to close file %s: %s", filename, err)
	}

	// [6] Now init the Terraform config
	err = tf.Init(context.Background(), tfexec.Upgrade(true))
	if err != nil {
		log.Fatal("tf init failed ", err)
	}

	ps, err := tf.ProvidersSchema(context.Background())
	if err != nil {
		log.Fatal("failed to read provider schema", err)
	}
	log.Debug("ps.Schemas:", ps.Schemas)

	// [7] Identify the correct provider version
	providerNames := []string{
		fmt.Sprintf("zscaler.com/%s/%s", cloudType, cloudType),
		fmt.Sprintf("zscaler/%s", cloudType),
		fmt.Sprintf("registry.terraform.io/zscaler/%s", cloudType),
	}
	var s *tfjson.ProviderSchema
	for _, p := range providerNames {
		if ps, ok := ps.Schemas[p]; ok {
			s = ps
			break
		}
	}
	if s == nil {
		log.Fatal("failed to detect " + cloudType + " provider installation")
	}
	r = s.ResourceSchemas[resourceType]
	if displayReleaseVersion {
		tfVrsion, providerVersions, err := tf.Version(context.Background(), false)
		if err == nil {
			if tfVrsion != nil {
				log.Infof("Terraform Version: %s", tfVrsion.String())
			}
			for provider, version := range providerVersions {
				log.Infof("Provider %s:%s", provider, version.String())
			}
		}
	}
	return
}

func generate(ctx context.Context, cmd *cobra.Command, writer io.Writer, resourceType string) {
	if resourceType == "" {
		log.Fatal("you must define a resource type to generate")
	}
	tf, r, workingDir := initTf(resourceType) // Ensure workingDir is obtained
	log.Debugf("beginning to read and build %s resources", resourceType)

	// Note: Reference replacement is now handled in post-processing after all imports

	// Initialise `resourceCount` outside of the switch for supported resources
	// to allow it to be referenced further down in the loop that outputs the
	// newly generated resources.
	resourceCount := 0

	// Lazy approach to restrict support to known resources due to Go's type
	// restrictions and the need to explicitly map out the structs.
	var jsonStructData []interface{}

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
			log.Fatal(err)
		}

		jsonPayload := []appconnectorgroup.AppConnectorGroup{}
		for _, i := range list {
			if i.Name == "Zscaler Deception" {
				continue
			}
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
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
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
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
	case "zpa_pra_approval_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := praapproval.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
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
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_pra_credential_pool":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService

		// Get all credential pools first (for the list)
		allPools, _, err := pracredentialpool.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}

		// Get full details for each pool (including credentials attribute)
		for _, pool := range allPools {
			poolDetails, _, err := pracredentialpool.Get(ctx, service, pool.ID)
			if err != nil {
				log.Printf("error retrieving credential pool %s: %v", pool.ID, err)
				continue
			}
			data, _ := json.Marshal(poolDetails)
			var poolMap map[string]interface{}
			_ = json.Unmarshal(data, &poolMap)
			jsonStructData = append(jsonStructData, poolMap)
		}

		resourceCount = len(jsonStructData)
	case "zpa_pra_portal_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := praportal.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
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
			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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

			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := inspection_custom_controls.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_microtenant_controller":
		if api.ZPAService == nil {
			log.Fatal("ZPA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZPAService
		jsonPayload, _, err := microtenants.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		// Filter out any resources with name == "Default"
		var filteredPayload []microtenants.MicroTenant
		for _, item := range jsonPayload {
			if item.Name != "Default" {
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(servicesFiltered)
		m, _ := json.Marshal(servicesFiltered)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		for _, group := range groups {
			if helpers.IsInList(group.Name, []string{"Microsoft Office365"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_location_management":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		// Get all parent locations
		jsonPayload, err := locationmanagement.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		jsonPayload, err := urlcategories.GetAllCustomURLCategories(ctx, service)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
	case "zia_forwarding_control_proxies":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		rules, err := proxies.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
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
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
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
	case "zia_ftp_control_policy":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		ftpControl, err := ftp_control_policy.GetFTPControlPolicy(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*ftp_control_policy.FTPControlPolicy{ftpControl}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "ftp_control"
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
	case "zia_mobile_malware_protection_policy":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		mobileSettings, err := mobile_threat_settings.GetMobileThreatSettings(ctx, service)
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*mobile_threat_settings.MobileAdvanceThreatSettings{mobileSettings}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
		if len(jsonStructData) > 0 {
			dataMap := jsonStructData[0].(map[string]interface{})
			dataMap["id"] = "mobile_settings"
		}
	case "zia_virtual_service_edge_cluster":
		if api.ZIAService == nil {
			log.Fatal("ZIA service is not initialized")
		}
		// EXACTLY like the TF pattern:
		service := api.ZIAService
		jsonPayload, err := vzen_clusters.GetAll(ctx, service)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
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
			log.Fatal(err)
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
			log.Fatal(err)
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
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "%q is not yet supported for automatic generation", resourceType)
		return
	}

	if resourceCount == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "no resources found to generate.")
		return
	}

	output := ""

	for i := 0; i < resourceCount; i++ {
		structData := jsonStructData[i].(map[string]interface{})
		helpers.ConvertAttributes(structData) // Ensure the attributes are converted

		resourceID := ""
		if os.Getenv("USE_STATIC_RESOURCE_IDS") == "true" {
			resourceID = "terraform_managed_resource"
		} else {
			resourceID = buildResourceName(resourceType, structData)
		}

		// Note: Reference replacement is now handled in post-processing after all imports

		resourceName := ""
		if structData["name"] != nil {
			resourceName = structData["name"].(string)
		} else if structData["description"] != nil {
			desc := structData["description"].(string)
			// Normalize description for resource name to avoid Terraform parsing issues
			resourceName = helpers.FormatHeredoc(desc)
			// Remove newlines and limit length for resource name
			resourceName = strings.ReplaceAll(resourceName, "\n", " ")
			if len(resourceName) > 50 {
				resourceName = resourceName[:50] + "..."
			}
		} else {
			resourceName = fmt.Sprintf("ID %v", structData["id"])
		}

		output += fmt.Sprintf("# __generated__ by Zscaler Terraformer from %s\n", resourceName)
		output += fmt.Sprintf(`resource "%s" "%s" {`+"\n", resourceType, resourceID)

		sortedBlockAttributes := make([]string, 0, len(r.Block.Attributes))
		for k := range r.Block.Attributes {
			sortedBlockAttributes = append(sortedBlockAttributes, k)
		}

		sort.Strings(sortedBlockAttributes)

		for _, attrName := range sortedBlockAttributes {

			apiAttrName := nesting.MapTfFieldNameToAPI(resourceType, attrName)
			if attrName == "id" || attrName == "tcp_port_ranges" || attrName == "udp_port_ranges" || attrName == "rule_order" || (resourceType == "zia_url_categories" && attrName == "val") {
				continue
			}

			// Ensure proper Heredoc formatting for multi-line string attributes
			if attrName == "quarantine_custom_notification_text" || attrName == "url_cat_review_text" || attrName == "caution_custom_text" || attrName == "custom_text" || attrName == "idp_proxy_notification_text" || attrName == "security_review_text" || attrName == "web_dlp_review_text" {
				value := structData[apiAttrName]
				if value != nil {
					valueStr := strings.TrimSpace(value.(string))
					// If the value is empty after trimming, skip the attribute entirely to avoid validation errors
					if valueStr == "" {
						continue
					} else {
						formattedValue := helpers.FormatHeredoc(valueStr)
						output += fmt.Sprintf("  %s = <<-EOT\n%s\nEOT\n\n", attrName, formattedValue)
					}
					continue
				}
			}

			// Ensure proper Heredoc formatting for multi-line string attributes
			if attrName == "plain_text_message" || attrName == "html_message" || attrName == "subject" {
				value := structData[apiAttrName]
				if value != nil {
					valueStr := strings.TrimSpace(value.(string))
					// If the value is empty after trimming, skip the attribute entirely to avoid validation errors
					if valueStr == "" {
						continue
					} else {
						formattedValue := helpers.FormatHeredoc(valueStr) // Use the updated helper function
						output += fmt.Sprintf("  %s = <<-EOT\n%s\nEOT\n\n", attrName, formattedValue)
					}
					continue
				}
			}
			ty := r.Block.Attributes[attrName].AttributeType
			// If this attribute is "url_categories" and empty/missing, set to ANY
			// EXCEPT for zia_sandbox_rules where we should not set it unless explicitly present
			if attrName == "url_categories" && resourceType != "zia_sandbox_rules" {
				raw := structData[apiAttrName]
				if raw == nil {
					// Not present? Force to ANY
					structData[apiAttrName] = []string{"ANY"}
				} else {
					// Convert raw to check emptiness
					switch val := raw.(type) {
					case []string:
						if len(val) == 0 {
							structData[apiAttrName] = []string{"ANY"}
						}
					case []interface{}:
						if len(val) == 0 {
							structData[apiAttrName] = []string{"ANY"}
						}
					}
				}
			}
			// (A) ADD THIS BLOCK:
			// If this attribute is a boolean in the schema, but structData doesn't have it at all,
			// default it to false so WriteAttrLine will print "= false".
			if ty.Equals(cty.Bool) {
				if _, present := structData[apiAttrName]; !present {
					structData[apiAttrName] = false
				}
			}
			// Handle specific attributes for zpa_cloud_browser_isolation_external_profile
			if attrName == "banner_id" || attrName == "certificate_ids" || attrName == "region_ids" {
				value := structData[attrName]
				if value == nil {
					log.Printf("[DEBUG] %s attribute is nil", attrName)
					continue
				}

				switch attrName {
				case "certificate_ids", "region_ids":
					ids, ok := value.([]string)
					if !ok {
						log.Printf("[ERROR] %s attribute is not of type []string", attrName)
						continue
					}
					output += fmt.Sprintf("%s = [\"%s\"]\n", attrName, strings.Join(ids, "\", \""))
				case "banner_id":
					output += nesting.WriteAttrLine(attrName, value, false)
				}
				continue
			}

			// Special handling for description field in ZIA resources to prevent Terraform parsing issues
			if attrName == "description" && strings.HasPrefix(resourceType, "zia_") {
				value := structData[apiAttrName]
				if value != nil {
					valueStr := value.(string)
					// If the value is empty, skip the attribute entirely to avoid validation errors
					if strings.TrimSpace(valueStr) == "" {
						continue
					} else {
						// Use the same normalization as the provider
						normalized := helpers.FormatHeredoc(valueStr)

						// Check if the description contains newlines
						if strings.Contains(valueStr, "\n") {
							// Use heredoc formatting for multi-line descriptions
							output += fmt.Sprintf("  %s = <<EOT\n%sEOT\n", attrName, normalized)
						} else {
							// Use regular quoted string for single-line descriptions
							// Remove the trailing newline for quoted string
							normalized = strings.TrimSuffix(normalized, "\n")
							output += fmt.Sprintf("  %s = %q\n", attrName, normalized)
						}
					}
					continue
				}
			}

			// No need to output computed attributes that are also not optional.
			bypassAttributes := []string{"static_ip_id", "tunnel_id"}
			if r.Block.Attributes[attrName].Computed && !r.Block.Attributes[attrName].Optional && helpers.IsInList(attrName, bypassAttributes) {
				continue
			}

			// Special handling for zia_dlp_dictionaries confidence_level_for_predefined_dict attribute
			if resourceType == "zia_dlp_dictionaries" && attrName == "confidence_level_for_predefined_dict" {
				// Check if this is a predefined clone dictionary
				predefinedClone, ok := structData["predefinedClone"].(bool)
				if !ok || !predefinedClone {
					// Skip this attribute for non-predefined clone dictionaries
					continue
				}
			}

			// ty := r.Block.Attributes[attrName].AttributeType
			switch {
			case ty.IsPrimitiveType():
				switch ty {
				case cty.String, cty.Bool:
					value := structData[apiAttrName]
					if resourceType == "zpa_service_edge_group" {
						if attrName == "is_public" {
							if value == nil {
								value = false
							} else {
								isPublicStr, ok := value.(string)
								if ok {
									isPublic, _ := strconv.ParseBool(isPublicStr)
									value = isPublic
								} else {
									value = false
								}
							}
						}
					}

					output += nesting.WriteAttrLine(attrName, value, false)

				case cty.Number:
					value := structData[apiAttrName]

					if attrName == "idle_time_in_minutes" || attrName == "surrogate_refresh_time_in_minutes" {
						floatValue, ok := value.(float64)
						if ok {
							output += fmt.Sprintf("%s = %d\n", attrName, int64(floatValue))
							continue
						}
					}

					if attrName == "parent_id" {
						intValue, ok := value.(float64)
						if ok {
							output += fmt.Sprintf("%s = %d\n", attrName, int64(intValue))
							continue
						}
					} else if resourceType == "zpa_pra_approval_controller" && (attrName == "start_time" || attrName == "end_time") {
						if strValue, ok := value.(string); ok {
							epoch, err := strconv.ParseInt(strValue, 10, 64)
							if err == nil {
								value = conversion.EpochToRFC1123(epoch)
							}
						}
					} else if resourceType == "zia_url_filtering_rules" && (attrName == "validity_start_time" || attrName == "validity_end_time") {
						if strValue, ok := value.(string); ok {
							value = strValue
						}
					}
					output += nesting.WriteAttrLine(attrName, value, false)

				default:
					log.Debugf("unexpected primitive type %q", ty.FriendlyName())
				}

			case ty.IsCollectionType():
				switch {
				case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
					output += nesting.WriteAttrLine(attrName, structData[apiAttrName], false)
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

		if resourceType == "zpa_inspection_custom_controls" {
			if controlRuleJson, ok := structData["controlRuleJson"]; ok {
				var controlRules []map[string]interface{}
				err := json.Unmarshal([]byte(controlRuleJson.(string)), &controlRules)
				if err != nil {
					log.Fatalf("failed to unmarshal controlRuleJson: %v", err)
				}
				for _, rule := range controlRules {
					output += "  rules {\n"
					for key, value := range rule {
						if key == "conditions" {
							for _, condition := range value.([]interface{}) {
								output += "    conditions {\n"
								conditionMap := condition.(map[string]interface{})
								for condKey, condValue := range conditionMap {
									output += nesting.WriteAttrLine(condKey, condValue, false)
								}
								output += "    }\n" // Close each individual conditions block
							}
						} else {
							output += nesting.WriteAttrLine(key, value, false)
						}
					}
					output += "  }\n"
				}
			}
		}

		output += nesting.NestBlocks(resourceType, r.Block, jsonStructData[i].(map[string]interface{}), uuid.New().String(), map[string][]string{})
		output += "}\n\n"

		helpers.GenerateOutputs(resourceType, resourceID, workingDir)
	}

	formattedOutput, err := tf.FormatString(context.Background(), output)
	if err != nil {
		log.Printf("failed to format output: %s", err)
	}

	// Write output to both stdout and file
	_, _ = fmt.Fprint(writer, formattedOutput)

	// Also write to file for post-processing
	filename := fmt.Sprintf("%s/%s.tf", workingDir, resourceType)
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("[WARNING] Failed to create file %s: %v", filename, err)
	} else {
		_, err = file.WriteString(formattedOutput)
		if err != nil {
			log.Printf("[WARNING] Failed to write to file %s: %v", filename, err)
		}
		file.Close()
	}

	// Note: Post-processing is now handled centrally after all imports are complete
	// This improves performance by avoiding multiple file scans during generation
}
