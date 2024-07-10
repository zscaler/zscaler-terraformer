// Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

//                             MIT License
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

	"github.com/google/uuid"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zclconf/go-cty/cty"
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
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudbrowserisolation/cbibannercontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudbrowserisolation/cbiprofilecontroller"
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
	"github.com/zscaler/zscaler-terraformer/teraformutils/conversion"
	"github.com/zscaler/zscaler-terraformer/teraformutils/helpers"
	"github.com/zscaler/zscaler-terraformer/teraformutils/nesting"

	"fmt"
)

var resourceType_ string
var resources string
var excludedResources string

var allGeneratableResources = []string{
	"zpa_app_connector_group",
	"zpa_application_server",
	"zpa_application_segment",
	"zpa_application_segment_browser_access",
	"zpa_application_segment_inspection",
	"zpa_application_segment_pra",
	"zpa_ba_certificate",
	"zpa_cloud_browser_isolation_banner",
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
	"zpa_pra_portal_controller",
	"zpa_provisioning_key",
	"zpa_service_edge_group",
	"zpa_lss_config_controller",
	"zpa_inspection_custom_controls",
	"zpa_microtenant_controller",
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
	"zia_rule_labels",
	"zia_auth_settings_urls",
	"zia_sandbox_behavioral_analysis",
	"zia_security_settings",
	"zia_forwarding_control_zpa_gateway",
	"zia_forwarding_control_rule",
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
			if resources == "*" {
				resourceTypes = allGeneratableResources
			} else if resources == "zia" || resources == "zpa" {
				for _, resource := range resourceImportStringFormats {
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
				if helpers.IsInList(resourceTyp, excludedResourcesTypes) {
					continue
				}
				generate(cmd, cmd.OutOrStdout(), resourceTyp)
			}
			return
		}
		generate(cmd, cmd.OutOrStdout(), resourceType_)
	}
}

func buildResourceName(resourceType string, structData map[string]interface{}) string {
	// Define a variable for the short UUID.
	var shortUUID string

	// For resources that typically lack a unique identifier, generate a short UUID.
	resourcesRequiringShortID := []string{"zia_sandbox_behavioral_analysis", "zia_security_settings", "zia_auth_settings_urls"}
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
		resID = fmt.Sprintf("resource_%s_%s", resourceType, resourceID)
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
	// Check if Terraform is already installed
	execPath, err := exec.LookPath("terraform")
	if err != nil {
		log.Debugf("Terraform not found, installing...")
		installDir := "/usr/local/bin"
		installer := &releases.LatestVersion{
			Product:    product.Terraform,
			InstallDir: installDir,
		}
		execPath, err = installer.Install(context.Background())
		if err != nil {
			log.Fatalf("error installing Terraform: %s", err)
		}
		log.Debugf("Terraform installed at: %s", execPath)
	} else {
		log.Debugf("Terraform already installed at: %s", execPath)
	}

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
		err := os.Mkdir(workingDir, os.ModePerm)
		if err != nil {
			log.Fatal("failed creating dir:"+workingDir, err)
		}
	}
	tf, err = tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		log.Fatal("NewTerraform failed", err)
	}

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

	// Add credentials if they are provided inline (not from environment variables)
	if cloudType == "zpa" {
		zpa_client_id := viper.GetString("zpa_client_id")
		zpa_client_secret := viper.GetString("zpa_client_secret")
		zpa_customer_id := viper.GetString("zpa_customer_id")
		zpa_cloud := viper.GetString("zpa_cloud")

		if os.Getenv("ZPA_CLIENT_ID") == "" && os.Getenv("ZPA_CLIENT_SECRET") == "" && os.Getenv("ZPA_CUSTOMER_ID") == "" && os.Getenv("ZPA_CLOUD") == "" {
			if zpa_client_id != "" && zpa_client_secret != "" && zpa_customer_id != "" && zpa_cloud != "" {
				providerConfig += fmt.Sprintf(`
  zpa_client_id     = "%s"
  zpa_client_secret = "%s"
  zpa_customer_id   = "%s"
  zpa_cloud         = "%s"
`, zpa_client_id, zpa_client_secret, zpa_customer_id, zpa_cloud)
			}
		}
	} else if cloudType == "zia" {
		zia_username := viper.GetString("zia_username")
		zia_password := viper.GetString("zia_password")
		zia_api_key := viper.GetString("zia_api_key")
		zia_cloud := viper.GetString("zia_cloud")

		if os.Getenv("ZIA_USERNAME") == "" && os.Getenv("ZIA_PASSWORD") == "" && os.Getenv("ZIA_API_KEY") == "" && os.Getenv("ZIA_CLOUD") == "" {
			if zia_username != "" && zia_password != "" && zia_api_key != "" && zia_cloud != "" {
				providerConfig += fmt.Sprintf(`
  username  = "%s"
  password  = "%s"
  api_key   = "%s"
  zia_cloud = "%s"
`, zia_username, zia_password, zia_api_key, zia_cloud)
			}
		}
	}

	providerConfig += `
}
`

	filename := workingDir + "/" + cloudType + "-provider.tf"
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal("failed creating "+filename, err)
	}
	_, _ = f.WriteString(providerConfig)
	f.Close()

	// Initialize Terraform with the provider configuration
	err = tf.Init(context.Background(), tfexec.Upgrade(true))
	if err != nil {
		log.Fatal("tf init failed ", err)
	}

	ps, err := tf.ProvidersSchema(context.Background())
	if err != nil {
		log.Fatal("failed to read provider schema", err)
	}
	log.Debug("ps.Schemas:", ps.Schemas)

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

func generate(cmd *cobra.Command, writer io.Writer, resourceType string) {
	if resourceType == "" {
		log.Fatal("you must define a resource type to generate")
	}
	tf, r, workingDir := initTf(resourceType) // Ensure workingDir is obtained
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.AppConnectorGroup
		list, _, err := appconnectorgroup.GetAll(zpaClient)
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
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.AppServerController
		jsonPayload, _, err := appservercontroller.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_browser_access":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.BrowserAccess
		jsonPayload, _, err := browseraccess.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_banner":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.CbiBanner

		// Retrieve all resources using GetAll
		allBanners, _, err := cbibannercontroller.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}

		// Collect the payload data
		for _, banner := range allBanners {
			// Use the ID or name to get the full details of the banner
			bannerDetails, _, err := cbibannercontroller.GetByNameOrID(zpaClient, banner.ID)
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
	case "zpa_cloud_browser_isolation_external_profile":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.CbiExternalProfile

		allProfiles, _, err := cbiprofilecontroller.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}

		for _, profile := range allProfiles {
			profileDetails, _, err := cbiprofilecontroller.GetByNameOrID(zpaClient, profile.ID)
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
		m, _ := json.Marshal(jsonPayload)
		resourceCount = len(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
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
			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.InspectionCustomControls
		jsonPayload, _, err := inspection_custom_controls.GetAll(zpaClient)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_microtenant_controller":
		if api.ZPA == nil {
			log.Fatal("ZPA client is not initialized")
		}
		zpaClient := api.ZPA.MicroTenants
		jsonPayload, _, err := microtenants.GetAll(zpaClient)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(servicesFiltered)
		m, _ := json.Marshal(servicesFiltered)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		if api.ZIA == nil {
			log.Fatal("ZIA client is not initialized")
		}
		ziaClient := api.ZIA.GRETunnels
		jsonPayload, err := gretunnels.GetAll(ziaClient)
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(items)
		m, _ := json.Marshal(items)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
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
		resourceCount = len(gwsFiltered)
		m, _ := json.Marshal(gwsFiltered)
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
		resourceName := ""
		if structData["name"] != nil {
			resourceName = structData["name"].(string)
		} else if structData["description"] != nil {
			resourceName = structData["description"].(string)
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
			if attrName == "id" || attrName == "tcp_port_ranges" || attrName == "udp_port_ranges" || attrName == "rule_order" {
				continue
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
			// No need to output computed attributes that are also not optional.
			bypassAttributes := []string{"static_ip_id", "tunnel_id"}
			if r.Block.Attributes[attrName].Computed && !r.Block.Attributes[attrName].Optional && helpers.IsInList(attrName, bypassAttributes) {
				continue
			}

			ty := r.Block.Attributes[attrName].AttributeType
			switch {
			case ty.IsPrimitiveType():
				switch ty {
				case cty.String, cty.Bool:
					value := structData[apiAttrName]
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
					} else if resourceType == "zia_dlp_notification_templates" && helpers.IsInList(attrName, []string{"subject", "plain_text_message", "html_message"}) {
						valueStr := strings.ReplaceAll(value.(string), "$", "$$")
						formattedValue := formatHeredoc(valueStr)
						switch attrName {
						case "html_message", "plain_text_message":
							output += fmt.Sprintf("  %s = <<-EOT\n%sEOT\n\n", attrName, formattedValue)
						case "subject":
							output += fmt.Sprintf("  %s = <<-EOT\n%sEOT\n", attrName, formattedValue)
						}
					} else if resourceType == "zpa_service_edge_group" && attrName == "is_public" {
						if value == nil {
							value = false
						} else {
							isPublic, _ := strconv.ParseBool(value.(string))
							value = isPublic
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
							output += "    conditions {\n"
							for _, condition := range value.([]interface{}) {
								conditionMap := condition.(map[string]interface{})
								for condKey, condValue := range conditionMap {
									output += nesting.WriteAttrLine(condKey, condValue, false)
								}
							}
							output += "    }\n"
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

	output, err := tf.FormatString(context.Background(), output)
	if err != nil {
		log.Printf("failed to format output: %s", err)
	}

	fmt.Fprint(writer, output)
}

func formatHeredoc(value string) string {
	lines := strings.Split(value, "\n")
	formatted := ""
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			formatted += fmt.Sprintf("%s\n", trimmedLine)
		} else if i != len(lines)-1 {
			formatted += "\n"
		}
	}
	return formatted
}
