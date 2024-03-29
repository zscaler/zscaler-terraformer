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

	"fmt"
)

var resourceType_ string
var resources string
var excludedResources string

var allGeneratableResources = []string{
	"zpa_app_connector_group",
	"zpa_application_server",
	"zpa_application_segment",
	"zpa_application_segment_pra",
	"zpa_application_segment_inspection",
	"zpa_application_segment_browser_access",
	"zpa_ba_certificate",
	"zpa_cloud_browser_isolation_banner",
	"zpa_cloud_browser_isolation_certificate",
	"zpa_cloud_browser_isolation_external_profile",
	"zpa_segment_group",
	"zpa_server_group",
	"zpa_policy_access_rule",
	"zpa_policy_inspection_rule",
	"zpa_policy_timeout_rule",
	"zpa_policy_forwarding_rule",
	"zpa_provisioning_key",
	"zpa_service_edge_group",
	"zpa_lss_config_controller",
	"zpa_inspection_custom_controls",
	"zpa_inspection_profile",
	"zpa_microtenant_controller",
	"zia_admin_users",
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
	"zia_user_management",
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
				if isInList(resourceTyp, excludedResourcesTypes) {
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
	if isInList(resourceType, resourcesRequiringShortID) {
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
			id := strings.ReplaceAll(strings.ToLower(strip(name)), " ", "_")
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
		// Terraform is not found, install it
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
		log.Debugf("Terraform installed at:%s", execPath)
	} else {
		log.Debugf("Terraform already installed at:%s", execPath)
	}

	cloudType := ""
	if strings.HasPrefix(resourceType, "zpa_") {
		cloudType = "zpa"
	} else if strings.HasPrefix(resourceType, "zia_") {
		cloudType = "zia"
	}
	workingDir = viper.GetString(cloudType + "-terraform-install-path")
	// Setup and configure Terraform to operate in the temporary directory where
	// the provider is already configured.
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

	err = tf.Init(context.Background(), tfexec.Upgrade(true))
	if err != nil {
		log.Fatal("tf init failed ", err)
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
		// try to init it
		filename := workingDir + "/" + cloudType + "-provider.tf"
		f, err := os.Create(filename)
		if err != nil {
			log.Fatal("failed creating "+filename, err)
		}
		_, _ = f.WriteString(fmt.Sprintf("terraform {\n\trequired_providers {\n\t  %s = {\n\t	source = \"zscaler/%s\"\n\t  }\n\t}\n}\n", cloudType, cloudType))
		f.Close()

		err = tf.Init(context.Background(), tfexec.Upgrade(true))
		if err != nil {
			log.Fatal("tf init failed ", err)
		}
		ps, err = tf.ProvidersSchema(context.Background())
		if err != nil {
			log.Fatal("failed to read provider schema", err)
		}
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
	}
	r = s.ResourceSchemas[resourceType]
	if displayReleaseVersion {
		tfVrsion, providerVersions, err := tf.Version(context.Background(), false)
		if err == nil {
			if tfVrsion != nil {
				log.Infof("Terrafrom Version: %s", tfVrsion.String())
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
	tf, r, _ := initTf(resourceType)
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
		list, _, err := api.zpa.appconnectorgroup.GetAll()
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
		jsonPayload, _, err := api.zpa.appservercontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment":
		jsonPayload, _, err := api.zpa.applicationsegment.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_pra":
		jsonPayload, _, err := api.zpa.applicationsegmentpra.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_inspection":
		jsonPayload, _, err := api.zpa.applicationsegmentinspection.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_ba_certificate":
		jsonPayload, _, err := api.zpa.bacertificate.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_banner":
		jsonPayload, _, err := api.zpa.cbibannercontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_certificate":
		jsonPayload, _, err := api.zpa.cbicertificatecontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_cloud_browser_isolation_external_profile":
		jsonPayload, _, err := api.zpa.cbiprofilecontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
			i.Applications = nil // Suppress the applications block
			jsonPayload = append(jsonPayload, i)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_application_segment_browser_access":
		jsonPayload, _, err := api.zpa.browseraccess.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_provisioning_key":
		jsonPayload, err := api.zpa.provisioningkey.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_service_edge_group":
		jsonPayload, _, err := api.zpa.serviceedgegroup.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_lss_config_controller":
		jsonPayload, _, err := api.zpa.lssconfigcontroller.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_custom_controls":
		jsonPayload, _, err := api.zpa.inspection_custom_controls.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_inspection_profile":
		jsonPayload, _, err := api.zpa.inspection_profile.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zpa_microtenant_controller":
		jsonPayload, _, err := api.zpa.microtenants.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)

	case "zia_admin_users":
		jsonPayload, err := api.zia.admins.GetAllAdminUsers()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_notification_templates":
		jsonPayload, err := api.zia.dlp_notification_templates.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_dlp_web_rules":
		jsonPayload, err := api.zia.dlp_web_rules.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
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
		resourceCount = len(servicesFiltered)
		m, _ := json.Marshal(servicesFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_service_groups":
		jsonPayload, err := api.zia.networkservicegroups.GetAllNetworkServiceGroups()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_firewall_filtering_network_application_groups":
		groups, err := api.zia.networkapplicationgroups.GetAllNetworkApplicationGroups()
		if err != nil {
			log.Fatal(err)
		}
		groupsFiltered := []networkapplicationgroups.NetworkApplicationGroups{}
		for _, group := range groups {
			if isInList(group.Name, []string{"Microsoft Office365"}) {
				continue
			}
			groupsFiltered = append(groupsFiltered, group)
		}
		resourceCount = len(groupsFiltered)
		m, _ := json.Marshal(groupsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_gre_tunnel":
		jsonPayload, err := api.zia.gretunnels.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_static_ip":
		jsonPayload, err := api.zia.staticips.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_traffic_forwarding_vpn_credentials":
		jsonPayload, err := api.zia.vpncredentials.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_location_management":
		// Get all parent locations
		jsonPayload, err := api.zia.locationmanagement.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(items)
		m, _ := json.Marshal(items)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_url_filtering_rules":
		jsonPayload, err := api.zia.urlfilteringpolicies.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_user_management":
		jsonPayload, err := api.zia.users.GetAllUsers()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_rule_labels":
		jsonPayload, err := api.zia.rule_labels.GetAll()
		if err != nil {
			log.Fatal(err)
		}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_auth_settings_urls":
		exemptedUrls, err := api.zia.user_authentication_settings.Get()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*user_authentication_settings.ExemptedUrls{exemptedUrls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_sandbox_behavioral_analysis":
		hashes, err := api.zia.sandbox_settings.Get()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*sandbox_settings.BaAdvancedSettings{hashes}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
		_ = json.Unmarshal(m, &jsonStructData)
	case "zia_security_settings":
		urls, err := api.zia.security_policy_settings.GetListUrls()
		if err != nil {
			log.Fatal(err)
		}
		jsonPayload := []*security_policy_settings.ListUrls{urls}
		resourceCount = len(jsonPayload)
		m, _ := json.Marshal(jsonPayload)
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
		resourceCount = len(rulesFiltered)
		m, _ := json.Marshal(rulesFiltered)
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
		resourceCount = len(gwsFiltered)
		m, _ := json.Marshal(gwsFiltered)
		_ = json.Unmarshal(m, &jsonStructData)
	default:
		fmt.Fprintf(cmd.OutOrStdout(), "%q is not yet supported for automatic generation", resourceType)
		return
	}
	// If we don't have any resources to generate, just bail out early.
	if resourceCount == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "no resources found to generate.")
		return
	}

	output := ""

	for i := 0; i < resourceCount; i++ {
		structData := jsonStructData[i].(map[string]interface{})

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
		// Block attributes are for any attributes where assignment is involved.
		for _, attrName := range sortedBlockAttributes {
			apiAttrName := mapTfFieldNameToApi(resourceType, attrName)
			// Don't bother outputting the ID for the resource as that is only for
			// internal use (such as importing state).
			if attrName == "id" {
				continue
			}

			// No need to output computed attributes that are also not
			// optional.
			// Here is the corrected part for handling "static_ip_id" and "tunnel_id"
			bypassAttributes := []string{"static_ip_id", "tunnel_id"}
			if r.Block.Attributes[attrName].Computed && !r.Block.Attributes[attrName].Optional && isInList(attrName, bypassAttributes) {
				continue
			}

			ty := r.Block.Attributes[attrName].AttributeType
			switch {
			case ty.IsPrimitiveType():
				switch ty {
				case cty.String, cty.Bool:
					value := structData[apiAttrName]
					// Handle any string modifications here, if necessary.

					output += writeAttrLine(attrName, value, false)

				case cty.Number:
					value := structData[apiAttrName]

					// Special handling for idle_time_in_minutes and surrogate_refresh_time_in_minutes to prevent scientific notation
					if attrName == "idle_time_in_minutes" || attrName == "surrogate_refresh_time_in_minutes" {
						floatValue, ok := value.(float64)
						if ok {
							// Explicitly convert and format as integer
							output += fmt.Sprintf("%s = %d\n", attrName, int64(floatValue))
							continue // Skip the rest of the logic for these specific fields
						}
					}

					// Handle parent_id specially to prevent scientific notation.
					if attrName == "parent_id" {
						intValue, ok := value.(float64)
						if ok {
							output += fmt.Sprintf("%s = %d\n", attrName, int64(intValue))
							continue
						}
					} else if resourceType == "zia_dlp_notification_templates" && isInList(attrName, []string{"subject", "plain_text_message", "html_message"}) {
						value = strings.ReplaceAll(value.(string), "${", "$${")
					} else if resourceType == "zpa_service_edge_group" && attrName == "is_public" {
						if value == nil {
							value = false
						} else {
							isPublic, _ := strconv.ParseBool(value.(string))
							value = isPublic
						}
					}

					output += writeAttrLine(attrName, value, false)

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

		output += nestBlocks(resourceType, r.Block, jsonStructData[i].(map[string]interface{}), uuid.New().String(), map[string][]string{})
		output += "}\n\n"
	}

	output, err := tf.FormatString(context.Background(), output)
	if err != nil {
		log.Printf("failed to format output: %s", err)
	}

	fmt.Fprint(writer, output)
}
