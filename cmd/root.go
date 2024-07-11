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
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zscaler/zscaler-terraformer/providers/zia"
	"github.com/zscaler/zscaler-terraformer/providers/zpa"
)

var log = logrus.New()
var terraformInstallPath string
var zpa_cloud, zpa_client_id, zpa_client_secret, zpa_customer_id string
var zia_cloud, zia_username, zia_password, zia_api_key string
var verbose, displayReleaseVersion bool
var supportedResources string
var api *Client
var terraformImportCmdPrefix = "terraform import"
var zpaProviderNamespace string

type Client struct {
	ZPA *zpa.Client
	ZIA *zia.Client
}

var allSupportedResources = []string{
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

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "zscaler-terraformer",
	Short: "Bootstrapping Terraform from existing ZPA/ZIA account",
	Long: "\x1B[34;01m" +
		"  ______              _           \n" +
		" |___  /             | |          \n" +
		"    / / ___  ___ __ _| | ___ _ __ \n" +
		"   / / / __|/ __/ _` | |/ _ \\ '__|\n" +
		"  / /__\\__ \\ (_| (_| | |  __/ |   \n" +
		" /_____|___/\\___\\__,_|_|\\___|_|   \n" +
		"\x1B[0m\n" +
		"zscaler-terraformer is an application that allows ZPA/ZIA users\n" +
		"to be able to adopt Terraform by giving them a feasible way to get\n" +
		"all of their existing ZPA/ZIA configuration into Terraform.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(logrus.DebugLevel)
			log.Debug("Verbose mode enabled")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if supportedResources != "" {
			listSupportedResources(supportedResources)
			return
		}

		if len(args) > 0 {
			fmt.Printf("Error: unrecognized command \"%s\"\n\n", args[0])
			_ = cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	// Define flags and configuration settings.
	// ZPA API credentials
	rootCmd.PersistentFlags().StringVarP(&zpa_client_id, "zpa_client_id", "", "", "ZPA client ID")
	_ = viper.BindPFlag("zpa_client_id", rootCmd.PersistentFlags().Lookup("zpa_client_id"))
	_ = viper.BindEnv("zpa_client_id", "ZPA_CLIENT_ID")

	rootCmd.PersistentFlags().StringVarP(&zpa_client_secret, "zpa_client_secret", "", "", "ZPA client secret")
	_ = viper.BindPFlag("zpa_client_secret", rootCmd.PersistentFlags().Lookup("zpa_client_secret"))
	_ = viper.BindEnv("zpa_client_secret", "ZPA_CLIENT_SECRET")

	rootCmd.PersistentFlags().StringVarP(&zpa_customer_id, "zpa_customer_id", "", "", "ZPA Customer ID")
	_ = viper.BindPFlag("zpa_customer_id", rootCmd.PersistentFlags().Lookup("zpa_customer_id"))
	_ = viper.BindEnv("zpa_customer_id", "ZPA_CUSTOMER_ID")

	rootCmd.PersistentFlags().StringVarP(&zpa_cloud, "zpa_cloud", "", "", "ZPA Cloud (BETA, GOV, GOVUS, PRODUCTION, ZPATWO)")
	_ = viper.BindPFlag("zpa_cloud", rootCmd.PersistentFlags().Lookup("zpa_cloud"))
	_ = viper.BindEnv("zpa_cloud", "ZPA_CLOUD")

	// ZIA API credentials
	rootCmd.PersistentFlags().StringVarP(&zia_username, "zia_username", "", "", "ZIA username")
	_ = viper.BindPFlag("zia_username", rootCmd.PersistentFlags().Lookup("zia_username"))
	_ = viper.BindEnv("zia_username", "ZIA_USERNAME")

	rootCmd.PersistentFlags().StringVarP(&zia_password, "zia_password", "", "", "ZIA password")
	_ = viper.BindPFlag("zia_password", rootCmd.PersistentFlags().Lookup("zia_password"))
	_ = viper.BindEnv("zia_password", "ZIA_PASSWORD")

	rootCmd.PersistentFlags().StringVarP(&zia_api_key, "zia_api_key", "", "", "ZIA API Key")
	_ = viper.BindPFlag("zia_api_key", rootCmd.PersistentFlags().Lookup("zia_api_key"))
	_ = viper.BindEnv("zia_api_key", "ZIA_API_KEY")

	rootCmd.PersistentFlags().StringVarP(&zia_cloud, "zia_cloud", "", "", "ZIA Cloud (i.e zscalerthree)")
	_ = viper.BindPFlag("zia_cloud", rootCmd.PersistentFlags().Lookup("zia_cloud"))
	_ = viper.BindEnv("zia_cloud", "ZIA_CLOUD")

	// Debug logging mode
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Specify verbose output (same as setting log level to debug)")

	rootCmd.PersistentFlags().BoolVarP(&displayReleaseVersion, "version", "", false, "Display the release version")

	rootCmd.PersistentFlags().StringVar(&resourceType_, "resource-type", "", "Which resource you wish to generate")

	rootCmd.PersistentFlags().StringVar(&resources, "resources", "", "Which resources you wish to import")

	rootCmd.PersistentFlags().StringVar(&excludedResources, "exclude", "", "Which resources you wish to exclude")

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "terraform-install-path", ".", "Path to the default Terraform installation")
	_ = viper.BindPFlag("terraform-install-path", rootCmd.PersistentFlags().Lookup("terraform-install-path"))
	_ = viper.BindEnv("terraform-install-path", "ZSCALER_TERRAFORM_INSTALL_PATH")

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "zpa-terraform-install-path", ".", "Path to the ZPA Terraform installation")
	_ = viper.BindPFlag("zpa-terraform-install-path", rootCmd.PersistentFlags().Lookup("zpa-terraform-install-path"))
	_ = viper.BindEnv("zpa-terraform-install-path", "ZSCALER_ZPA_TERRAFORM_INSTALL_PATH")

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "zia-terraform-install-path", ".", "Path to the ZIA Terraform installation")
	_ = viper.BindPFlag("zia-terraform-install-path", rootCmd.PersistentFlags().Lookup("zia-terraform-install-path"))
	_ = viper.BindEnv("zia-terraform-install-path", "ZSCALER_ZIA_TERRAFORM_INSTALL_PATH")

	rootCmd.PersistentFlags().StringVar(&zpaProviderNamespace, "zpa-provider-namespace", "", "Custom namespace for the ZPA provider")
	_ = viper.BindPFlag("zpa-provider-namespace", rootCmd.PersistentFlags().Lookup("zpa-provider-namespace"))
	_ = viper.BindEnv("zpa-provider-namespace", "ZPA_PROVIDER_NAMESPACE")

	rootCmd.PersistentFlags().StringVar(&zpaProviderNamespace, "zia-provider-namespace", "", "Custom namespace for the ZIA provider")
	_ = viper.BindPFlag("zia-provider-namespace", rootCmd.PersistentFlags().Lookup("zia-provider-namespace"))
	_ = viper.BindEnv("zia-provider-namespace", "ZIA_PROVIDER_NAMESPACE")

	rootCmd.PersistentFlags().StringVar(&supportedResources, "supported-resources", "", "List supported resources for ZPA or ZIA")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvPrefix("")

	// Ensure ZSCALER_SDK_CACHE_DISABLED is set to true
	err := os.Setenv("ZSCALER_SDK_CACHE_DISABLED", "true")
	if err != nil {
		log.Fatalf("failed to set environment variable ZSCALER_SDK_CACHE_DISABLED: %v", err)
	}

	var cfgLogLevel = logrus.InfoLevel

	if verbose {
		cfgLogLevel = logrus.DebugLevel
	}

	log.SetLevel(cfgLogLevel)

	// Debugging statements to verify the values
	log.Debug("ZPA Client ID:", viper.GetString("zpa_client_id"))
	log.Debug("ZPA Client Secret:", viper.GetString("zpa_client_secret"))
	log.Debug("ZPA Customer ID:", viper.GetString("zpa_customer_id"))
	log.Debug("ZPA Cloud:", viper.GetString("zpa_cloud"))
	log.Debug("ZIA Username:", viper.GetString("zia_username"))
	log.Debug("ZIA Password:", viper.GetString("zia_password"))
	log.Debug("ZIA API Key:", viper.GetString("zia_api_key"))
	log.Debug("ZIA Cloud:", viper.GetString("zia_cloud"))
}

func sharedPreRun(cmd *cobra.Command, args []string) {
	if os.Getenv("CI") != "true" {
		if api == nil {
			api = &Client{}
		}
		if strings.HasPrefix(resourceType_, "zpa_") || strings.Contains(resources, "zpa_") || resources == "*" || resources == "zpa" {
			zpaClient, err := zpa.NewClient()
			if err != nil {
				log.Fatal("failed to initialize ZPA client:", err)
			}
			api.ZPA = zpaClient
		}
		if strings.HasPrefix(resourceType_, "zia_") || strings.Contains(resources, "zia_") || resources == "*" || resources == "zia" {
			ziaClient, err := zia.NewClient()
			if err != nil {
				log.Fatal("failed to initialize ZIA client:", err)
			}
			api.ZIA = ziaClient
		}
	}
}

func listSupportedResources(prefix string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight|tabwriter.Debug)

	// Define headers with centering
	header1 := "Resource"
	header2 := "Generate Supported"
	header3 := "Import Supported"
	width1 := 50
	width2 := 18
	width3 := 18

	// Print table with double lined format and close the entire table
	fmt.Fprintf(w, "╔%s╗\n", strings.Repeat("═", width1+width2+width3+10))
	fmt.Fprintf(w, "║ %-*s │ %-*s │ %-*s   ║\n", width1, centerText(header1, width1), width2, centerText(header2, width2), width3, centerText(header3, width3))
	fmt.Fprintf(w, "╠%s╣\n", strings.Repeat("═", width1+width2+width3+10))

	for _, resource := range allSupportedResources {
		if strings.HasPrefix(resource, prefix) {
			fmt.Fprintf(w, "║ %-*s │ %-*s │ %-*s ║\n", width1, resource, width2, centerText("✅", width2), width3, centerText("✅", width3))
		}
	}
	fmt.Fprintf(w, "╚%s╝\n", strings.Repeat("═", width1+width2+width3+10))

	w.Flush()
}

func centerText(text string, width int) string {
	padding := (width - len(text)) / 2
	return fmt.Sprintf("%*s%s%*s", padding, "", text, padding, "")
}
