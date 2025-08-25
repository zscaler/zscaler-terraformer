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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler"
	zia "github.com/zscaler/zscaler-terraformer/v2/providers/zia"
	zpa "github.com/zscaler/zscaler-terraformer/v2/providers/zpa"
)

var log = logrus.New()
var terraformInstallPath string

// ONEAPI Fields.
var oneAPIClientID string      // required
var oneAPIClientSecret string  // required
var oneAPIVanityDomain string  // required
var oneAPICustomerID string    // optional
var oneAPIMicrotenantID string // optional
var oneAPICloud string         // optional

// ZPA Legacy Fields.
var zpaClientID string      // required
var zpaClientSecret string  // required
var zpaCustomerID string    // required
var zpaMicrotenantID string // optional
var zpaCloud string         // optional

// ZIA Legacy Fields.
var ziaUsername string // required
var ziaPassword string // required
var ziaAPIKey string   // required
var ziaCloud string    // required

var useLegacyClient bool
var verbose, displayReleaseVersion bool
var supportedResources string

var resourceType_, resources, excludedResources string

var api *Client
var terraformImportCmdPrefix = "terraform import"
var zpaProviderNamespace, ziaProviderNamespace string

type Client struct {
	ZPAService *zscaler.Service
	ZIAService *zscaler.Service
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
	"zia_sandbox_rules",
	"zia_file_type_control_rules",
	"zia_ssl_inspection_rules",
	"zia_firewall_dns_rule",
	"zia_firewall_ips_rule",
	"zia_advanced_settings",
	"zia_advanced_threat_settings",
	"zia_atp_malicious_urls",
	"zia_end_user_notification",
	"zia_url_filtering_and_cloud_app_settings",
}

// rootCmd represents the base command when called without any subcommands.
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
		// Handle --version flag
		if displayReleaseVersion {
			cliVersion := getCLIVersion()
			platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
			fmt.Printf("zscaler-terraformer %s\n", cliVersion)

			terraformVersion, err := exec.Command("terraform", "version").Output()
			if err != nil {
				log.Error("failed to get Terraform version")
			} else {
				tfVersion := strings.Split(string(terraformVersion), "\n")[0]
				fmt.Printf("Terraform version: %s\n", tfVersion)
			}
			fmt.Printf("on (%s)\n", platform)

			latestVersion := getLatestReleaseVersion()
			if cliVersion != latestVersion {
				fmt.Printf("\nYour version of Zscaler-Terraformer is out of date! The latest version\nis %s. You can update by running the command\n", latestVersion)

				if runtime.GOOS == "windows" {
					fmt.Println("\"choco upgrade zscaler-terraformer\"")
				} else {
					fmt.Println("\"brew upgrade zscaler/tap/zscaler-terraformer\"")
				}

				fmt.Println("or download the new version from")
				fmt.Println("https://github.com/zscaler/zscaler-terraformer/releases")
			}
			return
		}

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

	// -----------------------
	// OneAPI flags (V3)
	// -----------------------
	rootCmd.PersistentFlags().StringVar(&oneAPIClientID, "client_id", "", "OneAPI client_id (required in V3 mode)")
	if err := viper.BindPFlag("client_id", rootCmd.PersistentFlags().Lookup("client_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("client_id", "ZSCALER_CLIENT_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&oneAPIClientSecret, "client_secret", "", "OneAPI client_secret (required in V3 mode)")
	if err := viper.BindPFlag("client_secret", rootCmd.PersistentFlags().Lookup("client_secret")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("client_secret", "ZSCALER_CLIENT_SECRET"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&oneAPIVanityDomain, "vanity_domain", "", "OneAPI vanity_domain (required in V3 mode)")
	if err := viper.BindPFlag("vanity_domain", rootCmd.PersistentFlags().Lookup("vanity_domain")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("vanity_domain", "ZSCALER_VANITY_DOMAIN"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&oneAPICustomerID, "customer_id", "", "OneAPI optional customer_id")
	if err := viper.BindPFlag("customer_id", rootCmd.PersistentFlags().Lookup("customer_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("customer_id", "ZPA_CUSTOMER_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&oneAPIMicrotenantID, "microtenant_id", "", "OneAPI optional microtenant_id")
	if err := viper.BindPFlag("microtenant_id", rootCmd.PersistentFlags().Lookup("microtenant_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("microtenant_id", "ZPA_MICROTENANT_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&oneAPICloud, "zscaler_cloud", "", "OneAPI optional zscaler_cloud (e.g. PRODUCTION)")
	if err := viper.BindPFlag("zscaler_cloud", rootCmd.PersistentFlags().Lookup("zscaler_cloud")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zscaler_cloud", "ZSCALER_CLOUD"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	// -----------------------
	// ZPA Legacy flags (V2)
	// -----------------------
	rootCmd.PersistentFlags().StringVar(&zpaClientID, "zpa_client_id", "", "ZPA legacy client ID (required if using legacy mode for ZPA resources)")
	if err := viper.BindPFlag("zpa_client_id", rootCmd.PersistentFlags().Lookup("zpa_client_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa_client_id", "ZPA_CLIENT_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&zpaClientSecret, "zpa_client_secret", "", "ZPA legacy client secret")
	if err := viper.BindPFlag("zpa_client_secret", rootCmd.PersistentFlags().Lookup("zpa_client_secret")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa_client_secret", "ZPA_CLIENT_SECRET"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&zpaCustomerID, "zpa_customer_id", "", "ZPA legacy customer ID")
	if err := viper.BindPFlag("zpa_customer_id", rootCmd.PersistentFlags().Lookup("zpa_customer_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa_customer_id", "ZPA_CUSTOMER_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&zpaMicrotenantID, "zpa_microtenant_id", "", "ZPA legacy microtenant_id (optional)")
	if err := viper.BindPFlag("zpa_microtenant_id", rootCmd.PersistentFlags().Lookup("zpa_microtenant_id")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa_microtenant_id", "ZPA_MICROTENANT_ID"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&zpaCloud, "zpa_cloud", "", "ZPA Cloud environment (optional, e.g. PRODUCTION)")
	if err := viper.BindPFlag("zpa_cloud", rootCmd.PersistentFlags().Lookup("zpa_cloud")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa_cloud", "ZPA_CLOUD"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	// -----------------------
	// ZIA Legacy flags (V2)
	// -----------------------
	rootCmd.PersistentFlags().StringVar(&ziaUsername, "zia_username", "", "ZIA legacy username (required if using legacy mode for ZIA resources)")
	if err := viper.BindPFlag("zia_username", rootCmd.PersistentFlags().Lookup("zia_username")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia_username", "ZIA_USERNAME"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&ziaPassword, "zia_password", "", "ZIA legacy password (required)")
	if err := viper.BindPFlag("zia_password", rootCmd.PersistentFlags().Lookup("zia_password")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia_password", "ZIA_PASSWORD"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&ziaAPIKey, "zia_api_key", "", "ZIA legacy api_key (required)")
	if err := viper.BindPFlag("zia_api_key", rootCmd.PersistentFlags().Lookup("zia_api_key")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia_api_key", "ZIA_API_KEY"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&ziaCloud, "zia_cloud", "", "ZIA Cloud environment (required for ZIA legacy, e.g. zscalerthree)")
	if err := viper.BindPFlag("zia_cloud", rootCmd.PersistentFlags().Lookup("zia_cloud")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia_cloud", "ZIA_CLOUD"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	// -----------------------
	// Global toggle
	// -----------------------
	rootCmd.PersistentFlags().BoolVar(&useLegacyClient, "use_legacy_client", false, "Enable Legacy Mode (true/false)")
	if err := viper.BindPFlag("use_legacy_client", rootCmd.PersistentFlags().Lookup("use_legacy_client")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("use_legacy_client", "ZSCALER_USE_LEGACY_CLIENT"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	// -----------------------
	// Additional flags
	// -----------------------
	rootCmd.PersistentFlags().StringVar(&excludedResources, "exclude", "", "Which resources you wish to exclude")
	rootCmd.PersistentFlags().StringVar(&resourceType_, "resource-type", "", "Which resource you wish to generate")
	rootCmd.PersistentFlags().StringVar(&resources, "resources", "", "Which resources you wish to import")
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Show help for zscaler-terraformer")
	rootCmd.PersistentFlags().StringVar(&supportedResources, "supported-resources", "", "List supported resources for ZPA or ZIA")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose debug output")
	rootCmd.PersistentFlags().BoolVarP(&displayReleaseVersion, "version", "", false, "Display the release version")

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "terraform-install-path", ".", "Path to the default Terraform installation")
	if err := viper.BindPFlag("terraform-install-path", rootCmd.PersistentFlags().Lookup("terraform-install-path")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("terraform-install-path", "ZSCALER_TERRAFORM_INSTALL_PATH"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "zpa-terraform-install-path", ".", "Path to the ZPA Terraform installation")
	if err := viper.BindPFlag("zpa-terraform-install-path", rootCmd.PersistentFlags().Lookup("zpa-terraform-install-path")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa-terraform-install-path", "ZSCALER_ZPA_TERRAFORM_INSTALL_PATH"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&terraformInstallPath, "zia-terraform-install-path", ".", "Path to the ZIA Terraform installation")
	if err := viper.BindPFlag("zia-terraform-install-path", rootCmd.PersistentFlags().Lookup("zia-terraform-install-path")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia-terraform-install-path", "ZSCALER_ZIA_TERRAFORM_INSTALL_PATH"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&zpaProviderNamespace, "zpa-provider-namespace", "", "Custom namespace for the ZPA provider")
	if err := viper.BindPFlag("zpa-provider-namespace", rootCmd.PersistentFlags().Lookup("zpa-provider-namespace")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zpa-provider-namespace", "ZPA_PROVIDER_NAMESPACE"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}

	rootCmd.PersistentFlags().StringVar(&ziaProviderNamespace, "zia-provider-namespace", "", "Custom namespace for the ZIA provider")
	if err := viper.BindPFlag("zia-provider-namespace", rootCmd.PersistentFlags().Lookup("zia-provider-namespace")); err != nil {
		log.Fatalf("failed to bind flag: %v", err)
	}
	if err := viper.BindEnv("zia-provider-namespace", "ZIA_PROVIDER_NAMESPACE"); err != nil {
		log.Fatalf("failed to bind env: %v", err)
	}
}

func initConfig() {
	viper.AutomaticEnv()   // read environment variables if set
	viper.SetEnvPrefix("") // optional prefix, can be removed if undesired

	// Set log level
	var cfgLogLevel = logrus.InfoLevel
	if verbose {
		cfgLogLevel = logrus.DebugLevel
	}
	log.SetLevel(cfgLogLevel)

	// Read the toggle
	useLegacyClient = viper.GetBool("use_legacy_client")

	// -----------------------
	// Read the CLI or env values into our global variables
	// -----------------------
	// OneAPI
	oneAPIClientID = viper.GetString("client_id")
	oneAPIClientSecret = viper.GetString("client_secret")
	oneAPIVanityDomain = viper.GetString("vanity_domain")
	oneAPICustomerID = viper.GetString("customer_id")
	oneAPIMicrotenantID = viper.GetString("microtenant_id")
	oneAPICloud = viper.GetString("zscaler_cloud")

	// ZPA legacy
	zpaClientID = viper.GetString("zpa_client_id")
	zpaClientSecret = viper.GetString("zpa_client_secret")
	zpaCustomerID = viper.GetString("zpa_customer_id")
	zpaMicrotenantID = viper.GetString("zpa_microtenant_id")
	zpaCloud = viper.GetString("zpa_cloud")

	// ZIA legacy
	ziaUsername = viper.GetString("zia_username")
	ziaPassword = viper.GetString("zia_password")
	ziaAPIKey = viper.GetString("zia_api_key")
	ziaCloud = viper.GetString("zia_cloud")

	// Debug logs of what we got
	// log.Debugf("use_legacy_client=%v", useLegacyClient)
	// log.Debugf("[ONEAPI] client_id=%s, client_secret=%s, vanity_domain=%s, customer_id=%s, microtenant_id=%s, zscaler_cloud=%s",
	// 	oneAPIClientID, oneAPIClientSecret, oneAPIVanityDomain, oneAPICustomerID, oneAPIMicrotenantID, oneAPICloud)
	// log.Debugf("[ZPA Legacy] zpa_client_id=%s, zpa_client_secret=%s, zpa_customer_id=%s, zpa_microtenant_id=%s, zpa_cloud=%s",
	// 	zpaClientID, zpaClientSecret, zpaCustomerID, zpaMicrotenantID, zpaCloud)
	// log.Debugf("[ZIA Legacy] zia_username=%s, zia_password=%s, zia_api_key=%s, zia_cloud=%s",
	// 	ziaUsername, ziaPassword, ziaAPIKey, ziaCloud)

	log.Debug("[INFO] initConfig success (no validation).")

	// ----------------------------------------------------
	// FIX: Bridge the values from these top-level variables
	// into the EXACT viper keys that the providers use.
	// ----------------------------------------------------
	// For OneAPI in providers/zpa/client.go or providers/zia/client.go:
	viper.Set("client_id", oneAPIClientID)
	viper.Set("client_secret", oneAPIClientSecret)
	viper.Set("vanity_domain", oneAPIVanityDomain)
	viper.Set("customer_id", oneAPICustomerID)
	viper.Set("microtenant_id", oneAPIMicrotenantID)
	viper.Set("zscaler_cloud", oneAPICloud)

	// For ZPA Legacy in providers/zpa/client.go:
	viper.Set("zpa_client_id", zpaClientID)
	viper.Set("zpa_client_secret", zpaClientSecret)
	viper.Set("zpa_customer_id", zpaCustomerID)
	viper.Set("zpa_microtenant_id", zpaMicrotenantID)
	viper.Set("zpa_cloud", zpaCloud)

	// For ZIA Legacy (providers/zia/client.go or similar):
	viper.Set("username", ziaUsername) // your code calls viper.GetString("username")
	viper.Set("password", ziaPassword)
	viper.Set("api_key", ziaAPIKey)
	viper.Set("zia_cloud", ziaCloud) // some code calls viper.GetString("zia_cloud")

	// Also set the legacy toggle for the second layer:
	viper.Set("use_legacy_client", useLegacyClient)
}

func sharedPreRun(cmd *cobra.Command, args []string) {
	if os.Getenv("CI") != "true" {
		if api == nil {
			api = &Client{}
		}
		if wantsZPA(resourceType_, resources) {
			zpaCli, err := zpa.NewClient()
			if err != nil {
				log.Fatal("failed to initialize ZPA client:", err)
			}
			api.ZPAService = zpaCli.Service
		}
		if wantsZIA(resourceType_, resources) {
			ziaCli, err := zia.NewClient()
			if err != nil {
				log.Fatal("failed to initialize ZIA client:", err)
			}
			api.ZIAService = ziaCli.Service
		}
	}
}

func wantsZPA(rt, rs string) bool {
	return strings.HasPrefix(rt, "zpa_") ||
		strings.Contains(rs, "zpa_") ||
		rs == "*" || rs == "zpa"
}

func wantsZIA(rt, rs string) bool {
	return strings.HasPrefix(rt, "zia_") ||
		strings.Contains(rs, "zia_") ||
		rs == "*" || rs == "zia"
}

func listSupportedResources(prefix string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight|tabwriter.Debug)

	header1 := "Resource"
	header2 := "Generate Supported"
	header3 := "Import Supported"
	width1 := 50
	width2 := 18
	width3 := 18

	fmt.Fprintf(w, "╔%s╗\n", strings.Repeat("═", width1+width2+width3+10))
	fmt.Fprintf(w, "║ %-*s │ %-*s │ %-*s   ║\n",
		width1, centerText(header1, width1),
		width2, centerText(header2, width2),
		width3, centerText(header3, width3))
	fmt.Fprintf(w, "╠%s╣\n", strings.Repeat("═", width1+width2+width3+10))

	for _, resource := range allSupportedResources {
		if strings.HasPrefix(resource, prefix) {
			fmt.Fprintf(w, "║ %-*s │ %-*s │ %-*s ║\n",
				width1, resource,
				width2, centerText("✅", width2),
				width3, centerText("✅", width3))
		}
	}
	fmt.Fprintf(w, "╚%s╝\n", strings.Repeat("═", width1+width2+width3+10))

	if err := w.Flush(); err != nil {
		log.Fatalf("Error flushing output: %v", err)
	}
}

func centerText(text string, width int) string {
	padding := (width - len(text)) / 2
	return fmt.Sprintf("%*s%s%*s", padding, "", text, padding, "")
}
