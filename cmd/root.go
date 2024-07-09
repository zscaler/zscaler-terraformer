package cmd

import (
	"os"
	"strings"

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
var api *Client
var terraformImportCmdPrefix = "terraform import"
var zpaProviderNamespace string

type Client struct {
	ZPA *zpa.Client
	ZIA *zia.Client
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "zscaler-terraformer",
	Short: "Bootstrapping Terraform from existing ZPA/ZIA account",
	Long: `zscaler-terraformer is an application that allows ZPA/ZIA users
to be able to adopt Terraform by giving them a feasible way to get
all of their existing ZPA/ZIA configuration into Terraform.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		return
	}
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
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvPrefix("")

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
