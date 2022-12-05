package cmd

import (
	homedir "github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var log = logrus.New()
var cfgFile, terraformInstallPath string
var zpaCloud, zpaClientID, zpaClientSecret, zpaCustomerID string
var ziaCloud, ziaUsername, ziaPassword, ziaApiKey string

var verbose bool
var api *Client
var terraformImportCmdPrefix = "terraform import"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "zscaler-terraforming",
	Short: "Bootstrapping Terraform from existing ZPA/ZIA account",
	Long: `zscaler-terraforming is an application that allows ZPA/ZIA users
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

	home, err := homedir.Dir()
	if err != nil {
		log.Debug(err)
		return
	}

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", home+"/.zscaler-terraforming.yaml", "Path to config file")

	// API credentials
	rootCmd.PersistentFlags().StringVarP(&zpaClientID, "zpaClientID", "", "", "ZPA client ID")
	_ = viper.BindPFlag("zpaClientID", rootCmd.PersistentFlags().Lookup("zpaClientID"))
	_ = viper.BindEnv("zpaClientID", "ZPA_CLIENT_ID")

	rootCmd.PersistentFlags().StringVarP(&zpaClientSecret, "zpaClientSecret", "", "", "ZPA client secret")
	_ = viper.BindPFlag("zpaClientSecret", rootCmd.PersistentFlags().Lookup("zpaClientSecret"))
	_ = viper.BindEnv("zpaClientSecret", "ZPA_CLIENT_SECRET")

	rootCmd.PersistentFlags().StringVarP(&zpaCustomerID, "zpaCustomerID", "", "", "ZPA Customer ID")
	_ = viper.BindPFlag("zpaCustomerID", rootCmd.PersistentFlags().Lookup("zpaCustomerID"))
	_ = viper.BindEnv("zpaCustomerID", "ZPA_CUSTOMER_ID")

	rootCmd.PersistentFlags().StringVarP(&zpaCloud, "zpaCloud", "", "", "ZPA Cloud (BETA or PRODUCTION)")
	_ = viper.BindPFlag("zpaCloud", rootCmd.PersistentFlags().Lookup("zpaCloud"))
	_ = viper.BindEnv("zpaCloud", "ZPA_CLOUD")

	rootCmd.PersistentFlags().StringVarP(&ziaUsername, "ziaUsername", "", "", "ZIA username")
	_ = viper.BindPFlag("ziaUsername", rootCmd.PersistentFlags().Lookup("ziaUsername"))
	_ = viper.BindEnv("ziaUsername", "ZIA_USERNAME")

	rootCmd.PersistentFlags().StringVarP(&ziaPassword, "ziaPassword", "", "", "ZIA password")
	_ = viper.BindPFlag("ziaPassword", rootCmd.PersistentFlags().Lookup("ziaPassword"))
	_ = viper.BindEnv("ziaPassword", "ZIA_PASSWORD")

	rootCmd.PersistentFlags().StringVarP(&ziaApiKey, "ziaApiKey", "", "", "ZIA API Key")
	_ = viper.BindPFlag("ziaApiKey", rootCmd.PersistentFlags().Lookup("ziaApiKey"))
	_ = viper.BindEnv("ziaApiKey", "ZIA_API_KEY")

	rootCmd.PersistentFlags().StringVarP(&ziaCloud, "ziaCloud", "", "", "ZIA Cloud (i.e zscalerthree)")
	_ = viper.BindPFlag("ziaCloud", rootCmd.PersistentFlags().Lookup("ziaCloud"))
	_ = viper.BindEnv("ziaCloud", "ZIA_CLOUD")
	// Debug logging mode
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Specify verbose output (same as setting log level to debug)")

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
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			log.Debug(err)
			return
		}

		// Search config in home directory with name ".zscaler-terraforming" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".zscaler-terraforming")
	}

	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvPrefix("")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Debug("using config file:", viper.ConfigFileUsed())
	}

	var cfgLogLevel = logrus.InfoLevel

	if verbose {
		cfgLogLevel = logrus.DebugLevel
	}

	log.SetLevel(cfgLogLevel)
}
