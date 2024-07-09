package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var versionString = "dev"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of zscaler-terraformer",
	Run: func(cmd *cobra.Command, args []string) {
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
			fmt.Printf("\nYour version of Zscaler-Terraformer is out of date! The latest version\nis %s. You can update by running the command\n\"brew upgrade zscaler/tap/zscaler-terraformer\"\nor download the new version from\nhttps://github.com/zscaler/zscaler-terraformer/releases\n", latestVersion)
		}
	},
}

func getCLIVersion() string {
	if versionString == "dev" {
		gitDescribe := exec.Command("git", "describe", "--tags", "--abbrev=0")
		gitDescribeStdout, err := gitDescribe.Output()
		if err != nil {
			log.Error("failed to exec to `git`")
		}

		gitSha := exec.Command("git", "rev-parse", "--short=12", "HEAD")
		gitShaStdout, err := gitSha.Output()
		if err != nil {
			log.Error("failed to exec to `git`")
		}
		versionString = strings.TrimSpace(string(gitDescribeStdout)) + "-" + versionString + "+" + strings.TrimSpace(string(gitShaStdout))
	}
	return versionString
}

func getLatestReleaseVersion() string {
	resp, err := http.Get("https://api.github.com/repos/zscaler/zscaler-terraformer/releases/latest")
	if err != nil {
		log.Error("failed to get latest release version")
		return ""
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		log.Error("failed to parse latest release version")
		return ""
	}
	return release.TagName
}
