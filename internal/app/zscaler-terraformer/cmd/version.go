package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var versionString = "pre-release"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of zscaler-terraformer",
	Run: func(cmd *cobra.Command, args []string) {
		if versionString == "pre-release" {
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

		fmt.Printf("zscaler-terraformer %s\n", versionString)
	},
}
