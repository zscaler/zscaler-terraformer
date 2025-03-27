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
			fmt.Printf("\nYour version of Zscaler-Terraformer is out of date! The latest version\nis %s. You can update by running the command\n", latestVersion)

			if runtime.GOOS == "windows" {
				fmt.Println("\"choco upgrade zscaler-terraformer\"")
			} else {
				fmt.Println("\"brew upgrade zscaler/tap/zscaler-terraformer\"")
			}

			fmt.Println("or download the new version from")
			fmt.Println("https://github.com/zscaler/zscaler-terraformer/releases")
		}
	},
}

func getCLIVersion() string {
	if versionString == "dev" {
		// Attempt to get a tag name from Git
		gitDescribe := exec.Command("git", "describe", "--tags", "--abbrev=0")
		gitDescribeStdout, err := gitDescribe.Output()
		if err != nil {
			// If we fail, just keep it "dev"
			return versionString
		}

		// Attempt to get the short commit SHA
		gitSha := exec.Command("git", "rev-parse", "--short=12", "HEAD")
		gitShaStdout, err := gitSha.Output()
		if err != nil {
			// If we fail here, just return e.g. "v1.2.3-dev"
			return strings.TrimSpace(string(gitDescribeStdout)) + "-" + versionString
		}

		versionString = strings.TrimSpace(string(gitDescribeStdout)) +
			"-dev+" + strings.TrimSpace(string(gitShaStdout))
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
