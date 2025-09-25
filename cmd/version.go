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
	"time"

	"github.com/spf13/cobra"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of zscaler-terraformer",
	Run: func(cmd *cobra.Command, args []string) {
		cliVersion := terraformutils.Version()
		platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("zscaler-terraformer v%s\n", cliVersion)

		terraformVersion, err := exec.Command("terraform", "version").Output()
		if err != nil {
			log.Error("failed to get Terraform version")
		} else {
			tfVersion := strings.Split(string(terraformVersion), "\n")[0]
			fmt.Printf("Terraform version: %s\n", tfVersion)
		}
		fmt.Printf("on (%s)\n", platform)

		// Check for newer version
		checkForNewerVersion(cliVersion)

		fmt.Println("\nFor the latest releases and updates, visit:")
		fmt.Println("https://github.com/zscaler/zscaler-terraformer/releases")
	},
}

// GitHubRelease represents a GitHub release response.
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
}

// checkForNewerVersion checks GitHub releases for a newer version.
func checkForNewerVersion(currentVersion string) {
	// Create HTTP client with short timeout for non-blocking check
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Get latest release from GitHub API
	resp, err := client.Get("https://api.github.com/repos/zscaler/zscaler-terraformer/releases/latest")
	if err != nil {
		// Silently ignore network errors - don't interrupt user workflow
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Silently ignore API errors
		return
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		// Silently ignore JSON parsing errors
		return
	}

	// Extract version number from tag (remove 'v' prefix if present)
	latestVersion := strings.TrimPrefix(release.TagName, "v")

	// Compare versions (simple string comparison works for semantic versions)
	if latestVersion != currentVersion && IsNewerVersion(latestVersion, currentVersion) {
		fmt.Printf("\n\033[33m📣 A newer version of 'zscaler-terraformer' is available - consider upgrading to v%s\033[0m\n", latestVersion)
	}
}

// IsNewerVersion performs basic semantic version comparison (exported for testing).
func IsNewerVersion(latest, current string) bool {
	// Split versions into parts (major.minor.patch)
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	// Ensure we have at least 3 parts for comparison
	for len(latestParts) < 3 {
		latestParts = append(latestParts, "0")
	}
	for len(currentParts) < 3 {
		currentParts = append(currentParts, "0")
	}

	// Compare major, minor, patch in order
	for i := 0; i < 3; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}

	return false // Versions are equal
}
