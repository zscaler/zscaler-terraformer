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
	"os/exec"
	"runtime"
	"strings"

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

		fmt.Println("\nFor the latest releases and updates, visit:")
		fmt.Println("https://github.com/zscaler/zscaler-terraformer/releases")
	},
}
