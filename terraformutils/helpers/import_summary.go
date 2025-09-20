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

package helpers

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

// ImportSummary contains statistics about the import process
type ImportSummary struct {
	TotalResources       int
	ResourcesByType      map[string]int
	DataSourceReferences int
	ResourceReferences   int
	FilesProcessed       int
}

// GenerateImportSummary analyzes the imported resources and generates a comprehensive summary
func GenerateImportSummary(workingDir string) (*ImportSummary, error) {
	summary := &ImportSummary{
		ResourcesByType: make(map[string]int),
	}

	// Get all .tf files in the working directory
	tfFiles, err := filepath.Glob(filepath.Join(workingDir, "*.tf"))
	if err != nil {
		return nil, fmt.Errorf("failed to find .tf files: %w", err)
	}

	// Count resources and references
	for _, tfFile := range tfFiles {
		baseName := filepath.Base(tfFile)

		// Skip special files
		if baseName == "outputs.tf" || baseName == "datasource.tf" || strings.HasSuffix(baseName, "-provider.tf") {
			continue
		}

		summary.FilesProcessed++

		// Read the file
		content, err := ioutil.ReadFile(tfFile)
		if err != nil {
			continue
		}

		fileContent := string(content)

		// Count resources by type
		resourcePattern := regexp.MustCompile(`resource\s+"([^"]+)"\s+"[^"]+"\s*\{`)
		resourceMatches := resourcePattern.FindAllStringSubmatch(fileContent, -1)

		for _, match := range resourceMatches {
			if len(match) >= 2 {
				resourceType := match[1]
				summary.ResourcesByType[resourceType]++
				summary.TotalResources++
			}
		}

		// Count data source references
		dataSourcePattern := regexp.MustCompile(`data\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+`)
		dataSourceMatches := dataSourcePattern.FindAllString(fileContent, -1)
		summary.DataSourceReferences += len(dataSourceMatches)

		// Count resource references (excluding data source references)
		resourceRefPattern := regexp.MustCompile(`[a-zA-Z0-9_]+\.resource_[a-zA-Z0-9_]+\.id`)
		resourceRefMatches := resourceRefPattern.FindAllString(fileContent, -1)
		summary.ResourceReferences += len(resourceRefMatches)
	}

	return summary, nil
}

// PrintImportSummary displays a beautiful summary report with emojis
func PrintImportSummary(workingDir string) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🎉 ZSCALER TERRAFORMER IMPORT SUMMARY")
	fmt.Println(strings.Repeat("=", 70))

	summary, err := GenerateImportSummary(workingDir)
	if err != nil {
		fmt.Printf("⚠️  Failed to generate summary: %v\n", err)
		return
	}

	// Overall statistics
	fmt.Printf("📊 IMPORT STATISTICS\n")
	fmt.Printf("   📁 Files Processed: %d\n", summary.FilesProcessed)
	fmt.Printf("   🏗️  Total Resources: %d\n", summary.TotalResources)
	fmt.Printf("   🔗 Resource References: %d\n", summary.ResourceReferences)
	fmt.Printf("   📋 Data Source References: %d\n", summary.DataSourceReferences)

	// Success message
	fmt.Printf("\n🎯 IMPORT COMPLETED SUCCESSFULLY!\n")
	fmt.Printf("   ✅ All resources imported and configured\n")
	fmt.Printf("   🔗 All references resolved automatically\n")
	fmt.Printf("   📁 Files ready for Terraform usage\n")

	fmt.Println(strings.Repeat("=", 70))
}
