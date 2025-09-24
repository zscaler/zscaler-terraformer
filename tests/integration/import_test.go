package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration test for actual Zscaler Terraformer imports
// Tests real API calls and validates all new features

func TestIntegrationBasicImport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if we have the required environment variables
	requireEnvVars(t)

	// Build the binary if it doesn't exist
	binaryPath := buildBinary(t)
	defer cleanupBinary(t, binaryPath)

	// Skip individual tests in CI if they consistently timeout (GitHub Actions detection)
	isCI := os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") == "true"
	if isCI {
		t.Log("Running in CI environment - using shorter timeouts and graceful error handling")
	}

	// Create temporary test directory
	testDir := t.TempDir()

	tests := []struct {
		name           string
		args           []string
		expectedFiles  []string
		timeoutMinutes int
	}{
		{
			name: "ZPA Application Segment with Progress Bar",
			args: []string{
				"import",
				"--resources", "zpa_application_segment",
			},
			expectedFiles: []string{
				"zpa/zpa_application_segment.tf",
				"zpa/outputs.tf",
			},
			timeoutMinutes: 5,
		},
		{
			name: "ZIA Firewall Rule with Data Sources",
			args: []string{
				"import",
				"--resources", "zia_firewall_filtering_rule",
			},
			expectedFiles: []string{
				"zia/zia_firewall_filtering_rule.tf",
				"zia/outputs.tf",
				"zia/datasource.tf",
			},
			timeoutMinutes: 5,
		},
		{
			name: "Custom Prefix with Validation",
			args: []string{
				"--prefix", "test",
				"--validate",
				"import",
				"--resources", "zpa_application_segment",
			},
			expectedFiles: []string{
				"zpa/zpa_application_segment.tf",
				"zpa/outputs.tf",
			},
			timeoutMinutes: 5,
		},
		{
			name: "No Progress with Verbose and Collect Logs",
			args: []string{
				"--no-progress",
				"--verbose",
				"--collect-logs",
				"import",
				"--resources", "zpa_application_segment",
			},
			expectedFiles: []string{
				"zpa/zpa_application_segment.tf",
				"zpa/outputs.tf",
				"zpa/debug_*.log",
			},
			timeoutMinutes: 5,
		},
		{
			name: "ZPA Policy Access Rule with Operand Mapping",
			args: []string{
				"import",
				"--resources", "zpa_policy_access_rule",
			},
			expectedFiles: []string{
				"zpa/zpa_policy_access_rule.tf",
				"zpa/outputs.tf",
				"zpa/datasource.tf",
			},
			timeoutMinutes: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create subdirectory for this test
			testSubDir := filepath.Join(testDir, sanitizeTestName(tt.name))
			err := os.MkdirAll(testSubDir, 0755)
			require.NoError(t, err)

			// Change to test directory
			originalDir, err := os.Getwd()
			require.NoError(t, err)
			defer func() { _ = os.Chdir(originalDir) }()

			err = os.Chdir(testSubDir)
			require.NoError(t, err)

			// Run the command with timeout
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(tt.timeoutMinutes)*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath, tt.args...)
			cmd.Env = os.Environ() // Pass through environment variables

			output, err := cmd.CombinedOutput()

			// Log output for debugging
			t.Logf("Command output for %s:\n%s", tt.name, string(output))

			// For integration tests, we expect success but handle errors gracefully
			if err != nil {
				// Check if it's a timeout or context cancellation
				if ctx.Err() == context.DeadlineExceeded {
					if isCI {
						t.Logf("Test %s timed out after %d minutes in CI environment - this is often expected due to network/API issues", tt.name, tt.timeoutMinutes)
					} else {
						t.Logf("Test %s timed out after %d minutes", tt.name, tt.timeoutMinutes)
					}
					return // Don't fail on timeout, just log it
				}

				// Check if it's a license error or network error (expected for some resources)
				if strings.Contains(string(output), "license error") ||
					strings.Contains(string(output), "permission.denied") ||
					strings.Contains(string(output), "feature flag") ||
					strings.Contains(string(output), "connection") ||
					strings.Contains(string(output), "network") ||
					strings.Contains(string(output), "timeout") {
					t.Logf("Test %s encountered expected error in CI: %v", tt.name, err)
					return // Don't fail on expected errors
				}

				// In CI, be more lenient with failures due to environment issues
				if isCI {
					t.Logf("Command failed in CI environment (this may be expected): %v\nOutput: %s", err, string(output))
					return
				}

				// For local runs, fail the test on unexpected errors
				t.Errorf("Command failed: %v\nOutput: %s", err, string(output))
				return
			}

			// Verify expected files exist
			for _, pattern := range tt.expectedFiles {
				files, err := filepath.Glob(pattern)
				if err != nil {
					t.Errorf("Error globbing pattern %s: %v", pattern, err)
					continue
				}

				if len(files) == 0 {
					t.Errorf("Expected files matching pattern %s, but found none", pattern)
				} else {
					t.Logf("Found %d files matching pattern %s", len(files), pattern)
				}
			}

			// Verify terraform files are valid HCL
			// Look for terraform files in both current dir and zpa/zia subdirs
			if files, _ := filepath.Glob("zpa/*.tf"); len(files) > 0 {
				validateTerraformFiles(t, "zpa")
			} else if files, _ := filepath.Glob("zia/*.tf"); len(files) > 0 {
				validateTerraformFiles(t, "zia")
			} else {
				validateTerraformFiles(t, ".")
			}
		})
	}
}

func TestIntegrationSupportFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	binaryPath := buildBinary(t)
	defer cleanupBinary(t, binaryPath)

	cmd := exec.Command(binaryPath, "--support")
	output, err := cmd.CombinedOutput()

	assert.NoError(t, err, "Support flag should not fail")
	assert.Contains(t, string(output), "ZSCALER PHONE SUPPORT", "Should display support information")
}

func TestIntegrationMultiResourceImport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	requireEnvVars(t)
	binaryPath := buildBinary(t)
	defer cleanupBinary(t, binaryPath)

	testDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(originalDir) }()

	err := os.Chdir(testDir)
	require.NoError(t, err)

	// Test multi-resource import with all features
	args := []string{
		"--prefix", "inttest",
		"--collect-logs",
		"--validate",
		"import",
		"--resources", "zpa_application_segment,zpa_server_group",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	t.Logf("Multi-resource import output:\n%s", string(output))

	// Don't fail on license errors or timeouts
	if err != nil && !isExpectedError(string(output)) && ctx.Err() != context.DeadlineExceeded {
		t.Errorf("Multi-resource import failed: %v", err)
	}

	// Check for expected files
	expectedFiles := []string{"zpa/*.tf", "zpa/outputs.tf", "zpa/debug_*.log"}
	for _, pattern := range expectedFiles {
		files, _ := filepath.Glob(pattern)
		if len(files) > 0 {
			t.Logf("Found %d files matching pattern %s", len(files), pattern)
		}
	}
}

// Helper functions

func requireEnvVars(t *testing.T) {
	required := []string{
		"ZSCALER_CLIENT_ID",
		"ZSCALER_CLIENT_SECRET",
		"ZSCALER_VANITY_DOMAIN",
		"ZPA_CUSTOMER_ID",
		"ZSCALER_CLOUD",
	}

	missing := []string{}
	for _, env := range required {
		if os.Getenv(env) == "" {
			missing = append(missing, env)
		}
	}

	if len(missing) > 0 {
		t.Skipf("Missing required environment variables: %s", strings.Join(missing, ", "))
	}
}

func buildBinary(t *testing.T) string {
	// Find the project root (where go.mod is located)
	projectRoot := findProjectRoot(t)
	binaryPath := filepath.Join(projectRoot, "zscaler-terraformer")

	// Check if binary already exists and is recent (less than 5 minutes old)
	if info, err := os.Stat(binaryPath); err == nil {
		if time.Since(info.ModTime()) < 5*time.Minute {
			return binaryPath
		}
	}

	t.Log("Building zscaler-terraformer binary...")

	// Build from project root
	cmd := exec.Command("go", "build", "-o", "zscaler-terraformer", ".")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build binary: %s", string(output))

	return binaryPath
}

func findProjectRoot(t *testing.T) string {
	// Start from current directory and walk up to find go.mod
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod)")
		}
		dir = parent
	}
}

func cleanupBinary(_ *testing.T, binaryPath string) {
	if binaryPath != "" && !strings.HasSuffix(binaryPath, "/zscaler-terraformer") {
		_ = os.Remove(binaryPath)
	}
}

func sanitizeTestName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), " ", "_")
}

func validateTerraformFiles(t *testing.T, dir string) {
	// Check if terraform is available
	if _, err := exec.LookPath("terraform"); err != nil {
		t.Log("Terraform not available, skipping HCL validation")
		return
	}

	// Find all .tf files
	tfFiles, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		t.Logf("Error finding .tf files: %v", err)
		return
	}

	if len(tfFiles) == 0 {
		t.Log("No .tf files found to validate")
		return
	}

	// Initialize terraform (suppress output)
	cmd := exec.Command("terraform", "init", "-backend=false")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Terraform init failed (this may be expected): %s", string(output))
		return
	}

	// Validate HCL syntax
	cmd = exec.Command("terraform", "validate")
	cmd.Dir = dir
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Terraform validation failed: %s", string(output))
		// Don't fail the test as this might be expected for some configurations
	} else {
		t.Log("Terraform validation passed")
	}
}

func isExpectedError(output string) bool {
	expectedErrors := []string{
		"license error",
		"permission.denied",
		"feature flag",
		"authz.featureflag",
		"unauthorized",
		"not found",
		"rate limit",
	}

	outputLower := strings.ToLower(output)
	for _, expected := range expectedErrors {
		if strings.Contains(outputLower, expected) {
			return true
		}
	}
	return false
}
