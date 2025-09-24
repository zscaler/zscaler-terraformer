package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDebugStepByStep isolates each step to find where hanging occurs
func TestDebugStepByStep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check environment variables
	required := []string{
		"ZSCALER_CLIENT_ID",
		"ZSCALER_CLIENT_SECRET",
		"ZSCALER_VANITY_DOMAIN",
		"ZPA_CUSTOMER_ID",
		"ZSCALER_CLOUD",
	}

	for _, env := range required {
		if os.Getenv(env) == "" {
			t.Skipf("Missing required environment variable: %s", env)
		}
	}

	// Set debug environment variables
	os.Setenv("ZSCALER_SDK_LOG", "true")
	os.Setenv("ZSCALER_SDK_VERBOSE", "true")

	// Find project root and build binary
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}

	binaryPath := filepath.Join(projectRoot, "zscaler-terraformer")
	t.Log("Building zscaler-terraformer binary...")
	buildCmd := exec.Command("go", "build", "-o", "zscaler-terraformer", ".")
	buildCmd.Dir = projectRoot
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build binary: %v\nOutput: %s", err, string(buildOutput))
	}
	defer func() { _ = os.Remove(binaryPath) }()

	// Test 1: Just the generate command (no terraform imports)
	t.Log("=== TEST 1: Generate command only (no terraform imports) ===")
	testDir1 := t.TempDir()
	originalDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(originalDir) }()

	if err = os.Chdir(testDir1); err != nil {
		t.Fatalf("Failed to change to test directory: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel1()

	cmd1 := exec.CommandContext(ctx1, binaryPath,
		"generate", "--resources", "zpa_segment_group", "--no-progress")
	cmd1.Env = append(os.Environ(),
		"ZSCALER_SDK_LOG=true",
		"ZSCALER_SDK_VERBOSE=true",
	)

	output1, err1 := cmd1.CombinedOutput()
	t.Logf("Generate command output:\n%s", string(output1))

	if err1 != nil {
		if ctx1.Err() == context.DeadlineExceeded {
			t.Log("Generate command timed out - API call is hanging")
		} else {
			t.Logf("Generate command failed: %v", err1)
		}
	} else {
		t.Log("✅ Generate command completed successfully - API calls are working!")
	}

	// Test 2: Simple terraform init only
	t.Log("=== TEST 2: Terraform init only ===")
	testDir2 := t.TempDir()
	if err = os.Chdir(testDir2); err != nil {
		t.Fatalf("Failed to change to test directory: %v", err)
	}

	// Create a simple main.tf file
	mainTf := `terraform {
  required_providers {
    zpa = {
      source = "zscaler/zpa"
    }
  }
}

provider "zpa" {}
`
	if err = os.WriteFile("main.tf", []byte(mainTf), 0644); err != nil {
		t.Fatalf("Failed to write main.tf: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel2()

	cmd2 := exec.CommandContext(ctx2, "terraform", "init", "-no-color")
	cmd2.Env = os.Environ()

	output2, err2 := cmd2.CombinedOutput()
	t.Logf("Terraform init output:\n%s", string(output2))

	if err2 != nil {
		if ctx2.Err() == context.DeadlineExceeded {
			t.Log("Terraform init timed out - terraform/network issue in Docker")
		} else {
			t.Logf("Terraform init failed: %v", err2)
		}
	} else {
		t.Log("✅ Terraform init completed successfully")
	}

	// Test 3: Test a simple terraform import with fake provider
	t.Log("=== TEST 3: Simple terraform import test ===")

	// Create a minimal resource file
	resourceTf := `resource "zpa_segment_group" "test" {
  name = "test"
  description = "test"
  enabled = true
}`
	if err = os.WriteFile("resource.tf", []byte(resourceTf), 0644); err != nil {
		t.Fatalf("Failed to write resource.tf: %v", err)
	}

	ctx3, cancel3 := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel3()

	// Try a terraform import with a fake ID to see where it hangs
	cmd3 := exec.CommandContext(ctx3, "terraform", "import", "-no-color", "zpa_segment_group.test", "fake-id")
	cmd3.Env = append(os.Environ(),
		"ZSCALER_SDK_LOG=true",
		"ZSCALER_SDK_VERBOSE=true",
	)

	output3, err3 := cmd3.CombinedOutput()
	t.Logf("Terraform import output:\n%s", string(output3))

	if err3 != nil {
		if ctx3.Err() == context.DeadlineExceeded {
			t.Log("Terraform import timed out - this is the exact issue!")
		} else {
			if strings.Contains(string(output3), "does not exist") || strings.Contains(string(output3), "not found") {
				t.Log("✅ Terraform import failed as expected (fake ID) - terraform provider is working")
			} else {
				t.Logf("Terraform import failed with unexpected error: %v", err3)
			}
		}
	} else {
		t.Log("Terraform import completed unexpectedly")
	}
}
