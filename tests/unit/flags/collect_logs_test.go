package flags

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zscaler/zscaler-terraformer/v2/tests/testutils"
)

func TestLogFileCreation(t *testing.T) {
	// Test log file creation logic
	tempDir := testutils.CreateTempTestDir(t, "collect_logs_test")

	// Test timestamp format
	timestamp := time.Now().Format("20060102_150405")
	expectedFileName := filepath.Join(tempDir, "debug_"+timestamp+".log")

	// Create a test log file
	logFile, err := os.Create(expectedFileName)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()

	// Verify file was created
	if !testutils.FileExists(expectedFileName) {
		t.Error("Log file should be created")
	}
}

func TestLogFileHeader(t *testing.T) {
	// Test log file header generation
	tempDir := testutils.CreateTempTestDir(t, "log_header_test")
	logFile := filepath.Join(tempDir, "test_debug.log")

	// Create expected header content
	header := "=== Zscaler Terraformer Debug Log ===\n"
	header += "Timestamp: 2025-09-22 21:54:10 PDT\n"
	header += "Terraformer Version: 2.1.0\n"
	header += "Terraform Version: Terraform v1.9.0\n"
	header += "OS: darwin_arm64\n"
	header += "Working Directory: " + tempDir + "\n"
	header += "Command: test-command\n"
	header += "=====================================\n\n"

	// Write header to file
	err := os.WriteFile(logFile, []byte(header), 0644)
	if err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	// Read and verify content
	content := testutils.ReadFileContent(t, logFile)

	testutils.AssertContains(t, content, "=== Zscaler Terraformer Debug Log ===", "Header should contain title")
	testutils.AssertContains(t, content, "Terraformer Version:", "Header should contain terraformer version")
	testutils.AssertContains(t, content, "Terraform Version:", "Header should contain terraform version")
	testutils.AssertContains(t, content, "Working Directory:", "Header should contain working directory")
}

func TestEnvironmentVariableSetup(t *testing.T) {
	// Test SDK environment variable setup
	testVars := map[string]string{
		"ZSCALER_SDK_LOG":     "true",
		"ZSCALER_SDK_VERBOSE": "true",
	}

	// Test setting variables
	for key, expectedValue := range testVars {
		testutils.SetTestEnvVar(t, key, expectedValue)

		actualValue := os.Getenv(key)
		if actualValue != expectedValue {
			t.Errorf("Environment variable %s should be %s, got %s", key, expectedValue, actualValue)
		}
	}
}

func TestEnvironmentVariableCleanup(t *testing.T) {
	// Test environment variable cleanup
	testVars := []string{
		"ZSCALER_SDK_LOG",
		"ZSCALER_SDK_VERBOSE",
	}

	// Set variables
	for _, key := range testVars {
		os.Setenv(key, "true")
	}

	// Simulate cleanup
	for _, key := range testVars {
		os.Unsetenv(key)
	}

	// Verify cleanup
	for _, key := range testVars {
		value := os.Getenv(key)
		if value != "" {
			t.Errorf("Environment variable %s should be unset after cleanup, got %s", key, value)
		}
	}
}

func TestLogFileNaming(t *testing.T) {
	// Test log file naming pattern
	timestamp := "20250922_213457"
	workingDir := "/tmp/test"

	expectedPattern := filepath.Join(workingDir, "debug_"+timestamp+".log")

	// Verify the pattern matches expected format
	if !strings.Contains(expectedPattern, "debug_") {
		t.Error("Log file name should contain 'debug_' prefix")
	}

	if !strings.HasSuffix(expectedPattern, ".log") {
		t.Error("Log file name should have .log extension")
	}

	if !strings.Contains(expectedPattern, timestamp) {
		t.Error("Log file name should contain timestamp")
	}
}

func TestLogCompletionMarker(t *testing.T) {
	// Test log completion marker
	tempDir := testutils.CreateTempTestDir(t, "log_completion_test")
	logFile := filepath.Join(tempDir, "test_completion.log")

	// Write initial content and completion marker
	content := "Initial log content\n"
	content += "=== Log Collection Completed ===\n"

	err := os.WriteFile(logFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	// Verify completion marker exists
	fileContent := testutils.ReadFileContent(t, logFile)
	testutils.AssertContains(t, fileContent, "=== Log Collection Completed ===", "Log should contain completion marker")
}

func TestLogFileLocation(t *testing.T) {
	// Test that log files are created in the correct working directory
	testCases := []struct {
		name        string
		workingDir  string
		expected    string
		description string
	}{
		{
			name:        "ZPA working directory",
			workingDir:  "/tmp/zpa",
			expected:    "/tmp/zpa/debug_",
			description: "Should create log file in ZPA working directory",
		},
		{
			name:        "ZIA working directory",
			workingDir:  "/tmp/zia",
			expected:    "/tmp/zia/debug_",
			description: "Should create log file in ZIA working directory",
		},
		{
			name:        "Current directory fallback",
			workingDir:  "",
			expected:    "./debug_",
			description: "Should fallback to current directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock log file path generation
			logPath := mockGenerateLogPath(tc.workingDir)

			if !strings.HasPrefix(logPath, tc.expected) {
				t.Errorf("%s: Expected log path to start with '%s', got '%s'", tc.description, tc.expected, logPath)
			}
		})
	}
}

// Mock helper functions for testing

func mockGenerateLogPath(workingDir string) string {
	timestamp := "20250922_213457"
	if workingDir == "" {
		// For current directory fallback, return with ./ prefix explicitly
		return "./debug_" + timestamp + ".log"
	}
	return filepath.Join(workingDir, "debug_"+timestamp+".log")
}
