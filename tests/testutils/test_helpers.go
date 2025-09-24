package testutils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CreateTempTestDir creates a temporary directory for testing
func CreateTempTestDir(t *testing.T, prefix string) string {
	tempDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Cleanup function to remove temp directory after test
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	return tempDir
}

// CreateTestFile creates a test file with specified content
func CreateTestFile(t *testing.T, dir, filename, content string) string {
	filePath := filepath.Join(dir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file %s: %v", filePath, err)
	}
	return filePath
}

// FileExists checks if a file exists
func FileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}

// ReadFileContent reads and returns file content
func ReadFileContent(t *testing.T, filepath string) string {
	content, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", filepath, err)
	}
	return string(content)
}

// SetTestEnvVar sets an environment variable for testing and ensures cleanup
func SetTestEnvVar(t *testing.T, key, value string) {
	originalValue := os.Getenv(key)
	_ = os.Setenv(key, value)

	// Cleanup function to restore original value
	t.Cleanup(func() {
		if originalValue == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, originalValue)
		}
	})
}

// CaptureStdout captures stdout during function execution
func CaptureStdout(fn func()) (string, error) {
	// Create a pipe to capture output
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}

	// Store original stdout
	originalStdout := os.Stdout
	os.Stdout = w

	// Channel to capture output
	outputChan := make(chan string, 1)

	// Goroutine to read from pipe
	go func() {
		defer func() { _ = r.Close() }()
		buf := make([]byte, 1024)
		var output string
		for {
			n, err := r.Read(buf)
			if err != nil {
				break
			}
			output += string(buf[:n])
		}
		outputChan <- output
	}()

	// Execute function
	fn()

	// Restore stdout and close writer
	os.Stdout = originalStdout
	_ = w.Close()

	// Get captured output with timeout
	select {
	case output := <-outputChan:
		return output, nil
	case <-time.After(5 * time.Second):
		return "", nil // Timeout
	}
}

// AssertContains checks if a string contains a substring
func AssertContains(t *testing.T, haystack, needle, message string) {
	if !strings.Contains(haystack, needle) {
		t.Errorf("%s: Expected to contain '%s', but got: %s", message, needle, haystack)
	}
}

// AssertNotContains checks if a string does not contain a substring
func AssertNotContains(t *testing.T, haystack, needle, message string) {
	if strings.Contains(haystack, needle) {
		t.Errorf("%s: Expected NOT to contain '%s', but got: %s", message, needle, haystack)
	}
}
