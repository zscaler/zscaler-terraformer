package integration

import (
	"os"
	"strings"
	"testing"
)

// Simple integration test that validates environment setup
// The actual integration testing is handled by the Makefile
func TestIntegrationEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if we have the required environment variables
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

	t.Log("✅ All required environment variables are set")
	t.Log("Integration tests should be run via: make test-integration")
}
