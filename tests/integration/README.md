# Integration Tests

This directory contains integration tests for Zscaler Terraformer that perform actual API calls against Zscaler services.

## Prerequisites

### Environment Variables

The following environment variables must be set:

```bash
export ZSCALER_CLIENT_ID="your_client_id"
export ZSCALER_CLIENT_SECRET="your_client_secret"
export ZSCALER_VANITY_DOMAIN="your_domain"
export ZPA_CUSTOMER_ID="your_customer_id"
export ZSCALER_CLOUD="production"
```

### Required Tools

- Go 1.24+
- Terraform (for validation tests)
- Internet connection (for API calls)

## Running Integration Tests

### Option 1: Using the Test Runner Script

```bash
# From project root
./tests/integration/run_integration_tests.sh
```

### Option 2: Using Go Test Directly

```bash
# From project root
go test -v ./tests/integration/... -timeout 10m
```

### Option 3: Running Specific Tests

```bash
# Run only basic import test
go test -v ./tests/integration/... -run TestIntegrationBasicImport -timeout 5m

# Run only support flag test
go test -v ./tests/integration/... -run TestIntegrationSupportFlag
```

## Test Coverage

The integration tests validate the following features:

### 🚀 Core Functionality
- **Progress Bar as Default** - Verifies the colored progress bar is shown by default
- **No-Progress Flag** - Tests `--no-progress` with verbose scrolling output
- **Custom Prefix** - Validates `--prefix` flag for custom resource naming
- **Collect Logs** - Tests `--collect-logs` for SDK debug capture
- **Validate Flag** - Verifies `--validate` performs terraform validation

### 🔗 Reference Processing
- **Data Source Replacement** - Tests automatic replacement of hard-coded IDs with data source references
- **ZPA Policy Operand Mapping** - Validates complex conditional mapping for policy resources
- **Resource Reference Replacement** - Tests resource-to-resource reference mapping

### 🛡️ Error Handling
- **License Error Handling** - Graceful skipping of unlicensed features
- **API Error Recovery** - Proper handling of API timeouts and errors
- **Validation Errors** - Terraform HCL syntax validation

### 🎯 Resource Types Tested
- **ZPA Resources**: `zpa_application_segment`, `zpa_server_group`, `zpa_policy_access_rule`
- **ZIA Resources**: `zia_firewall_filtering_rule`
- **Multi-resource imports** with combined features

## Test Structure

```
tests/integration/
├── import_test.go              # Main integration test suite
├── run_integration_tests.sh    # Test runner script
└── README.md                   # This file
```

## Expected Behavior

### Successful Test Run
- All API calls complete successfully
- Terraform files are generated with proper HCL syntax
- Data sources are created and referenced correctly
- Progress bar displays correctly
- Debug logs are captured when requested

### Expected Failures (Not Test Failures)
- **License Errors**: Some resources may fail due to feature flags
- **API Rate Limits**: Tests include timeout handling
- **Missing Resources**: Tests gracefully handle missing resources

## CI/CD Integration

Integration tests run automatically in GitHub Actions when:

- Pull requests are opened or updated
- Code is pushed to master
- Scheduled runs (weekdays at 2 PM UTC)
- Manual workflow dispatch

### GitHub Secrets Required
The following secrets must be configured in the GitHub repository:

- `ZSCALER_CLIENT_ID`
- `ZSCALER_CLIENT_SECRET`
- `ZSCALER_VANITY_DOMAIN`
- `ZPA_CUSTOMER_ID`
- `ZSCALER_CLOUD`

## Troubleshooting

### Common Issues

1. **Missing Environment Variables**
   ```
   Missing required environment variables: ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET
   ```
   **Solution**: Set all required environment variables

2. **API Rate Limits**
   ```
   Test timed out after 10 minutes
   ```
   **Solution**: Wait and retry, or reduce test concurrency

3. **License Errors**
   ```
   Feature flag feature.ddil.config disabled
   ```
   **Solution**: This is expected behavior - tests handle this gracefully

4. **Build Failures**
   ```
   Failed to build binary
   ```
   **Solution**: Ensure Go 1.24+ is installed and dependencies are available

### Debug Mode

Run tests with verbose output for debugging:

```bash
go test -v ./tests/integration/... -timeout 10m -args -test.v
```

## Security Notes

- **Never commit credentials** to version control
- **Use GitHub Secrets** for CI/CD environment variables
- **Rotate credentials regularly** for security
- **Monitor API usage** to avoid rate limits

## Contributing

When adding new integration tests:

1. Follow the existing test structure
2. Include proper error handling
3. Add timeout contexts for long-running tests
4. Update this README with new test coverage
5. Ensure tests are idempotent (can run multiple times)
