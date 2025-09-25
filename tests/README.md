# Zscaler Terraformer Tests

This directory contains the test suite for the Zscaler Terraformer tool.

## Directory Structure

```
tests/
├── unit/                           # Unit tests (fast, isolated)
│   ├── flags/                      # Command line flag tests
│   ├── processing/                 # Core processing logic tests
│   ├── error_handling/             # Error handling tests
│   └── utils/                      # Utility function tests
├── testutils/                      # Common test utilities
├── fixtures/                       # Test data and mock responses
└── run_unit_tests.go              # Standalone test runner
```

## Running Tests

### Using Make Commands (Recommended)

```bash
# Run all unit tests (quick)
make test

# Run unit tests with verbose output
make test-unit

# Run unit tests with coverage report
make test-coverage

# Generate HTML coverage report
make test-coverage-html

# Run all tests (unit + integration)
make test-all

# Clean test artifacts
make test-clean
```

### Using Go Commands Directly

```bash
# Run all unit tests
go test ./tests/unit/... -timeout 30s

# Run with verbose output
go test -v ./tests/unit/... -timeout 30s

# Run with coverage
go test -cover ./tests/unit/... -timeout 30s

# Run specific test package
go test -v ./tests/unit/flags/... -timeout 30s

# Run specific test function
go test -v ./tests/unit/flags/... -run TestSupportContactsDataStructure
```

### Using the Standalone Runner

```bash
# Run using the custom test runner
go run tests/run_unit_tests.go
```

## Test Categories

### Unit Tests
- **Purpose**: Fast, isolated testing of individual components
- **Duration**: ~30 seconds
- **Dependencies**: None (mocked)
- **Coverage**: Flags, processing logic, error handling, utilities

### Integration Tests (Future)
- **Purpose**: End-to-end workflow testing
- **Duration**: ~5 minutes
- **Dependencies**: API credentials required
- **Coverage**: Full import/generate workflows

## Test Utilities

The `testutils` package provides common testing utilities:

- **File Operations**: Temp directories, test file creation
- **Environment Management**: Variable setup/cleanup
- **Output Capture**: Console output testing
- **Assertions**: String containment, custom assertions

## Test Fixtures

The `fixtures` package contains:

- **Sample HCL**: Example terraform configurations
- **Mock Responses**: API response samples
- **Error Cases**: Various error scenarios
- **Expected Outputs**: Reference data for validation

## Coverage Goals

- **Unit Tests**: Aim for >80% coverage
- **Critical Paths**: 100% coverage for error handling
- **New Features**: All new flags and features should have tests

## Contributing

When adding new features:

1. **Add Unit Tests**: Create tests in appropriate `tests/unit/` subdirectory
2. **Update Fixtures**: Add any new test data to `tests/fixtures/`
3. **Run Tests**: Use `make test-coverage` to verify coverage
4. **Update Documentation**: Update this README if needed

## CI/CD Integration

Tests are automatically run in GitHub Actions:
- **On Pull Requests**: Unit tests must pass before merge
- **On Push to Master**: Full test suite execution
- **Scheduled Runs**: Daily test execution for stability

## Troubleshooting

### Test Failures
```bash
# Run specific failing test with verbose output
go test -v ./tests/unit/flags/... -run TestSpecificFunction

# Check coverage for specific package
go test -cover ./tests/unit/processing/...
```

### Coverage Issues
```bash
# Generate detailed coverage report
make test-coverage-html
# Open coverage.html in browser to see uncovered lines
```

### Environment Issues
```bash
# Clean test artifacts and retry
make test-clean
make test
```
