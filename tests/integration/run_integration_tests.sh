#!/bin/bash

# Integration Test Runner for Zscaler Terraformer
# Runs actual API calls against Zscaler services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT_MINUTES=10

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
    log_error "Please run this script from the project root directory"
    exit 1
fi

# Check for required environment variables
check_env_vars() {
    local missing=()
    local required=(
        "ZSCALER_CLIENT_ID"
        "ZSCALER_CLIENT_SECRET"
        "ZSCALER_VANITY_DOMAIN"
        "ZPA_CUSTOMER_ID"
        "ZSCALER_CLOUD"
    )
    
    for var in "${required[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing+=("$var")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        for var in "${missing[@]}"; do
            echo "  - $var"
        done
        echo ""
        log_info "Please set the required environment variables:"
        echo "export ZSCALER_CLIENT_ID=\"your_client_id\""
        echo "export ZSCALER_CLIENT_SECRET=\"your_client_secret\""
        echo "export ZSCALER_VANITY_DOMAIN=\"your_domain\""
        echo "export ZPA_CUSTOMER_ID=\"your_customer_id\""
        echo "export ZSCALER_CLOUD=\"production\""
        exit 1
    fi
    
    log_success "All required environment variables are set"
}

# Build the binary
build_binary() {
    log_info "Building zscaler-terraformer binary..."
    cd "$PROJECT_ROOT"
    
    if ! go build -o zscaler-terraformer .; then
        log_error "Failed to build binary"
        exit 1
    fi
    
    log_success "Binary built successfully"
}

# Run integration tests
run_tests() {
    log_info "Running integration tests..."
    cd "$PROJECT_ROOT"
    
    # Set test timeout
    export TEST_TIMEOUT="${TIMEOUT_MINUTES}m"
    
    # Run the integration tests
    if go test -v ./tests/integration/... -timeout "$TEST_TIMEOUT"; then
        log_success "All integration tests passed!"
        return 0
    else
        log_error "Some integration tests failed"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    cd "$PROJECT_ROOT"
    
    # Remove binary if it was created
    if [[ -f "zscaler-terraformer" ]]; then
        rm -f zscaler-terraformer
        log_info "Removed temporary binary"
    fi
    
    # Clean up test artifacts
    find . -name "integration_test_results" -type d -exec rm -rf {} + 2>/dev/null || true
    find . -name "debug_*.log" -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    log_info "Starting Zscaler Terraformer Integration Tests"
    echo "=========================================="
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Check environment
    check_env_vars
    
    # Build binary
    build_binary
    
    # Run tests
    if run_tests; then
        echo ""
        log_success "🎉 Integration tests completed successfully!"
        log_info "Key features validated:"
        echo "  ✅ Progress bar as default"
        echo "  ✅ --no-progress flag"
        echo "  ✅ --prefix flag"
        echo "  ✅ --collect-logs flag"
        echo "  ✅ --validate flag"
        echo "  ✅ Data source reference replacement"
        echo "  ✅ ZPA policy operand mapping"
        echo "  ✅ Error handling"
        echo "  ✅ Support flag"
        exit 0
    else
        echo ""
        log_error "❌ Some integration tests failed"
        log_info "Check the test output above for details"
        exit 1
    fi
}

# Run main function
main "$@"
