COLOR_OK=\\x1b[0;32m
COLOR_NONE=\x1b[0m
COLOR_ERROR=\x1b[31;01m
COLOR_DESTROY=\033[31m # Red
COLOR_WARNING=\x1b[33;05m
COLOR_ZSCALER=\x1B[34;01m
GOFMT := gofumpt
GOIMPORTS := goimports

help:
	@echo "$(COLOR_ZSCALER)"
	@echo "  ______              _           "
	@echo " |___  /             | |          "
	@echo "    / / ___  ___ __ _| | ___ _ __ "
	@echo "   / / / __|/ __/ _\` | |/ _ \ '__|"
	@echo "  / /__\__ \ (_| (_| | |  __/ |   "
	@echo " /_____|___/\___\__,_|_|\___|_|   "
	@echo "                                  "
	@echo "                                  "
	@echo "$(COLOR_OK)Zscaler-Terraformer CLI$(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_WARNING)Usage:$(COLOR_NONE)"
	@echo "$(COLOR_OK)  make [command]$(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_WARNING)Available commands:$(COLOR_NONE)"
	@echo "$(COLOR_WARNING)Build$(COLOR_NONE)"
	@echo "$(COLOR_OK)  build                 	Builds the Binary For The Current Platform and Architecture$(COLOR_NONE)"
	@echo "$(COLOR_OK)  build_all               	Builds the Binary For Multiple Platforms $(COLOR_NONE)"
	@echo "$(COLOR_WARNING)Install$(COLOR_NONE)"
	@echo "$(COLOR_OK)  build                 	Builds and Installs The Binary For The Current Platform and Architecture$(COLOR_NONE)"
	@echo "$(COLOR_WARNING)test$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test               	Run all unit tests$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test-unit          	Run unit tests with verbose output$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test-coverage      	Run unit tests with coverage report$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test-fresh         	Run unit tests without cache$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test-clean         	Clean test cache and artifacts$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test_zia           	Run only zia integration tests$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test_zpa           	Run only zpa integration tests$(COLOR_NONE)"


TEST ?= $(shell go list ./...)
GOFMT_FILES ?= $(shell find . -name '*.go')
VERSION ?= $(shell git describe --tags --abbrev=0)-pre-release+$(shell git rev-parse --short=12 HEAD)
ROOT_DIR = $(PWD)
ZSCALER_TERRAFORM_INSTALL_PATH=$(PWD)
HASHICORP_CHECKPOINT_TIMEMOUT ?= 30000
TFPROVIDERLINT = tfproviderlint
STATICCHECK = staticcheck
BINARY_NAME = zscaler-terraformer

# Fully qualified variable for use with ldflags
LD_FLAGS=-ldflags="-X github.com/zscaler/zscaler-terraformer/cmd.versionString=$(VERSION)"

build:
	@go build \
		-gcflags=all=-trimpath=$(GOPATH) \
		-asmflags=all=-trimpath=$(GOPATH) \
		$(LD_FLAGS) \
		-o $(BINARY_NAME) main.go

install: GOOS=$(shell go env GOOS)
install: GOARCH=$(shell go env GOARCH)
ifeq ($(OS),Windows_NT)
install: DESTINATION=C:\Windows\System32
else
install: DESTINATION=/usr/local/bin
endif
install:
	@echo "==> Installing $(BINARY_NAME) CLI in: $(DESTINATION)/$(BINARY_NAME)"
	@mkdir -p $(DESTINATION)
	@rm -f $(DESTINATION)/$(BINARY_NAME)
	@go build \
		-gcflags=all=-trimpath=$(GOPATH) \
		-asmflags=all=-trimpath=$(GOPATH) \
		$(LD_FLAGS) \
		-o $(DESTINATION)/$(BINARY_NAME) main.go

build_all:
	@echo "==> Building $(BINARY_NAME) for Windows, macOS, and Linux..."
	GOOS=windows GOARCH=amd64 go build -o build/$(BINARY_NAME).exe main.go
	GOOS=darwin GOARCH=amd64 go build -o build/$(BINARY_NAME)_darwin_amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -o build/$(BINARY_NAME)_darwin_arm64 main.go
	GOOS=linux GOARCH=amd64 go build -o build/$(BINARY_NAME)_linux_amd64 main.go
	GOOS=linux GOARCH=arm64 go build -o build/$(BINARY_NAME)_linux_arm64 main.go

test_zpa:
	@CI=true \
		USE_STATIC_RESOURCE_IDS=true \
		CHECKPOINT_TIMEOUT=$(HASHICORP_CHECKPOINT_TIMEMOUT) \
		ZPA_CLIENT_ID="$(ZPA_CLIENT_ID)" \
		ZPA_CLIENT_SECRET="$(ZPA_CLIENT_SECRET)" \
		ZPA_CUSTOMER_ID="$(ZPA_CUSTOMER_ID)" \
		ZPA_CLOUD="$(ZPA_CLOUD)" \
		go test $(TEST) -timeout 120m -v $(TESTARGS)

# All Tests
test:
	@echo "$(COLOR_ZSCALER)🧪 Running All Tests...$(COLOR_NONE)"
	@go test ./tests/... -timeout 30s
	@echo "$(COLOR_OK)✅ All tests completed$(COLOR_NONE)"

test-unit:
	@echo "$(COLOR_ZSCALER)🧪 Running Unit Tests (Verbose)...$(COLOR_NONE)"
	@go test -v ./tests/unit/... -timeout 30s
	@echo "$(COLOR_OK)✅ Unit tests completed$(COLOR_NONE)"

test-coverage:
	@echo "$(COLOR_ZSCALER)📊 Running All Tests with Coverage...$(COLOR_NONE)"
	@go test -cover -coverprofile=coverage.out ./tests/... -timeout 30s
	@go tool cover -func=coverage.out
	@echo "$(COLOR_OK)✅ Coverage report completed$(COLOR_NONE)"
	@echo "$(COLOR_WARNING)📄 Coverage details saved to coverage.out$(COLOR_NONE)"

test-coverage-html:
	@echo "$(COLOR_ZSCALER)📊 Generating HTML Coverage Report...$(COLOR_NONE)"
	@go test -cover -coverprofile=coverage.out ./tests/... -timeout 30s
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_OK)✅ HTML coverage report generated: coverage.html$(COLOR_NONE)"

test-fresh:
	@echo "$(COLOR_ZSCALER)🧪 Running Fresh Tests (no cache)...$(COLOR_NONE)"
	@go clean -testcache
	@go test ./tests/... -timeout 30s
	@echo "$(COLOR_OK)✅ Fresh tests completed$(COLOR_NONE)"

test-clean:
	@echo "$(COLOR_ZSCALER)🧹 Cleaning test artifacts...$(COLOR_NONE)"
	@rm -f coverage.out coverage.html
	@rm -f tests/fixtures/temp_*
	@go clean -testcache
	@echo "$(COLOR_OK)✅ Test artifacts and cache cleaned$(COLOR_NONE)"


# Integration Tests
test_zia:
	@CI=true \
		USE_STATIC_RESOURCE_IDS=true \
		CHECKPOINT_TIMEOUT=$(HASHICORP_CHECKPOINT_TIMEMOUT) \
		ZIA_USERNAME="$(ZIA_USERNAME)" \
		ZIA_PASSWORD="$(ZIA_PASSWORD)" \
		ZIA_API_KEY="$(ZIA_API_KEY)" \
		ZIA_CLOUD="$(ZIA_CLOUD)" \
		go test $(TEST) -timeout 120m -v $(TESTARGS)

vet:
	@echo "==> Checking source code against go vet and staticcheck"
	@go vet ./...
	@staticcheck ./...

imports:
	goimports -w $(GOFMT_FILES)

fmt:
	gofmt -w $(GOFMT_FILES)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

errcheck:
	@sh -c "'$(CURDIR)/scripts/errcheck.sh'"

lint: vendor
	@echo "✓ Linting source code with https://staticcheck.io/ ..."
	@go run honnef.co/go/tools/cmd/staticcheck@v0.4.6 ./...

tools:
	@which $(GOFMT) || go install mvdan.cc/gofumpt@v0.5.0
	@which $(TFPROVIDERLINT) || go install github.com/bflad/tfproviderlint/cmd/tfproviderlint@v0.29.0
	@which $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@v0.4.6

tools-update:
	@go install mvdan.cc/gofumpt@v0.5.0
	@go install github.com/bflad/tfproviderlint/cmd/tfproviderlint@v0.29.0
	@go install honnef.co/go/tools/cmd/staticcheck@v0.4.6

validate-tf:
	@bash scripts/validate-tf.sh

print-version:
	@echo "VERSION = $(VERSION)"
	@echo "LD_FLAGS = $(LD_FLAGS)"

.PHONY: build install build_all test test-unit test-coverage test-coverage-html test-fresh test-all test-clean test_zpa test_zia vet imports fmt fmtcheck errcheck lint tools tools-update validate-tf
