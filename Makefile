TEST                  ?= $$(go list ./...)
GOFMT_FILES              ?= $$(find . -name '*.go')
VERSION               ?= $$(git describe --tags --abbrev=0)-pre-release+$$(git rev-parse --short=12 HEAD)
ROOT_DIR               = $$PWD
ZSCALER_TERRAFORM_INSTALL_PATH=$$PWD
HASHICORP_CHECKPOINT_TIMEMOUT ?= 30000
TFPROVIDERLINT=tfproviderlint
STATICCHECK=staticcheck

build:
	@go build \
		-gcflags=all=-trimpath=$(GOPATH) \
		-asmflags=all=-trimpath=$(GOPATH) \
		-ldflags="-X github.com/zscaler/zscaler-terraformer/internal/app/zscaler-terraformer/cmd.versionString=$(VERSION)" \
		-o zscaler-terraformer cmd/zscaler-terraformer/main.go

test_zpa:
	@CI=true \
		USE_STATIC_RESOURCE_IDS=true \
		CHECKPOINT_TIMEOUT=$(HASHICORP_CHECKPOINT_TIMEMOUT) \
		ZPA_CLIENT_ID="$(ZPA_CLIENT_ID)" \
		ZPA_CLIENT_SECRET="$(ZPA_CLIENT_SECRET)" \
		ZPA_CUSTOMER_ID="$(ZPA_CUSTOMER_ID)" \
		ZPA_CLOUD="$(ZPA_CLOUD)" \
		go test $(TEST) -timeout 120m -v $(TESTARGS)

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


install: GOOS=$(shell go env GOOS)
install: GOARCH=$(shell go env GOARCH)
ifeq ($(OS),Windows_NT)  # is Windows_NT on XP, 2000, 7, Vista, 10...
install: DESTINATION=C:\Windows\System32
else
install: DESTINATION=/usr/local/bin
endif
install:
	@echo "==> Installing zscaler-terraformer cli in: $(DESTINATION)/zscaler-terraformer"
	@mkdir -p $(DESTINATION)
	@rm -f $(DESTINATION)/zscaler-terraformer
	@go build \
	-gcflags=all=-trimpath=$(GOPATH) \
	-asmflags=all=-trimpath=$(GOPATH) \
	-ldflags="-X github.com/zscaler/zscaler-terraformer/internal/app/zscaler-terraformer/cmd.versionString=$(VERSION)" \
	-o $(DESTINATION)/zscaler-terraformer ./cmd/zscaler-terraformer/main.go

.PHONY: build test fmt validate-tf vendor-status vet fmt fmtcheck errcheck tools vendor-status
