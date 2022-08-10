TEST                  ?= $$(go list ./...)
GO_FILES              ?= $$(find . -name '*.go')
ZPA_CLIENT_ID	      ?= aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ZPA_CLIENT_SECRET     ?= 00deadb33f000000000000000000000000000
ZPA_CUSTOMER_ID		  ?= 00deadb33f000000000000000000000000000

VERSION               ?= $$(git describe --tags --abbrev=0)-dev+$$(git rev-parse --short=12 HEAD)
ROOT_DIR               = $$PWD

HASHICORP_CHECKPOINT_TIMEMOUT ?= 30000

build:
	@go build \
		-gcflags=all=-trimpath=$(GOPATH) \
		-asmflags=all=-trimpath=$(GOPATH) \
		-ldflags="-X github.com/zscaler/zscaler-terraforming/internal/app/zscaler-terraforming/cmd.versionString=$(VERSION)" \
		-o zscaler-terraforming cmd/zscaler-terraforming/main.go

test:
	@CI=true \
		USE_STATIC_RESOURCE_IDS=true \
		CHECKPOINT_TIMEOUT=$(HASHICORP_CHECKPOINT_TIMEMOUT) \
		ZPA_CLIENT_ID="$(ZPA_CLIENT_ID)" \
		ZPA_CLIENT_SECRET="$(ZPA_CLIENT_SECRET)" \
		ZPA_CUSTOMER_ID="$(ZPA_CUSTOMER_ID)" \
		go test $(TEST) -timeout 120m -v $(TESTARGS)

fmt:
	gofmt -w $(GO_FILES)

validate-tf:
	@bash scripts/validate-tf.sh

.PHONY: build test fmt validate-tf
