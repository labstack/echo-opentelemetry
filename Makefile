PKG := "github.com/labstack/echo-opentelemetry"
PKG_LIST := $(shell go list ${PKG}/...)

.DEFAULT_GOAL := check
check: lint vet security race ## Check project


init:
	@go install golang.org/x/lint/golint@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest

lint: ## Lint the files
	@staticcheck ${PKG_LIST}
	@golint -set_exit_status ${PKG_LIST}

vet: ## Vet the files
	@go vet ${PKG_LIST}

security: ## Run Gosec static code security analyzer
	@gosec -quiet -exclude-dir=.cache ./...

test: ## Run tests
	@go test -short ${PKG_LIST}

race: ## Run tests with data race detector
	@go test -race ${PKG_LIST}

benchmark: ## Run benchmarks
	@go test -run="-" -bench=".*" ${PKG_LIST}

format: ## Format the source code
	@find ./ -type f -name "*.go" -exec gofmt -w {} \;

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

goversion ?= "1.26"
test_version: ## Run tests inside Docker with given version (defaults to 1.26 oldest supported). Example: make test_version goversion=1.26
	@docker run --rm -it -v $(shell pwd):/project golang:$(goversion) /bin/sh -c "cd /project && make race"
