.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make acctest"
	@echo "  make acctest PKG=prevention_policy"
	@echo "  make acctest PKG=prevention_policy TESTARGS='-run TestAccPreventionPolicyWindowsResource'"
	@echo "  make apply crowdstrike_host_group"
	@echo "  make destroy crowdstrike_host_group"

##@ Building

.PHONY: build
build: ## Build and install the provider
	go install .

.PHONY: localinstall
localinstall: ## Build and install the provider to ~/go/bin
	go build -o terraform-provider-crowdstrike .
	mv terraform-provider-crowdstrike ~/go/bin

##@ Code Quality

.PHONY: lint
lint: ## Run golangci-lint on the codebase
	golangci-lint run ./...

.PHONY: fmt-check
fmt-check: ## Check Go formatting without making changes
	@echo "Checking Go formatting..."
	golangci-lint fmt -E gofumpt --diff

.PHONY: fmt
fmt: ## Fix code formatting and linting issues automatically
	@echo "Fixing code (formatters + linters)..."
	golangci-lint run --fix ./...

.PHONY: gen
gen: ## Generate provider documentation
	@echo "Generating provider documentation..."
	go generate ./...

##@ Testing

.PHONY: test
test: ## Run unit tests (TESTARGS: additional go test flags)
	@branch=$$(git rev-parse --abbrev-ref HEAD); \
	printf "Running unit tests on branch: %s\n" "$$branch"
	unset TF_ACC && go test ./internal/... -v $(TESTARGS) -timeout 15m

.PHONY: testacc
testacc: fmt ## Run all acceptance tests (TESTARGS: additional go test flags)
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: acctest
acctest: fmt ## Run acceptance tests (PKG: package name, TESTARGS: additional go test flags)
	@branch=$$(git rev-parse --abbrev-ref HEAD); \
	printf "Running acceptance tests on branch: %s\n" "$$branch"
	TF_ACC=1 go test ./internal/$${PKG:-...} -v $(TESTARGS) -timeout 120m -parallel 10

SWEEP_TIMEOUT ?= 60m

.PHONY: sweep
sweep: ## Run sweepers to clean up test resources
	@echo "WARNING: This will destroy infrastructure. Use only in development accounts."
	TF_ACC=1 go test ./internal/sweep -v -sweep=default -timeout $(SWEEP_TIMEOUT)

.PHONY: sweeper
sweeper: ## Run sweepers with failures allowed
	@echo "WARNING: This will destroy infrastructure. Use only in development accounts."
	TF_ACC=1 go test ./internal/sweep -v -sweep=default -sweep-allow-failures -timeout $(SWEEP_TIMEOUT)

##@ Development

.PHONY: apply
apply: build ## Apply terraform example (TFARGS: additional terraform flags)
	@$(eval RESOURCE := $(filter-out $@,$(MAKECMDGOALS)))
	@if [ -z "$(RESOURCE)" ]; then \
		echo "Error: RESOURCE is required. Usage: make apply crowdstrike_host_group"; \
		exit 1; \
	fi
	@if [ ! -d "examples/resources/$(RESOURCE)" ]; then \
		echo "Error: examples/resources/$(RESOURCE) does not exist"; \
		exit 1; \
	fi
	@echo "Running terraform in examples/resources/$(RESOURCE)..."
	@cd examples/resources/$(RESOURCE) && terraform init && terraform apply $${TFARGS:--auto-approve}

.PHONY: destroy
destroy: build ## Destroy terraform example (TFARGS: additional terraform flags)
	@$(eval RESOURCE := $(filter-out $@,$(MAKECMDGOALS)))
	@if [ -z "$(RESOURCE)" ]; then \
		echo "Error: RESOURCE is required. Usage: make destroy crowdstrike_host_group"; \
		exit 1; \
	fi
	@if [ ! -d "examples/resources/$(RESOURCE)" ]; then \
		echo "Error: examples/resources/$(RESOURCE) does not exist"; \
		exit 1; \
	fi
	@echo "Running terraform destroy in examples/resources/$(RESOURCE)..."
	@cd examples/resources/$(RESOURCE) && terraform destroy $${TFARGS:--auto-approve}

%:
	@:
