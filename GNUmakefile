.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Terraform Provider CrowdStrike - Available targets:"
	@echo ""
	@echo "Building:"
	@echo "  build          - Build and install the provider to GOBIN"
	@echo "  localinstall   - Build and install the provider to ~/go/bin"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt            - Fix code formatting and linting issues automatically"
	@echo "  fmt-check      - Check Go formatting without making changes"
	@echo "  lint           - Run golangci-lint on the codebase"
	@echo "  gen            - Generate provider documentation (REQUIRED before commit)"
	@echo ""
	@echo "Testing:"
	@echo "  test           - Run unit tests only (no TF_ACC)"
	@echo "  acctest        - Run acceptance tests with format check (PKG=<package> optional)"
	@echo "  testacc        - Run acceptance tests without format check"
	@echo ""
	@echo "Development:"
	@echo "  apply <resource>   - Build provider and run terraform apply on example resource"
	@echo "  destroy <resource> - Build provider and run terraform destroy on example resource"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make acctest"
	@echo "  make acctest PKG=prevention_policy"
	@echo "  make acctest PKG=prevention_policy TESTARGS='-run TestAccPreventionPolicyWindowsResource'"
	@echo "  make apply crowdstrike_host_group"
	@echo "  make destroy crowdstrike_host_group"
	@echo ""
	@echo "Environment Variables:"
	@echo "  PKG      - Package name for targeted acceptance tests"
	@echo "  TESTARGS - Additional arguments for go test (e.g., -run TestName)"
	@echo "  TFARGS   - Additional arguments for terraform apply/destroy"

.PHONY: build
build:
	go install .

.PHONY: localinstall
localinstall:
	go build -o terraform-provider-crowdstrike .
	mv terraform-provider-crowdstrike ~/go/bin

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt-check
fmt-check:
	@echo "Checking Go formatting..."
	golangci-lint fmt -E gofumpt --diff

.PHONY: fmt
fmt:
	@echo "Fixing code (formatters + linters)..."
	golangci-lint run --fix ./...

.PHONY: gen
gen:
	@echo "Generating provider documentation..."
	go generate ./...

.PHONY: test
test:
	@branch=$$(git rev-parse --abbrev-ref HEAD); \
	printf "Running unit tests on branch: %s\n" "$$branch"
	unset TF_ACC && go test ./internal/... -v $(TESTARGS) -timeout 15m

.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: acctest
acctest: fmt-check
	@branch=$$(git rev-parse --abbrev-ref HEAD); \
	printf "Running acceptance tests on branch: %s\n" "$$branch"
	TF_ACC=1 go test ./internal/$${PKG:-...} -v $(TESTARGS) -timeout 120m -parallel 10

.PHONY: apply
apply: build
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
destroy: build
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
