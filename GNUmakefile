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
	go test ./internal/... -v $(TESTARGS) -timeout 15m

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
