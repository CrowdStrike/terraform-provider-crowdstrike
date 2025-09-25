default: testacc

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

localinstall:
	go build -o terraform-provider-crowdstrike .
	mv terraform-provider-crowdstrike ~/go/bin

build:
	go install .

# Lint with golangci-lint (same as CI)
.PHONY: lint
lint:
	golangci-lint run ./...
