default: testacc

# Run acceptance tests
.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

localinstall:
	go build -o terraform-provider-crowdstrike .
	mv terraform-provider-crowdstrike ~/go/bin

generate: provider-spec
		tfplugingen-framework generate all --input ./provider_code_spec.json --output ./internal

provider-spec:
		tfplugingen-openapi generate --config ./generator_config.yml --output ./provider_code_spec.json ./openapi.json
	
build:
	go install .

