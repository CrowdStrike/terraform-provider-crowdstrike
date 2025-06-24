# Prerequisites

- [Go 1.21+](https://go.dev/doc/install) installed and configured.
- [Terraform v1.8+](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) installed locally.

# Setting up the environment

Create a `.terraformrc` file in your home directory.

`touch ~/.terraformrc`

Then edit the `.terraformrc` file to look like this

```
provider_installation {
  dev_overrides {
      "registry.terraform.io/crowdstrike/crowdstrike" = "/path/to/go/bin"
  }

  direct {}
}
```

The value of `/path/to/go/bin` will be your `GOBIN` path. You can run `go env GOBIN` to find the path Go installs your binaries.

If `go env GOBIN` is not set then use the default path of `/Users/<Username>/go/bin`

Terraform will now use the locally built provider when you run terraform configurations that reference the CrowdStrike provider. Use the steps below in [Building the provider](#Building-the-provider) to learn how to create the local provider.

# Building the provider

Clone the repository

`git clone https://github.com/CrowdStrike/terraform-provider-crowdstrike.git`

Change into the cloned repository.

`cd terraform-provider-crowdstrike`

Build the CrowdStrike provider

`make build`

Run `make build` anytime new changes are added to the provider or you pull a new code from the repository to update your local install of the provider.

# Creating a New Resource

This section describes how to add a new Terraform resource to the CrowdStrike provider.

## 1. Scaffold the Resource
- Use the resource generator to scaffold files:
  ```sh
  go run tools/resource/gen.go <ResourceName>
  # Example: go run tools/resource/gen.go host_group
  ```
- This creates a Go file in `internal/<resource>/`, an example in `examples/resources/`, and an import script.

## 2. Implement Resource Logic
- Fill in the CRUD (Create, Read, Update, Delete) methods in the generated Go file. All communication with CrowdStrike services should go through the `gofalcon` library.
- Design the schema for clarity and usability—organize attributes in a way that makes sense for Terraform users, not just to match the API.
- Implement `ValidateConfig` for resource-specific validation logic.
- Register your new resource in the provider by adding it to the `Resources` function in `internal/provider/provider.go`.
- For guidance on writing a resource, see the [Terraform Plugin Framework documentation](https://developer.hashicorp.com/terraform/plugin/framework/resources).
> [!NOTE]
> Please consult the `DESIGN_DECISIONS.md` file for guidance on implementation choices and provider conventions.

## 3. Add Acceptance Tests
- Create a test file in the appropriate internal package (e.g., `internal/host_groups/host_group_resource_test.go`).
- Ensure the test covers the full resource lifecycle: create, update, destroy, and attribute checks.
- See the official [Terraform Testing documentation](https://developer.hashicorp.com/terraform/plugin/testing/testing-patterns) for best practices and common patterns for writing acceptance tests.

## 4. Add Example and Import Script
- Add a usage example in `examples/resources/<resource>/resource.tf`.
- Provide an import script in `examples/resources/<resource>/import.sh`.

## 5. Generate Documentation
- Run the following to update generated docs:
  ```sh
  go generate ./...
  ```
- Commit the generated documentation along with your code changes.

## 6. Build and Test
- Build the provider:
  ```sh
  make build
  ```
- Run `golangci-lint run ./...` to check for lint errors and fix any issues it reports.
- If you need to debug complex issues or see the raw API calls made by the provider (including all requests and responses from the gofalcon client), set the `TF_LOG` environment variable to `DEBUG`:
  ```sh
  TF_LOG=DEBUG TF_ACC=1 go test ./... -v -timeout 120m
  ```
  This will print detailed logs, including the raw API calls from gofalcon, which is helpful for troubleshooting.
- Ensure all linter and build errors are fixed before submitting a pull request.