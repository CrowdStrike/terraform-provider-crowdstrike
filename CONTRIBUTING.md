# Contributing to the CrowdStrike Terraform Provider

This guide covers both the practical aspects of setting up and contributing to the CrowdStrike Terraform Provider as well as the architectural decisions and design patterns that guide its development.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setting Up the Environment](#setting-up-the-environment)
- [Building the Provider](#building-the-provider)
- [Development Workflow](#development-workflow)
  - [Creating a New Resource](#creating-a-new-resource)
  - [File Structure](#file-structure)
- [Architecture and Design Patterns](#architecture-and-design-patterns)
  - [API Interaction](#api-interaction)
  - [Resource Schema Patterns](#resource-schema-patterns)
  - [Validation](#validation)
  - [Error Handling](#error-handling)
  - [Resource Registration](#resource-registration)
- [Testing](#testing)
- [Debugging](#debugging)
- [Example Patterns](#example-patterns)

## Prerequisites

- [Go 1.21+](https://go.dev/doc/install) installed and configured.
- [Terraform v1.8+](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) installed locally.

## Setting Up the Environment

Create a `.terraformrc` file in your home directory:

```bash
touch ~/.terraformrc
```

Edit the `.terraformrc` file to look like this:

```hcl
provider_installation {
  dev_overrides {
      "registry.terraform.io/crowdstrike/crowdstrike" = "/path/to/go/bin"
  }

  direct {}
}
```

The value of `/path/to/go/bin` will be your `GOBIN` path. You can run `go env GOBIN` to find the path Go installs your binaries.

If `go env GOBIN` is not set, then use the default path of `/Users/<Username>/go/bin`.

Terraform will now use the locally built provider when you run terraform configurations that reference the CrowdStrike provider.

## Building the Provider

Clone the repository:

```bash
git clone https://github.com/CrowdStrike/terraform-provider-crowdstrike.git
cd terraform-provider-crowdstrike
```

Build the CrowdStrike provider:

```bash
make build
```

Run `make build` anytime new changes are added to the provider or you pull new code from the repository to update your local installation.

## Development Workflow

### Creating a New Resource

Follow these steps to add a new Terraform resource to the provider:

1. **Scaffold the Resource**
   - Use the resource generator to scaffold files:
     ```sh
     go run tools/resource/gen.go <ResourceName>
     # Example: go run tools/resource/gen.go host_group
     ```
   - This creates a Go file in `internal/<resource>/`, an example in `examples/resources/`, and an import script.

2. **Implement Resource Logic**
   - Fill in the CRUD (Create, Read, Update, Delete) methods in the generated Go file.
   - Design the schema according to the [Resource Schema Patterns](#resource-schema-patterns) section below.
   - Implement `ValidateConfig` for resource-specific validation logic.
   - Register your new resource in `internal/provider/provider.go`.

3. **Add Acceptance Tests**
   - Create a test file in the appropriate internal package (e.g., `internal/<resource>/<resource>_resource_test.go`).
   - Ensure tests cover the full resource lifecycle: create, update, destroy, and attribute checks.

4. **Add Example and Import Script**
   - Add a usage example in `examples/resources/<resource>/resource.tf`.
   - Provide an import script in `examples/resources/<resource>/import.sh`.

5. **Generate Documentation**
   - Run `go generate ./...` to update generated docs.

6. **Build and Test**
   - Run `make build` to build the provider.
   - Run `golangci-lint run ./...` to check for lint errors.
   - Run tests to verify your changes work as expected.

### File Structure

- **Resource Implementation:** `internal/<resource>/<resource>_resource.go`
- **Acceptance Tests:** `internal/<resource>/<resource>_resource_test.go`
- **Examples:** `examples/resources/<resource>/`
- **Docs:** Auto-generated in `docs/resources/` from schema and examples.

## Architecture and Design Patterns

This section explains the architectural decisions, idioms, and patterns that guide development of the CrowdStrike Terraform provider.

### API Interaction

- **Single Source of Truth:** All API interactions must go through the `gofalcon` library. This ensures consistency and leverages upstream model validation.
- **No Direct HTTP:** Never use direct HTTP calls or undocumented endpoints, even for edge cases—extend `gofalcon` if necessary.

### Resource Schema Patterns

- **User Experience First:** Resource schemas are designed for clarity and usability, not just to mirror the API. Group related fields and use Terraform idioms (e.g., sets for collections).
- **Request vs. Response Models:** Only fields present in the API's request models (`Create...ReqV1`, `Update...ReqV1`) are user-settable. Fields only in response models are marked as `Computed`.
- **Plan Modifiers:** Use `RequiresReplace` for immutable fields, `UseStateForUnknown` for IDs, etc., to ensure correct lifecycle behavior.

### Validation

- **Early Feedback:** All resource-specific validation is implemented in `ValidateConfig`, not in CRUD methods, to provide early feedback during `terraform plan`.
- **Conditional Logic:** Use `ValidateConfig` for mutually exclusive fields, conditionally required attributes, and complex validation that cannot be expressed with simple validators.

### Error Handling

- **Actionable Errors:** Error messages should be actionable and user-focused, especially for common issues like insufficient API scopes.

### Resource Registration

- **Explicit Registration:** All resources must be registered in the `Resources` function in `internal/provider/provider.go`. This is the only place resources are made available to Terraform.

## Testing

- Follow the patterns in the [Terraform Testing documentation](https://developer.hashicorp.com/terraform/plugin/testing/testing-patterns).
- Ensure tests cover the full resource lifecycle and verify all attributes work as expected.

## Debugging

If you need to debug complex issues or see the raw API calls:

```bash
TF_LOG=DEBUG TF_ACC=1 go test ./... -v -timeout 120m
```

This prints detailed logs, including raw API calls from gofalcon, which is helpful for troubleshooting.

