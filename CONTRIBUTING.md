# Contributing to the CrowdStrike Terraform Provider

This guide covers both the practical aspects of setting up and contributing to the CrowdStrike Terraform Provider as well as the architectural decisions and design patterns that guide its development.

## Table of Contents

- [Contributing to the CrowdStrike Terraform Provider](#contributing-to-the-crowdstrike-terraform-provider)
  - [Table of Contents](#table-of-contents)
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
    - [Logging with tflog](#logging-with-tflog)
  - [Testing](#testing)
  - [Debugging](#debugging)
  - [Code Patterns](#code-patterns)
    - [Model Wrapping with .wrap Method](#model-wrapping-with-wrap-method)
    - [Schema Description Formatting](#schema-description-formatting)
    - [Single-line Diagnostics with Ellipsis](#single-line-diagnostics-with-ellipsis)
    - [Early State Updates](#early-state-updates)

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

### Logging with tflog

The Terraform Plugin Framework provides a structured logging system called `tflog` that should be used for logging information during provider execution:

- **Log Levels:**
  - `tflog.Trace()`: Most detailed, for very granular debugging information
  - `tflog.Debug()`: For information useful during development and debugging
  - `tflog.Info()`: For general operational information
  - `tflog.Warn()`: For potentially problematic situations that don't prevent execution
  - `tflog.Error()`: For errors that don't necessarily halt execution

- **Structured Logging:** Prefer structured fields over string interpolation:
  ```go
  // Good
  tflog.Debug(ctx, "Processing resource", map[string]interface{}{
      "id": id,
      "name": name,
  })
  
  // Avoid
  tflog.Debug(ctx, fmt.Sprintf("Processing resource with id %s and name %s", id, name))
  ```

- **Context Fields:** Use context to attach fields that will appear in all subsequent logs:
  ```go
  ctx = tflog.SetField(ctx, "resource_id", id)
  // All logs using this ctx will include the resource_id field
  ```

- **Sensitive Data:** Never log credentials or sensitive information:
  ```go
  // Use MaskLogString for sensitive values that appear in logs
  tflog.Debug(ctx, "Using configuration", map[string]interface{}{
      "endpoint": endpoint,
      "token": tflog.MaskLogString(token),
  })
  ```

- **Viewing Logs:** Users can see these logs by setting the `TF_LOG` environment variable:
  ```bash
  # For all logs
  TF_LOG=TRACE terraform apply
  
  # Provider-specific logs
  TF_LOG_PROVIDER=TRACE terraform apply
  ```

## Testing

- Follow the patterns in the [Terraform Testing documentation](https://developer.hashicorp.com/terraform/plugin/testing/testing-patterns).
- Ensure tests cover the full resource lifecycle and verify all attributes work as expected.

## Debugging

If you need to debug complex issues or see the raw API calls:

```bash
TF_LOG=DEBUG TF_ACC=1 go test ./... -v -timeout 120m
```

This prints detailed logs, including raw API calls from gofalcon, which is helpful for troubleshooting.

## Code Patterns

This section provides concrete examples of the code patterns that should be followed when contributing to the CrowdStrike Terraform Provider.

### Model Wrapping with .wrap Method

Implement a `.wrap()` method on your resource models to convert API responses to Terraform model data. This pattern ensures consistent handling of API data and separation of concerns:

```go
// wrap transforms API response values to their terraform model values.
func (d *preventionPolicyAttachmentResourceModel) wrap(
    ctx context.Context,
    policy models.PreventionPolicyV1,
) diag.Diagnostics {
    var diags diag.Diagnostics
    
    d.ID = types.StringValue(*policy.ID)
    
    // Convert API types to Terraform types
    hostGroupSet, diag := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
    diags.Append(diag...)
    if diags.HasError() {
        return diags
    }
    if !d.HostGroups.IsNull() || len(hostGroupSet.Elements()) != 0 {
        d.HostGroups = hostGroupSet
    }
    
    // More field conversions...
    
    return diags
}

// Usage in resource methods
func (r *Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
    var state resourceModel
    resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }
    
    // Get data from API
    policy, diags := getPolicy(ctx, r.client, state.ID.ValueString())
    resp.Diagnostics.Append(diags...)
    if resp.Diagnostics.HasError() {
        return
    }
    
    // Update state with API response
    resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
    resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
```

### Schema Description Formatting

Schema descriptions must follow a specific format to be correctly processed by the documentation generator. The preferred approach is to use the `utils.MarkdownDescription` helper function which handles proper formatting and inclusion of required API scopes:

```go
var (
	documentationSection        string         = "Prevention Policy"
	resourceMarkdownDescription string         = "This resource allows managing the host groups attached to a prevention policy."
	requiredScopes              []scopes.Scope = []scopes.Scope{
		{
			Name:  "Prevention policies",
			Read:  true,
			Write: true,
		},
	}
)

// Then in your Schema method
resp.Schema = schema.Schema{
    MarkdownDescription: utils.MarkdownDescription(
        documentationSection,
        resourceMarkdownDescription,
        requiredScopes,
    ),
    // Schema attributes...
}
```

This helper function automatically:
1. Uses the documentation section as the service grouping before the `---` separator
2. Places your resource description after the separator
3. Adds a formatted list of required API scopes for the resource


### Single-line Diagnostics with Ellipsis

The preferred pattern in this codebase is to append diagnostics from state operations in a single line using the ellipsis operator (`...`):

```go
// Preferred pattern - Get state in a single line
var state HostGroupResourceModel
resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

// Preferred pattern - Set state directly
resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)

// Not Preferred - Avoid separating the operation from diagnostics collection
diags := resp.State.Set(ctx, &model)
resp.Diagnostics.Append(diags...)
```

### Early State Updates

When creating resources, set any information required for deletion as early as possible in the Create method. This ensures that even if subsequent operations fail, Terraform can still track and clean up the resource:

```go
// Create the resource via API
createResponse, err := r.client.CreateResource(&params)
if err != nil {
    resp.Diagnostics.AddError("Failed to create resource", err.Error())
    return
}

// IMPORTANT: Set the ID early, immediately after creation succeeds
plan.ID = types.StringValue(*createResponse.Payload.Resources[0].ID)

// Store this ID in state ASAP so Terraform can track the resource
resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
if resp.Diagnostics.HasError() {
    return
}

// Now continue with additional operations that might fail
// If these fail, Terraform will still have the ID to attempt cleanup
```

This pattern is essential for complex resources where multiple API calls are needed to fully configure them. By setting the ID in state as soon as possible, you ensure that even if subsequent operations fail and the apply errors out, Terraform can still attempt to delete the partially created resources during a destroy operation.
