# Contributing to the CrowdStrike Terraform Provider

This guide covers both the practical aspects of setting up and contributing to the CrowdStrike Terraform Provider as well as the architectural decisions and design patterns that guide its development.

## Table of Contents

- [Contributing to the CrowdStrike Terraform Provider](#contributing-to-the-crowdstrike-terraform-provider)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Setting Up the Environment](#setting-up-the-environment)
  - [Building the Provider](#building-the-provider)
  - [Setting Up Pre-commit Hooks (Recommended)](#setting-up-pre-commit-hooks-recommended)
    - [Installation](#installation)
    - [Setup](#setup)
    - [Usage](#usage)
    - [What the Hooks Do](#what-the-hooks-do)
  - [Commit Message Standards (Optional)](#commit-message-standards-optional)
    - [Format](#format)
    - [Types](#types)
    - [Scopes](#scopes)
    - [Guidelines](#guidelines)
    - [Examples](#examples)
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
    - [State Consistency with flex and Validators](#state-consistency-with-flex-and-validators)
    - [Schema Description Formatting](#schema-description-formatting)
    - [Single-line Diagnostics with Ellipsis](#single-line-diagnostics-with-ellipsis)
    - [Early State Updates](#early-state-updates)

## Prerequisites

- [Go 1.21+](https://go.dev/doc/install) installed and configured.
- [Terraform v1.8+](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) installed locally.
- [pre-commit](https://pre-commit.com/#install) for code quality hooks (recommended).

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

## Setting Up Pre-commit Hooks (Recommended)

Pre-commit hooks help ensure code quality and consistency by running automated checks before each commit. They catch common issues early and auto-fix many formatting problems.

### Installation

First, install pre-commit if you haven't already:

```bash
# https://pre-commit.com/#install
pip install pre-commit
```

### Setup

After cloning the repository, install the pre-commit hooks:

```bash
pre-commit install
```

This installs the hooks defined in `.pre-commit-config.yaml` to run automatically on each `git commit`. If you do not want the hooks to run automatically, you can do `pre-commit run` to run them manually.

### Usage

**Automatic:** If you have installed the pre-commit hooks, they will run automatically on each commit. If any hook fails or makes changes, the commit will be aborted. Review the changes and commit again.

**Manual execution:**
```bash
# Run hooks on staged files only
pre-commit run

# Run hooks on all files
pre-commit run -a
```

### What the Hooks Do

- **Go linting & formatting:** `golangci-lint` runs comprehensive linting including formatting, static analysis, and style checks with auto-fix
- **Module cleanup:** `go mod tidy` keeps dependencies clean
- **Documentation:** `go generate` keeps docs up-to-date (only runs when files in examples/ or internal/ change)
- **Terraform formatting:** `terraform fmt` formats .tf files
- **General quality:** Hooks for general code quality.

**Performance:** Hooks are designed to be fast and efficient, only running on relevant file changes.

## Commit Message Standards (Optional)

Follow these commit message conventions for consistency. Since we use squash merges, maintainers will ensure final messages follow these standards.

### Format

```
<type>(<scope>): <description> (#PR)

[optional body]
[optional footer]
```

### Types

- `feat`: New features/resources
- `fix`: Bug fixes  
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

### Scopes

Scopes are optional. Use one when it's short and adds clarity, skip it when the description already makes the context obvious.

- `provider`: Core provider functionality
- `docs`: Documentation updates
- `tools`: Development tooling
- `ci`: CI/CD pipeline changes
- `deps`: Dependency updates

### Guidelines

- **Imperative mood**: Use "add" not "added", "fix" not "fixed"
- **Lowercase**: Start description with lowercase letter after the colon
- **Length**: Keep subject line under 72 characters
- **Issue reference**: Include issue number in footer when applicable
- **Be specific**: Clearly describe what changed, not how

### Examples

```bash
# Resource changes
feat(sensor_visibility_exclusion): add new resource
fix(default_sensor_update_policy): require replace on updates
feat(prevention_policy_attachment): add new resource

# System changes  
chore(deps): bump gofalcon to v0.13.4
fix(docs): default content update policy categorization
chore(ci): add pre-commit hooks configuration

# Multi-line example
feat(host_group): add advanced filtering support

Add support for complex filtering expressions in host group queries.
This enables more precise host targeting for policy assignments.

Closes #145
```

## Development Workflow

### Creating a New Resource

Follow these steps to add a new Terraform resource to the provider:

1. **Scaffold the Resource**
   - Use the generator to scaffold files:
     ```sh
     go run ./tools/generate resource <name>
     # Example: go run ./tools/generate resource host_group
     # Place in an existing package: go run ./tools/generate resource -d cloud_security kac_policy
     ```
   - This creates a Go file in `internal/<name>/` (or the `-d` directory), an example in `examples/resources/`, and an import script.

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

Use the `tferrors` package (`internal/tferrors`) for all API error handling. This package provides centralized, consistent error handling that automatically generates actionable messages, including scope hints for 403 errors.

**API Error Handling:**

When an API call returns an error, use `tferrors.NewDiagnosticFromAPIError()`. Pass the Terraform CRUD operation, the error, and the resource's required scopes:

```go
res, err := r.client.SomeService.SomeOperation(params)
if err != nil {
    resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
        tferrors.Create, // tferrors.Read, tferrors.Update, tferrors.Delete
        err,
        resourceRequiredScopes,
    ))
    return
}
```

**NotFound Error Handling (operation-specific):**

How you handle 404 errors depends on the CRUD operation:

- **Read**: Convert 404 to a warning and remove the resource from state (resource was deleted outside Terraform).
- **Delete**: Treat 404 as success (the resource is already gone).
- **Create/Update**: Treat 404 as an error (the default behavior).

```go
// Read method -- 404 means the resource was deleted outside Terraform
if err != nil {
    diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, resourceRequiredScopes)
    if diag.Summary() == tferrors.NotFoundErrorSummary {
        resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
        resp.State.RemoveResource(ctx)
        return
    }
    resp.Diagnostics.Append(diag)
    return
}

// Delete method -- 404 means already deleted, which is fine
if err != nil {
    diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, resourceRequiredScopes)
    if diag.Summary() == tferrors.NotFoundErrorSummary {
        return // Success -- already deleted
    }
    resp.Diagnostics.Append(diag)
    return
}
```

**Nil Checking for API Responses:**

Always check for nil pointers before accessing response data to prevent panics:

```go
if res == nil || res.Payload == nil {
    resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
    return
}
```

**Payload Error Handling:**

Some API responses include application-level errors in the payload even when the HTTP call succeeds. Check for these before checking for empty resources:

```go
if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
    resp.Diagnostics.Append(diag)
    return
}
```

**Empty Response Handling:**

When you expect the API to return data (e.g., Create, Read, Update), check for empty resources after ruling out payload errors:

```go
if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
    resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
    return
}
```

**Complete CRUD Error Pattern:**

Every CRUD method should follow this four-step error check sequence after an API call:

1. Check `err != nil` with `tferrors.NewDiagnosticFromAPIError()` (with operation-specific 404 handling for Read/Delete)
2. Check for nil response/payload to prevent panics
3. Check for payload errors with `tferrors.NewDiagnosticFromPayloadErrors()` (the API is telling you what went wrong)
4. Check for empty resources with `tferrors.NewEmptyResponseError()` (only when you expect data back)

See `internal/data_protection/content_pattern_resource.go` for a complete reference implementation.

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

Implement a `.wrap()` method on your resource models to convert API responses to Terraform state. Use the `flex` package (`internal/framework/flex`) for type conversions instead of raw `types.StringValue()` or `types.Int32Value()` calls. The `flex` functions handle nil pointers and empty strings correctly, converting them to null Terraform values:

```go
func (m *contentPatternResourceModel) wrap(
    pattern models.APIContentPatternV1,
) {
    m.ID = flex.StringPointerToFramework(pattern.ID)
    m.Name = flex.StringValueToFramework(pattern.Name)
    m.Description = flex.StringPointerToFramework(pattern.Description)
    m.MinMatchThreshold = flex.Int32PointerToFramework(pattern.MinMatchThreshold)
}
```

Key points:
- Use `flex.StringPointerToFramework()` for `*string` fields -- nil or empty becomes `types.StringNull()`.
- Use `flex.StringValueToFramework()` for `string` fields -- empty becomes `types.StringNull()`.
- Use `flex.Int32PointerToFramework()` for `*int32` fields -- nil becomes `types.Int32Null()`.
- The `.wrap()` method takes the API model by value, not as a pointer. The caller dereferences it.
- Keep `.wrap()` free of error returns when possible. If type conversions require diagnostics (e.g., collections), return `diag.Diagnostics`.

See [State Consistency with flex and Validators](#state-consistency-with-flex-and-validators) for why these flex functions matter and how they pair with schema validators.

### State Consistency with flex and Validators

**The problem:** Terraform compares your configuration to the state after every apply. If they don't match, Terraform returns an "inconsistent result after apply" error. This is a common issue with optional fields because the Go SDK doesn't distinguish between "not set" and "empty" — when a field has no value, the SDK may return `""` for strings or `[]` for lists. If a user sets `description = null` in their config but we write `""` to state, Terraform sees a mismatch and errors.

**The solution:** A two-part pattern that works together:

1. **Validators on the schema** prevent users from setting empty values. For example, `StringNotWhitespace()` ensures a string is either `null` (not set) or a real non-empty value — never `""`. Similarly, list/set size validators prevent empty collections.

2. **flex functions in `.wrap()`** normalize API responses. `flex.StringPointerToFramework()` converts `""` to `types.StringNull()`. `flex.FlattenStringValueSet()` converts `[]` to a null set.

Together, the only empty values that can exist come from the API, and flex converts them to `null` — matching what the user configured. Neither part works alone: without the validator, users could set `""` which flex would convert to `null` on read-back (different mismatch). Without flex, the API's `""` would land in state when the user had `null`.

**End-to-end example** — one field from schema to wrap:

```go
// In Schema(): the validator ensures the user can only set null or a real value
"description": schema.StringAttribute{
    Optional:    true,
    Description: "Description of the resource.",
    Validators: []validator.String{
        fwvalidators.StringNotWhitespace(),
    },
},

// In .wrap(): flex normalizes the API's "" to null
func (m *resourceModel) wrap(pattern models.APIPatternV1) {
    m.Description = flex.StringPointerToFramework(pattern.Description) // "" or nil → null
}

// In Create/Update: flex converts null back to "" for the API
createRequest := &models.CreateRequestV1{
    Description: flex.FrameworkToStringPointer(plan.Description), // null → ""
}
```

**When to use flex vs raw types:** Use flex for optional fields where the API might return empty values. For required fields that are always populated (like reading an ID from a create response), `types.StringValue()` works fine — but flex is preferred for consistency.

**Common flex functions:**

- **API → Terraform state (use in `.wrap()`):** `flex.StringPointerToFramework`, `flex.StringValueToFramework`, `flex.Int32PointerToFramework`, `flex.FlattenStringValueList`, `flex.FlattenStringValueSet`, `flex.FlattenHostGroupsToSet`
- **Terraform config → API request (use in Create/Update):** `flex.FrameworkToStringPointer`, `flex.FrameworkToInt32Pointer`, `flex.ExpandListAs[T]`, `flex.ExpandSetAs[T]`
- **Time:** `flex.RFC3339ValueToFramework`, `flex.RFC3339PointerToFramework`, `flex.FrameworkToRFC3339Pointer`

Run `go doc internal/framework/flex` for the full list and signatures.

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
res, err := r.client.SomeService.CreateResource(params)
if err != nil {
    resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
        tferrors.Create, err, resourceRequiredScopes,
    ))
    return
}

if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
    resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
    return
}

// IMPORTANT: Set the ID early, immediately after creation succeeds
plan.ID = flex.StringPointerToFramework(res.Payload.Resources[0].ID)

// Store this ID in state ASAP so Terraform can track the resource
resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
if resp.Diagnostics.HasError() {
    return
}

// Now continue with additional operations that might fail
// If these fail, Terraform will still have the ID to attempt cleanup
```

This pattern is essential for complex resources where multiple API calls are needed to fully configure them. By setting the ID in state as soon as possible, you ensure that even if subsequent operations fail and the apply errors out, Terraform can still attempt to delete the partially created resources during a destroy operation.
