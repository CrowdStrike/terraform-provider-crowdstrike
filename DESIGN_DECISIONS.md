# Design Decisions and Patterns

This document records architectural decisions, idioms, and patterns unique to the CrowdStrike Terraform provider. It explains the "why" behind our code, not just the "how."

## API Interaction
- **Single Source of Truth:** All API interactions must go through the `gofalcon` library. This ensures consistency and leverages upstream model validation.
- **No Direct HTTP:** Never use direct HTTP calls or undocumented endpoints, even for edge cases—extend `gofalcon` if necessary.

## Resource Schema Patterns
- **User Experience First:** Resource schemas are designed for clarity and usability, not just to mirror the API. For example, we group related fields and use Terraform idioms (e.g., sets for collections).
- **Request vs. Response Models:** Only fields present in the API's request models (`Create...ReqV1`, `Update...ReqV1`) are user-settable. Fields only in response models are marked as `Computed`.
- **Plan Modifiers:** Use `RequiresReplace` for immutable fields, `UseStateForUnknown` for IDs, etc., to ensure correct lifecycle behavior.

## Validation
- **Early Feedback:** All resource-specific validation is implemented in `ValidateConfig`, not in CRUD methods, to provide early feedback during `terraform plan`.
- **Conditional Logic:** Use `ValidateConfig` for mutually exclusive fields, conditionally required attributes, and complex validation that cannot be expressed with simple validators.

## Error Handling
- **Actionable Errors:** Error messages should be actionable and user-focused, especially for common issues like insufficient API scopes.
- **Diagnostics:** Always use `resp.Diagnostics.AddError` for reporting errors in CRUD and validation methods.

## Resource Registration
- **Explicit Registration:** All resources must be registered in the `Resources` function in `internal/provider/provider.go`. This is the only place resources are made available to Terraform.

## File Structure
- **Resource Implementation:** `internal/<resource>/<resource>_resource.go`
- **Acceptance Tests:** `internal/<resource>/<resource>_resource_test.go`
- **Examples:** `examples/resources/<resource>/`
- **Docs:** Auto-generated in `docs/resources/` from schema and examples.

## Example Patterns
- **Host Group Resource:** See `internal/host_groups/host_group_resource.go` for a canonical example of schema design, validation, and error handling.
- **Testing:** Acceptance tests follow the patterns in the [Terraform Testing documentation](https://developer.hashicorp.com/terraform/plugin/testing/testing-patterns).

---

If you introduce a new pattern or make a significant design decision, please update this file to keep it current and helpful for all contributors. 