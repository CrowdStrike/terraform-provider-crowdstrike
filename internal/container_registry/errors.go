package containerregistry

import "github.com/hashicorp/terraform-plugin-framework/diag"

const (
	registryNotFoundErrorSummary = "Container Registry not found"
	registryCreateErrorSummary   = "Failed to create Container Registry"
	registryUpdateErrorSummary   = "Failed to update Container Registry"
	registryDeleteErrorSummary   = "Failed to delete Container Registry"
	registryReadErrorSummary     = "Failed to read Container Registry"
)

// newRegistryCreateError creates a standardized "create failed" error for container registries.
func newRegistryCreateError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(registryCreateErrorSummary, detail)
}

// newRegistryUpdateError creates a standardized "update failed" error for container registries.
func newRegistryUpdateError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(registryUpdateErrorSummary, detail)
}

// newRegistryDeleteError creates a standardized "delete failed" error for container registries.
func newRegistryDeleteError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(registryDeleteErrorSummary, detail)
}

// newRegistryReadError creates a standardized "read failed" error for container registries.
func newRegistryReadError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(registryReadErrorSummary, detail)
}
