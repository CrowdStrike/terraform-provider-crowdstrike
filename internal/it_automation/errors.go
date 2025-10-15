package itautomation

import "github.com/hashicorp/terraform-plugin-framework/diag"

const (
	policyNotFoundErrorSummary    = "IT Automation Policy not found"
	taskNotFoundErrorSummary      = "IT Automation Task not found"
	taskGroupNotFoundErrorSummary = "IT Automation Task Group not found"
	notFoundRemoving              = "%s not found, removing from state"
	itAutomationPolicy            = "IT Automation Policy"
	itAutomationTask              = "IT Automation Task"
	itAutomationTaskGroup         = "IT Automation Task Group"
)

// newPolicyNotFoundError creates a new policy not found error diagnostic.
func newPolicyNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(policyNotFoundErrorSummary, detail)
}

// newTaskNotFoundError creates a new task not found error diagnostic.
func newTaskNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(taskNotFoundErrorSummary, detail)
}

// newTaskGroupNotFoundError creates a new task group not found error diagnostic.
func newTaskGroupNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(taskGroupNotFoundErrorSummary, detail)
}
