package fusionsoar

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
)

var (
	DefinitionWithID   = definitionWithID
	NewDefinitionValue = newDefinitionValue
	QueryDefinitions   = queryDefinitions
	DeleteWorkflow     = deleteWorkflow
)

// DefinitionDiff returns the path and diagnostic detail of the first configured
// value got does not contain, or empty strings when it contains all of want.
func DefinitionDiff(want, got string) (string, string, error) {
	mismatch, err := definitionDiff(want, got)
	if err != nil || mismatch == nil {
		return "", "", err
	}
	return mismatch.path, mismatch.detail(), nil
}

// StoredDefinition returns the workflow definition as the API stores it.
func StoredDefinition(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification, id string) (string, error) {
	r := &fusionWorkflowResource{client: apiClient}
	workflow, diags := r.getWorkflow(ctx, tferrors.Read, id)
	if diags.HasError() {
		return "", fmt.Errorf("reading workflow %s: %v", id, diags)
	}
	return workflow.definition, nil
}

// ReplaceDefinitionAndDisable replaces the workflow definition and disables the
// workflow.
func ReplaceDefinitionAndDisable(ctx context.Context, apiClient *client.CrowdStrikeAPISpecification, id, definition string) error {
	r := &fusionWorkflowResource{client: apiClient}
	if diags := r.updateDefinition(ctx, id, definition, false); diags.HasError() {
		return fmt.Errorf("updating workflow %s: %v", id, diags)
	}
	if diags := r.setEnabled(ctx, tferrors.Update, id, false); diags.HasError() {
		return fmt.Errorf("disabling workflow %s: %v", id, diags)
	}
	return nil
}
