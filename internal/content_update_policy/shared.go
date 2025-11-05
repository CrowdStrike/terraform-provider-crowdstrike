package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Valid delay hours for GA ring.
var validDelayHours = []int64{0, 1, 2, 4, 8, 12, 24, 48, 72}

// delayHoursValidators returns common validators for delay hours attributes.
func delayHoursValidators() []validator.Int64 {
	return []validator.Int64{
		int64validator.OneOf(validDelayHours...),
	}
}

// getContentUpdatePolicy retrieves a content update policy by ID.
func getContentUpdatePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting getContentUpdatePolicy", map[string]interface{}{
		"policyID": policyID,
	})

	res, err := client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)

	if err != nil {
		tflog.Error(ctx, "API call failed in getContentUpdatePolicy", map[string]interface{}{
			"policyID": policyID,
			"error":    err.Error(),
		})
		diags.AddError(
			"Error reading content update policy",
			"Could not read content update policy: "+policyID+": "+err.Error(),
		)
		return nil, diags
	}

	tflog.Debug(ctx, "API call successful", map[string]interface{}{
		"policyID":        policyID,
		"resources_count": len(res.Payload.Resources),
	})

	if len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, "Content update policy not found", map[string]interface{}{
			"policyID": policyID,
		})
		diags.AddError(
			"Content update policy not found",
			fmt.Sprintf("Content update policy with ID %s not found", policyID),
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]
	tflog.Debug(ctx, "Successfully retrieved content update policy", map[string]interface{}{
		"policyID":          policyID,
		"policy_name":       *policy.Name,
		"enabled":           *policy.Enabled,
		"host_groups_count": len(policy.Groups),
	})

	return policy, diags
}

// updatePolicyEnabledState enables or disables a content update policy.
func updatePolicyEnabledState(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	enabled bool,
) error {
	actionName := "disable"
	if enabled {
		actionName = "enable"
	}

	tflog.Debug(ctx, "Starting updatePolicyEnabledState", map[string]interface{}{
		"policyID":   policyID,
		"enabled":    enabled,
		"actionName": actionName,
	})

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	if err != nil {
		tflog.Error(ctx, "Failed to update policy enabled state", map[string]interface{}{
			"policyID":   policyID,
			"enabled":    enabled,
			"actionName": actionName,
			"error":      err.Error(),
		})
	} else {
		tflog.Debug(ctx, "Successfully updated policy enabled state", map[string]interface{}{
			"policyID":   policyID,
			"enabled":    enabled,
			"actionName": actionName,
		})
	}

	return err
}
