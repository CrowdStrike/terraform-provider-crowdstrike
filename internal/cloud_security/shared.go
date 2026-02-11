package cloudsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityInformational = "informational"
)

var (
	severityToInt64 = map[string]int64{
		SeverityCritical:      0,
		SeverityHigh:          1,
		SeverityMedium:        2,
		SeverityInformational: 3,
	}
	int32ToSeverity = map[int32]string{
		0: SeverityCritical,
		1: SeverityHigh,
		2: SeverityMedium,
		3: SeverityInformational,
	}
	int64ToSeverity = map[int64]string{
		0: SeverityCritical,
		1: SeverityHigh,
		2: SeverityMedium,
		3: SeverityInformational,
	}
	severityToString = map[string]string{
		SeverityCritical:      "0",
		SeverityHigh:          "1",
		SeverityMedium:        "2",
		SeverityInformational: "3",
	}
	stringToSeverity = map[string]string{
		"0": SeverityCritical,
		"1": SeverityHigh,
		"2": SeverityMedium,
		"3": SeverityInformational,
	}
)

func convertAlertRemediationInfoToTerraformState(input *string) basetypes.ListValue {
	if input == nil || *input == "" {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	*input = strings.TrimSpace(*input)
	*input = strings.TrimSuffix(*input, "|")

	parts := strings.Split(*input, "|")
	values := make([]attr.Value, 0, len(parts))

	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(trimmed, fmt.Sprintf("Step %d. ", index+1)); ok {
			trimmed = strings.TrimSpace(after)
		} else {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, fmt.Sprintf("%d. ", index+1)))
		}
		if trimmed != "" {
			values = append(values, types.StringValue(trimmed))
		}
	}

	return types.ListValueMust(types.StringType, values)
}

func convertAlertInfoToAPIFormat(ctx context.Context, alertInfo basetypes.ListValue, includeNumbering ...bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var alertInfoStrings []string
	var convertedAlertInfo string

	includeNum := false
	if len(includeNumbering) > 0 {
		includeNum = includeNumbering[0]
	}

	if alertInfo.IsNull() || alertInfo.IsUnknown() || len(alertInfo.Elements()) == 0 {
		return "", diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Alert Info while custom rules only require | without
	// newlines or numbering
	if includeNum {
		for i, elem := range alertInfo.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting AlertInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return "", diags
			}
			alertInfoStrings = append(alertInfoStrings, fmt.Sprintf("%d. %s", i+1, str.ValueString()))
		}

		convertedAlertInfo = strings.Join(alertInfoStrings, "|\n")
	} else {
		diags = alertInfo.ElementsAs(ctx, &alertInfoStrings, false)
		convertedAlertInfo = strings.Join(alertInfoStrings, "|")
	}
	return convertedAlertInfo, diags
}

func convertRemediationInfoToAPIFormat(ctx context.Context, info basetypes.ListValue, includeNumbering ...bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var infoStrings []string
	var convertedInfo string

	if info.IsNull() || info.IsUnknown() || len(info.Elements()) == 0 {
		return "", diags
	}

	includeNum := false
	if len(includeNumbering) > 0 {
		includeNum = includeNumbering[0]
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Remediation info while custom rules only require | without
	// newlines or numbering
	if includeNum {
		for i, elem := range info.Elements() {
			str, ok := elem.(types.String)
			if !ok {
				diags.AddError(
					"Error converting RemediationInfo",
					fmt.Sprintf("Failed to convert element %d to string", i),
				)
				return "", diags
			}
			infoStrings = append(infoStrings, fmt.Sprintf("Step %d. %s", i+1, str.ValueString()))
		}
		convertedInfo = strings.Join(infoStrings, "|\n")
	} else {
		diags = info.ElementsAs(ctx, &infoStrings, false)
		convertedInfo = strings.Join(infoStrings, "|")
	}

	return convertedInfo, diags
}

func createCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.CreateRuleMixin0Params, scopes []scopes.Scope) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var newRule *models.ApimodelsRule

	resp, err := client.CloudPolicies.CreateRuleMixin0(&params)
	diag := tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, scopes)
	if diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.Append(tferrors.NewOperationError(tferrors.Create, err))
		return nil, diags
	}

	newRule = payload.Resources[0]

	return newRule, diags
}

func getCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.GetRuleParams, scopes []scopes.Scope) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	resp, err := client.CloudPolicies.GetRule(&params)
	diag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, scopes)
	if diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	return payload.Resources[0], diags
}

func updateCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.UpdateRuleParams, scopes []scopes.Scope) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	resp, err := client.CloudPolicies.UpdateRule(&params)
	diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, scopes)
	if diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return nil, diags
	}

	return payload.Resources[0], diags
}

func deleteCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.DeleteRuleMixin0Params, scopes []scopes.Scope) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := client.CloudPolicies.DeleteRuleMixin0(&params)
	diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, scopes)
	if diag != nil {
		diags.Append(diag)
		return diags
	}

	return diags
}

// handleNotFoundRemoveFromState checks if the diagnostics contain a "not found" error and handles it by
// removing the resource from state and logging a warning.
func handleNotFoundRemoveFromState(
	ctx context.Context,
	diags diag.Diagnostics,
	resourceID string,
	resourceType string,
	resp *resource.ReadResponse,
) bool {
	if !diags.HasError() {
		return false
	}

	if tferrors.HasNotFoundError(diags) {
		resp.State.RemoveResource(ctx)
		tflog.Warn(
			ctx,
			fmt.Sprintf(
				"%s with ID %s not found, removing from state",
				resourceType,
				resourceID,
			),
		)
		return true
	}

	return false
}
