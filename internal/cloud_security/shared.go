package cloudsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	iomRuleDomainConfig = cloudSecurityDomainConfig{
		Domain:    "CSPM",
		Subdomain: "IOM",
	}
	kacIomRuleDomainConfig = cloudSecurityDomainConfig{
		Domain:    "Runtime",
		Subdomain: "IOM",
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

func convertAlertInfoToAPIFormat(ctx context.Context, alertInfo basetypes.ListValue, includeNumbering bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var alertInfoStrings []string
	var convertedAlertInfo string

	if alertInfo.IsNull() || alertInfo.IsUnknown() || len(alertInfo.Elements()) == 0 {
		return "", diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Alert Info while custom rules only require | without
	// newlines or numbering
	if includeNumbering {
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

func convertRemediationInfoToAPIFormat(ctx context.Context, info basetypes.ListValue, includeNumbering bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var infoStrings []string
	var convertedInfo string

	if info.IsNull() || info.IsUnknown() || len(info.Elements()) == 0 {
		return "", diags
	}

	// Duplicate rules require the numbering with |\n delimiters
	// for Remediation info while custom rules only require | without
	// newlines or numbering
	if includeNumbering {
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

func createCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.CreateRuleMixin0Params) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	var newRule *models.ApimodelsRule

	resp, err := client.CloudPolicies.CreateRuleMixin0(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateRuleMixin0BadRequest); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if ruleConflict, ok := err.(*cloud_policies.CreateRuleMixin0Conflict); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (409): %+v", *ruleConflict.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateRuleMixin0InternalServerError); ok {
			diags.AddError(
				"Error Creating Rule",
				fmt.Sprintf("Failed to create rule (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Rule",
			fmt.Sprintf("Failed to create rule: %+v", err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Rule",
			"Failed to create rule: API returned an empty response",
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Creating Rule. Body Error",
			fmt.Sprintf("Failed to create rule: %s", err.Error()),
		)
		return nil, diags
	}

	newRule = payload.Resources[0]

	return newRule, diags
}

func getCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.GetRuleParams) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	resp, err := client.CloudPolicies.GetRule(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetRuleNotFound); ok {
			diags.Append(tferrors.NewNotFoundError(
				fmt.Sprintf("Failed to retrieve rule (404): %s, %+v", params.Ids[0], *notFound.Payload.Errors[0].Message),
			))
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetRuleInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed to retrieve rule (500): %s, %+v", params.Ids[0], *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule %s: %+v", params.Ids[0], err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule %s: API returned an empty response", params.Ids[0]),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func updateCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.UpdateRuleParams) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	resp, err := client.CloudPolicies.UpdateRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateRuleBadRequest); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (400): %+v", *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if ruleConflict, ok := err.(*cloud_policies.UpdateRuleConflict); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (409): %+v", *ruleConflict.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.UpdateRuleInternalServerError); ok {
			diags.AddError(
				"Error Updating Rule",
				fmt.Sprintf("Failed to update rule (500): %+v", *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err),
		)
		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule %s: API returned an empty response", *params.Body.UUID),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return nil, diags
	}
	return payload.Resources[0], diags
}

func deleteCloudPolicyRule(client *client.CrowdStrikeAPISpecification, params cloud_policies.DeleteRuleMixin0Params) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := client.CloudPolicies.DeleteRuleMixin0(&params)
	if err != nil {
		if _, ok := err.(*cloud_policies.DeleteRuleMixin0NotFound); ok {
			return diags
		}
		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule %s: \n\n %s", params.Ids[0], err.Error()),
		)
	}

	return diags
}

// handleNotFoundRemoveFromState checks if the diagnostics contain a "not found" error and handles it by
// removing the resource from state and logging a warning. Returns true if the error was handled,
// false otherwise. This function can be used across all custom rule resources for consistent
// error handling.
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
