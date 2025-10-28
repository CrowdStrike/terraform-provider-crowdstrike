package cloudcompliance

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// API parameter building utilities

func buildCreateFrameworkParams(
	ctx context.Context,
	plan cloudComplianceCustomFrameworkResourceModel,
) *cloud_policies.CreateComplianceFrameworkParams {
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()

	createReq := &models.CommonCreateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewCreateComplianceFrameworkParamsWithContext(ctx)
	params.SetBody(createReq)
	return params
}

func buildUpdateFrameworkParams(
	ctx context.Context,
	plan cloudComplianceCustomFrameworkResourceModel,
) *cloud_policies.UpdateComplianceFrameworkParams {
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()

	updateReq := &models.CommonUpdateComplianceFrameworkRequest{
		Name:        &name,
		Description: &description,
		Active:      plan.Active.ValueBool(),
	}

	params := cloud_policies.NewUpdateComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(plan.ID.ValueString())
	params.SetBody(updateReq)
	return params
}

func buildCreateControlParams(
	ctx context.Context,
	frameworkID, sectionName, controlName, description string,
) *cloud_policies.CreateComplianceControlParams {
	createReq := &models.CommonCreateComplianceControlRequest{
		Name:        &controlName,
		Description: &description,
		FrameworkID: &frameworkID,
		SectionName: &sectionName,
	}

	params := cloud_policies.NewCreateComplianceControlParamsWithContext(ctx)
	params.SetBody(createReq)
	return params
}

// Terraform type conversion utilities

func convertRulesToTerraformSet(rules []string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	ruleValues := make([]attr.Value, len(rules))
	for i, rule := range rules {
		ruleValues[i] = types.StringValue(rule)
	}

	rulesSet, setDiags := types.SetValue(types.StringType, ruleValues)
	diags.Append(setDiags...)

	return rulesSet, diags
}

func convertControlsMapToTerraformMap(ctx context.Context, controls map[string]ControlModel) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	controlsAttrValue := make(map[string]attr.Value)
	for controlName, control := range controls {
		controlValue, controlDiags := types.ObjectValueFrom(ctx, controlAttrTypes, control)
		diags.Append(controlDiags...)
		if diags.HasError() {
			continue
		}
		controlsAttrValue[controlName] = controlValue
	}

	controlsMap, controlsMapDiags := types.MapValue(
		types.ObjectType{AttrTypes: controlAttrTypes},
		controlsAttrValue,
	)
	diags.Append(controlsMapDiags...)

	return controlsMap, diags
}

func convertSectionsMapToTerraformMap(ctx context.Context, sections map[string]SectionModel) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	sectionsAttrValue := make(map[string]attr.Value)
	for sectionName, section := range sections {
		sectionValue, sectionDiags := types.ObjectValueFrom(ctx, sectionAttrTypes, section)
		diags.Append(sectionDiags...)
		if diags.HasError() {
			continue
		}
		sectionsAttrValue[sectionName] = sectionValue
	}

	sectionsMap, sectionsMapDiags := types.MapValue(
		types.ObjectType{AttrTypes: sectionAttrTypes},
		sectionsAttrValue,
	)
	diags.Append(sectionsMapDiags...)

	return sectionsMap, diags
}
