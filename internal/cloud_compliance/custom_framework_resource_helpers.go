package cloudcompliance

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var controlAttrTypes = map[string]attr.Type{
	"id":          types.StringType,
	"name":        types.StringType,
	"description": types.StringType,
	"rules":       types.SetType{ElemType: types.StringType},
}

var sectionAttrTypes = map[string]attr.Type{
	"name": types.StringType,
	"controls": types.MapType{
		ElemType: types.ObjectType{
			AttrTypes: controlAttrTypes,
		},
	},
}

// SectionDomainModel is the Go representation of SectionTFModel
type SectionDomainModel struct {
	Key      string
	Name     string
	Controls map[string]ControlDomainModel
}

// ControlDomainModel is the Go representation of ControlTFModel
type ControlDomainModel struct {
	Key         string
	ID          string
	Name        string
	Description string
	Rules       []string
}

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

func buildRenameSectionParams(
	ctx context.Context,
	frameworkID, oldSectionName, newSectionName string,
) *cloud_policies.RenameSectionComplianceFrameworkParams {
	renameReq := &models.CommonRenameSectionRequest{
		SectionName: &newSectionName,
	}

	params := cloud_policies.NewRenameSectionComplianceFrameworkParamsWithContext(ctx)
	params.SetIds(frameworkID)
	params.SetSectionName(oldSectionName)
	params.SetBody(renameReq)
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

func convertControlsMapToTerraformMap(ctx context.Context, controls map[string]ControlTFModel, nameToKey map[string]string) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	controlsAttrValue := make(map[string]attr.Value)
	for controlName, control := range controls {
		controlKey := nameToKey[controlName]
		controlValue, controlDiags := types.ObjectValueFrom(ctx, controlAttrTypes, control)
		diags.Append(controlDiags...)
		if diags.HasError() {
			continue
		}
		controlsAttrValue[controlKey] = controlValue
	}

	controlsMap, controlsMapDiags := types.MapValue(
		types.ObjectType{AttrTypes: controlAttrTypes},
		controlsAttrValue,
	)
	diags.Append(controlsMapDiags...)

	return controlsMap, diags
}

func convertSectionsMapToTerraformMap(ctx context.Context, sections map[string]SectionTFModel) (types.Map, diag.Diagnostics) {
	var diags diag.Diagnostics

	sectionsAttrValue := make(map[string]attr.Value)
	for sectionKey, section := range sections {
		sectionValue, sectionDiags := types.ObjectValueFrom(ctx, sectionAttrTypes, section)
		diags.Append(sectionDiags...)
		if diags.HasError() {
			continue
		}
		sectionsAttrValue[sectionKey] = sectionValue
	}

	sectionsMap, sectionsMapDiags := types.MapValue(
		types.ObjectType{AttrTypes: sectionAttrTypes},
		sectionsAttrValue,
	)
	diags.Append(sectionsMapDiags...)

	return sectionsMap, diags
}

func convertSectionsTFMapToDomainMapByName(ctx context.Context, sections map[string]SectionTFModel) (map[string]SectionDomainModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sectionsDomainMap := make(map[string]SectionDomainModel)
	for sectionKey, section := range sections {
		sectionsDomainMap[section.Name.ValueString()] = SectionDomainModel{
			Key:      sectionKey,
			Name:     section.Name.ValueString(),
			Controls: map[string]ControlDomainModel{},
		}

		var sectionControls map[string]ControlTFModel
		diags.Append(section.Controls.ElementsAs(ctx, &sectionControls, false)...)

		for controlKey, control := range sectionControls {
			var rules []string
			diags.Append(control.Rules.ElementsAs(ctx, &rules, false)...)

			sectionsDomainMap[section.Name.ValueString()].Controls[control.Name.ValueString()] = ControlDomainModel{
				Key:         controlKey,
				ID:          control.ID.ValueString(),
				Name:        control.Name.ValueString(),
				Description: control.Description.ValueString(),
				Rules:       rules,
			}
		}
	}

	return sectionsDomainMap, diags
}
