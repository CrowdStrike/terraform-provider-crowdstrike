package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var windowsPlatformName = "Windows"
var linuxPlatformName = "Linux"
var macPlatformName = "Mac"

// ruleGroupAction for prevention policy action api.
type ruleGroupAction int

const (
	removeRuleGroup ruleGroupAction = iota
	addRuleGroup
)

// String convert ruleGroupAction to string value the api accepts.
func (r ruleGroupAction) String() string {
	return [...]string{"remove-rule-group", "add-rule-group"}[r]
}

// syncRuleGroups will sync the rule groups from the resource model to the api.
func syncRuleGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.IDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)

	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(updateRuleGroups(ctx, client, addRuleGroup, groupsToAdd, id)...)
	diags.Append(updateRuleGroups(ctx, client, removeRuleGroup, groupsToRemove, id)...)

	return diags
}

// updateRuleGroups will remove or add a slice of rule groups
// to a slice of prevention policies.
func updateRuleGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	action ruleGroupAction,
	ruleGroupIDs []string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(ruleGroupIDs) == 0 {
		return diags
	}

	var actionParams []*models.MsaspecActionParameter
	actionMsg := "adding"
	if action == removeRuleGroup {
		actionMsg = "removing"
	}
	name := "rule_group_id"

	for _, g := range ruleGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{id},
			},
		},
	)

	if err != nil {
		diags.AddError("Error updating prevention policy rule groups", fmt.Sprintf(
			"Could not %s prevention policy (%s) rule group (%s): %s",
			actionMsg,
			id,
			strings.Join(ruleGroupIDs, ", "),
			err.Error(),
		))
	}

	if res != nil && res.Payload == nil {
		return diags
	}

	for _, err := range res.Payload.Errors {
		diags.AddError(
			"Error updating prevention policy rule groups",
			fmt.Sprintf(
				"Could not %s prevention policy (%s) rule group (%s): %s",
				actionMsg,
				id,
				err.ID,
				err.String(),
			),
		)
	}

	return diags
}

// toggleOptions holds the options for toggleAttribute function.
type toggleOptions struct {
	enabled bool
}

// toggleOption is a functional option to configure toggleOption.
type toggleOption func(*toggleOptions)

// withEnabled sets the enabled field for toggleAttribute.
func withEnabled(enabled bool) toggleOption {
	return func(o *toggleOptions) {
		o.enabled = enabled
	}
}

func toggleAttribute(description string, opts ...toggleOption) schema.BoolAttribute {
	options := toggleOptions{
		enabled: false,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Description: fmt.Sprintf("Whether to enable the setting. %s", description),
		Default:     booldefault.StaticBool(options.enabled),
	}
}

var mlSliderLevels = []string{"DISABLED", "CAUTIOUS", "MODERATE", "AGGRESSIVE", "EXTRA_AGGRESSIVE"}
var mapMlSliderLevels = map[string]int{
	"DISABLED":         0,
	"CAUTIOUS":         1,
	"MODERATE":         2,
	"AGGRESSIVE":       3,
	"EXTRA_AGGRESSIVE": 4,
}

// mlSliderOptions holds the options for mlSLiderAttribute function.
type mlSliderOptions struct {
	description string
	prevention  bool
	detection   bool
}

// mlSliderOption is a functional option to configure mlSliderOptions.
type mlSliderOption func(*mlSliderOptions)

// withPrevention the description whether prevention should be included in the mlSliderAttribute.
func withPrevention(prevention bool) mlSliderOption {
	return func(o *mlSliderOptions) {
		o.prevention = prevention
	}
}

// generateMLSliderAttribute generates a mlslider attribute with a custom description.
// Includes prevention or detection slider settings if set to true.
func mlSLiderAttribute(description string, opts ...mlSliderOption) schema.SingleNestedAttribute {
	options := mlSliderOptions{
		description: "ml slider setting.",
		prevention:  true,
		detection:   true,
	}

	if description != "" {
		options.description = description
	}

	for _, opt := range opts {
		opt(&options)
	}

	attributeTypes := map[string]attr.Type{}
	attributeValues := map[string]attr.Value{}

	mlSliderAttribute := schema.SingleNestedAttribute{
		Optional:    true,
		Computed:    true,
		Description: description,
		Attributes:  map[string]schema.Attribute{},
	}

	if options.prevention {
		mlSliderAttribute.Attributes["prevention"] = schema.StringAttribute{
			Required:    true,
			Description: "Machine learning level for prevention.",
			Validators:  []validator.String{stringvalidator.OneOf(mlSliderLevels...)},
		}
		attributeTypes["prevention"] = types.StringType
		attributeValues["prevention"] = types.StringValue(mlSliderLevels[0])
	}

	if options.detection {
		mlSliderAttribute.Attributes["detection"] = schema.StringAttribute{
			Required:    true,
			Description: "Machine learning level for detection.",
			Validators:  []validator.String{stringvalidator.OneOf(mlSliderLevels...)},
		}
		attributeTypes["detection"] = types.StringType
		attributeValues["detection"] = types.StringValue(mlSliderLevels[0])
	}

	mlSliderAttribute.Default = objectdefault.StaticValue(
		types.ObjectValueMust(attributeTypes, attributeValues),
	)

	return mlSliderAttribute
}

// mlSlider a mlslider setting for a prevention policy.
type mlSlider struct {
	Detection  types.String `tfsdk:"detection"`
	Prevention types.String `tfsdk:"prevention"`
}

// detectionMlSlider a mlsider setting with only detection for a prevention policy.
type detectionMlSlider struct {
	Detection types.String `tfsdk:"detection"`
}

// apiToggle a toggle setting type used for calling CrowdStrike APIs.
type apiToggle struct {
	Enabled bool `json:"enabled"`
}

// apiMlSlider mlslider setting type used for calling CrowdStrike APIs.
type apiMlSlider struct {
	Detection  string `json:"detection,omitempty"`
	Prevention string `json:"prevention,omitempty"`
}

// updatePolicyEnabledState enables or disables a prevention policy.
func updatePolicyEnabledState(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
	enabled bool,
) (*prevention_policies.PerformPreventionPoliciesActionOK, diag.Diagnostics) {
	var diags diag.Diagnostics

	state := "disable"
	if enabled {
		state = "enable"
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			ActionName: state,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{id},
			},
		},
	)

	if err != nil {
		diags.AddError(
			"Error changing enabled state on prevention policy",
			fmt.Sprintf(
				"Could not %s prevention policy, unexpected error: \n\n %s",
				state,
				err.Error(),
			),
		)
	}

	return res, diags
}

// mapPreventionSettings converts prevention settings returned by the CrowdStrike api
// into the correct types used in the resource model and schema.
func mapPreventionSettings(
	categories []*models.PreventionCategoryRespV1,
) (map[string]types.Bool, map[string]*mlSlider, map[string]*detectionMlSlider) {
	toggleSettings := map[string]types.Bool{}
	mlSliderSettings := map[string]*mlSlider{}
	detectionMlSliderSettings := map[string]*detectionMlSlider{}

	for _, c := range categories {
		for _, s := range c.Settings {
			sID := *s.ID
			sValue := s.Value
			sType := *s.Type
			// the only slider that only supports detection instead of both prevention and detection.
			if sID == "ExtendedUserModeDataSlider" {
				v, _ := sValue.(map[string]interface{})
				detection, _ := v["detection"].(string)
				detectionMlSliderSettings[sID] = &detectionMlSlider{
					Detection: types.StringValue(detection),
				}
				continue
			}

			switch strings.ToLower(sType) {
			case "toggle":
				v, _ := sValue.(map[string]interface{})
				enabled, _ := v["enabled"].(bool)
				toggleSettings[sID] = types.BoolValue(enabled)
			case "mlslider":
				v, _ := sValue.(map[string]interface{})
				detection, _ := v["detection"].(string)
				prevention, _ := v["prevention"].(string)

				mlSliderSettings[sID] = &mlSlider{
					Detection:  types.StringValue(detection),
					Prevention: types.StringValue(prevention),
				}
			}
		}
	}

	return toggleSettings, mlSliderSettings, detectionMlSliderSettings
}

// validateMlSlider returns whether or not the mlslider is valid.
func validateMlSlider(attribute string, slider mlSlider) diag.Diagnostics {
	diags := diag.Diagnostics{}

	detectionLevel := slider.Detection.ValueString()
	preventionLevel := slider.Prevention.ValueString()

	if mapMlSliderLevels[detectionLevel] < mapMlSliderLevels[preventionLevel] {
		diags.AddAttributeError(
			path.Root(attribute),
			"Invalid ml slider setting.",
			fmt.Sprintf(
				"Prevention level: %s must the same or less restrictive than Detection level: %s. Ml detection levels are: %s",
				detectionLevel,
				preventionLevel,
				strings.Join(mlSliderLevels, ", "),
			),
		)
	}

	return diags
}

// validateRequiredAttribute validates that a required attribute is set.
func validateRequiredAttribute(
	attrValue bool,
	otherAttrValue bool,
	attr string,
	otherAttr string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if attrValue && !otherAttrValue {
		diags.AddAttributeError(
			path.Root(attr),
			fmt.Sprint("requirements not met to enable ", attr),
			fmt.Sprintf("%s requires %s to be enabled", attr, otherAttr),
		)
	}
	return diags
}

// deletePreventionPolicy deletes a prevention policy by id.
func deletePreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	_, diags = updatePolicyEnabledState(ctx, client, id, false)

	if diags.HasError() {
		return diags
	}

	_, err := client.PreventionPolicies.DeletePreventionPolicies(
		&prevention_policies.DeletePreventionPoliciesParams{
			Context: ctx,
			Ids:     []string{id},
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting prevention policy",
			fmt.Sprintf("Could not delete prevention policy: %s \n\n %s", id, err.Error()),
		)
		return diags
	}

	return diags
}

// updatePreventionPolicy updates a prevention policy with the provided settings.
func updatePreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	name, description string,
	preventionSettings []*models.PreventionSettingReqV1,
	id string,
) (*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var preventionPolicy *models.PreventionPolicyV1

	updateParams := prevention_policies.UpdatePreventionPoliciesParams{
		Context: ctx,
		Body: &models.PreventionUpdatePoliciesReqV1{
			Resources: []*models.PreventionUpdatePolicyReqV1{
				{
					ID:          &id,
					Name:        name,
					Description: description,
				},
			},
		},
	}

	updateParams.Body.Resources[0].Settings = preventionSettings

	res, err := client.PreventionPolicies.UpdatePreventionPolicies(&updateParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		diags.AddError(
			"Error updating prevention policy",
			fmt.Sprintf(
				"Could not update prevention policy, unexpected error: \n\n%s",
				err.Error(),
			),
		)
		return preventionPolicy, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Error updating prevention policy",
			fmt.Sprintf("No policy found with id: %s", id),
		)
	}

	preventionPolicy = res.Payload.Resources[0]

	return preventionPolicy, diags
}

// getPreventionPolicy retrieves a prevention policy by id.
func getPreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) (*models.PreventionPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var preventionPolicy *models.PreventionPolicyV1

	res, err := client.PreventionPolicies.GetPreventionPolicies(
		&prevention_policies.GetPreventionPoliciesParams{
			Context: ctx,
			Ids:     []string{id},
		},
	)

	if err != nil {
		diags.AddError(
			"Error reading CrowdStrike prevention policy",
			fmt.Sprintf(
				"Could not read CrowdStrike prevention policy: %s \n\n %s",
				id,
				err.Error(),
			),
		)
		return preventionPolicy, diags
	}

	if len(res.GetPayload().Resources) == 0 {
		diags.AddError(
			"Error reading CrowdStrike prevention policy",
			fmt.Sprintf(
				"Could not read CrowdStrike prevention policy: %s \n\n %s",
				id,
				"No policy found",
			),
		)
		return preventionPolicy, diags
	}

	preventionPolicy = res.GetPayload().Resources[0]
	return preventionPolicy, diags
}

// createPreventionPolicy creates a new prevention policy.
func createPreventionPolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	name, description, platformName string,
	preventionSettings []*models.PreventionSettingReqV1,
) (*prevention_policies.CreatePreventionPoliciesCreated, diag.Diagnostics) {
	var diags diag.Diagnostics
	var res *prevention_policies.CreatePreventionPoliciesCreated

	createParams := prevention_policies.CreatePreventionPoliciesParams{
		Context: ctx,
		Body: &models.PreventionCreatePoliciesReqV1{
			Resources: []*models.PreventionCreatePolicyReqV1{
				{
					Name:         &name,
					Description:  description,
					PlatformName: &platformName,
				},
			},
		},
	}

	createParams.Body.Resources[0].Settings = preventionSettings

	res, err := client.PreventionPolicies.CreatePreventionPolicies(&createParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		if strings.Contains(err.Error(), "least one ID must be provided") {
			diags.AddError(
				"Error creating prevention policy",
				"A prevention policy with the same name may already exist.",
			)
		} else {
			diags.AddError(
				"Error creating prevention policy",
				"Could not create prevention policy, unexpected error: "+err.Error(),
			)
		}
	}

	return res, diags
}

// updateHostGroups will remove or add a slice of host groups
// to a slice of prevention policies.
func updateHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	action hostgroups.HostGroupAction,
	hostGroupIDs []string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(hostGroupIDs) == 0 {
		return diags
	}

	var actionParams []*models.MsaspecActionParameter
	actionMsg := "adding"
	if action == hostgroups.RemoveHostGroup {
		actionMsg = "removing"
	}
	name := "group_id"

	for _, g := range hostGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	if len(actionParams) == 0 {
		return diags
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{id},
			},
		},
	)

	if err != nil {
		diags.AddError("Error updating prevention policy host groups", fmt.Sprintf(
			"Could not %s prevention policy (%s) host group (%s): %s",
			actionMsg,
			id,
			strings.Join(hostGroupIDs, ", "),
			err.Error(),
		))
	}

	if res != nil && res.Payload == nil {
		return diags
	}

	for _, err := range res.Payload.Errors {
		diags.AddError(
			"Error updating prevention policy host groups",
			fmt.Sprintf(
				"Could not %s prevention policy (%s) host group (%s): %s",
				actionMsg,
				id,
				err.ID,
				err.String(),
			),
		)
	}

	return diags
}

// syncHostGroups will sync the host groups from the resource model to the api.
func syncHostGroups(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.IDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(updateHostGroups(ctx, client, hostgroups.AddHostGroup, groupsToAdd, id)...)
	diags.Append(updateHostGroups(ctx, client, hostgroups.RemoveHostGroup, groupsToRemove, id)...)

	return diags
}
