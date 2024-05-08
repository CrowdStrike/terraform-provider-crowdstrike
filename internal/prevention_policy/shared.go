package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
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

// var linuxPlatformName = "Linux"
// var macPlatformName = "Mac"

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

// getRuleGroupsToModify takes in a slice of planned rule groups and a slice of current rule groups, and returns
// the rule groups to add and remove.
func getRuleGroupsToModify(
	ctx context.Context,
	plan, state types.Set,
) (ruleGroupsToAdd []string, ruleGroupsToRemove []string, diags diag.Diagnostics) {
	var planRuleGroupIDs, stateRuleGroupIDs []string
	planMap := make(map[string]bool)
	stateMap := make(map[string]bool)

	diags.Append(plan.ElementsAs(ctx, &planRuleGroupIDs, false)...)
	if diags.HasError() {
		return
	}
	diags.Append(state.ElementsAs(ctx, &stateRuleGroupIDs, false)...)
	if diags.HasError() {
		return
	}

	for _, id := range planRuleGroupIDs {
		planMap[id] = true
	}

	for _, id := range stateRuleGroupIDs {
		stateMap[id] = true
	}

	for _, id := range planRuleGroupIDs {
		if !stateMap[id] {
			ruleGroupsToAdd = append(ruleGroupsToAdd, id)
		}
	}

	for _, id := range stateRuleGroupIDs {
		if !planMap[id] {
			ruleGroupsToRemove = append(ruleGroupsToRemove, id)
		}
	}

	return
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
	policyID string,
	enabled bool,
) (prevention_policies.PerformPreventionPoliciesActionOK, error) {
	state := "disable"
	if enabled {
		state = "enable"
	}

	res, err := client.PreventionPolicies.PerformPreventionPoliciesAction(
		&prevention_policies.PerformPreventionPoliciesActionParams{
			ActionName: state,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	return *res, err
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
	diag := diag.Diagnostics{}

	detectionLevel := slider.Detection.ValueString()
	preventionLevel := slider.Prevention.ValueString()

	if mapMlSliderLevels[detectionLevel] < mapMlSliderLevels[preventionLevel] {
		diag.AddAttributeError(
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

	return diag
}

// validateRequiredAttribute validates that a required attribute is set.
func validateRequiredAttribute(
	attrValue bool,
	otherAttrValue bool,
	attr string,
	otherAttr string,
) diag.Diagnostics {
	diag := diag.Diagnostics{}

	if attrValue && !otherAttrValue {
		diag.AddAttributeError(
			path.Root(attr),
			fmt.Sprint("requirements not met to enable ", attr),
			fmt.Sprintf("%s requires %s to be enabled", attr, otherAttr),
		)
	}
	return diag
}
