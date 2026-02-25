package cloudsecurity

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var customRulesSchema = schema.SetNestedAttribute{
	Computed: true,
	Optional: true,
	Default:  setdefault.StaticValue(types.SetNull(types.ObjectType{AttrTypes: customRulesAttrMap})),
	MarkdownDescription: "Manage custom rules for your KAC policy. Adding a custom rule to one " +
		"rule group also adds the custom rule to all other rule groups in the same policy. " +
		"Custom rules are set to `\"Disabled\"` by default. Action must be one of:\n" +
		" - `\"Disabled\"`: Do nothing\n" +
		" - `\"Alert\"`: Send an alert\n" +
		" - `\"Prevent\"`: Prevent the object from running",
	NestedObject: schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier for the KAC custom rule.",
			},
			"action": schema.StringAttribute{
				Required:    true,
				Description: "Determines what action Falcon KAC takes when assessing the custom rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("Alert", "Prevent", "Disabled"),
				},
			},
		},
	},
}

func (cr *customRuleTFModel) wrapCustomRule(apiCustomRule *models.ModelsKACCustomPolicyRule) {
	if apiCustomRule.ID != nil {
		cr.ID = types.StringValue(*apiCustomRule.ID)
	}
	if apiCustomRule.Action != nil {
		cr.Action = types.StringValue(*apiCustomRule.Action)
	}
}
