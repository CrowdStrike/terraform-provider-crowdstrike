package validators

import (
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// BoolRequiresBool validates that when one boolean attribute is enabled,
// another boolean attribute must also be enabled.
//
// This is used in ValidateConfig methods for cross-attribute validation.
// Returns empty diagnostics if validation passes, or diagnostics with an error
// if the first attribute is enabled but the required attribute is not.
//
// Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Example: Validate that "falcon_scripts" requires "custom_scripts" to be enabled:
//
//	resp.Diagnostics.Append(
//	    validators.BoolRequiresBool(
//	        config.FalconScripts,
//	        config.CustomScripts,
//	        "falcon_scripts",
//	        "custom_scripts",
//	    )...)
func BoolRequiresBool(
	attrValue types.Bool,
	requiredAttrValue types.Bool,
	attrName string,
	requiredAttrName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if !utils.IsKnown(attrValue) || !utils.IsKnown(requiredAttrValue) {
		return diags
	}

	if attrValue.ValueBool() && !requiredAttrValue.ValueBool() {
		diags.AddAttributeError(
			path.Root(attrName),
			fmt.Sprintf("%s requires %s", attrName, requiredAttrName),
			fmt.Sprintf("When %s is enabled, %s must also be enabled.", attrName, requiredAttrName),
		)
	}
	return diags
}
