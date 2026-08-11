package validators

import (
	"fmt"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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

// AttributeRequiresBool validates that when an attribute of any type is configured,
// a controlling boolean attribute must be enabled.
//
// This is used in ValidateConfig methods for cross-attribute validation.
// Returns empty diagnostics if validation passes, or diagnostics with an error
// if the attribute is configured but the required boolean attribute is not enabled.
//
// Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Example: Validate that "file_size_threshold" requires "file_scanning" to be enabled:
//
//	resp.Diagnostics.Append(
//	    validators.AttributeRequiresBool(
//	        config.FileSizeThreshold,
//	        config.FileScanning,
//	        "file_size_threshold",
//	        "file_scanning",
//	    )...)
func AttributeRequiresBool(
	attrValue attr.Value,
	requiredAttrValue types.Bool,
	attrName string,
	requiredAttrName string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if !utils.IsKnown(attrValue) || !utils.IsKnown(requiredAttrValue) {
		return diags
	}

	if !requiredAttrValue.ValueBool() {
		diags.AddAttributeError(
			path.Root(attrName),
			fmt.Sprintf("%s requires %s", attrName, requiredAttrName),
			fmt.Sprintf("When %s is configured, %s must be enabled.", attrName, requiredAttrName),
		)
	}
	return diags
}

// BoolRequiresStringValue validates that when a boolean attribute is enabled, a
// controlling string attribute must equal a specific value.
//
// This is used in ValidateConfig methods for cross-attribute validation.
// Returns empty diagnostics if validation passes, or diagnostics with an error
// if the attribute is enabled but the controlling attribute does not equal the
// required value.
//
// Null (unconfigured) and unknown (known after apply) values are skipped, as is
// a boolean that is disabled: switching a feature off never constrains what
// enables it.
//
// Example: Validate that "block_everything" requires "mode" to be "strict":
//
//	resp.Diagnostics.Append(
//	    validators.BoolRequiresStringValue(
//	        config.BlockEverything,
//	        config.Mode,
//	        "block_everything",
//	        "mode",
//	        "strict",
//	    )...)
func BoolRequiresStringValue(
	attrValue types.Bool,
	controllingValue types.String,
	attrName string,
	controllingName string,
	requiredValue string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if !utils.IsKnown(attrValue) || !utils.IsKnown(controllingValue) {
		return diags
	}

	if attrValue.ValueBool() && controllingValue.ValueString() != requiredValue {
		diags.AddAttributeError(
			path.Root(attrName),
			fmt.Sprintf("%s requires %s to be %q", attrName, controllingName, requiredValue),
			fmt.Sprintf("When %s is enabled, %s must be %q.", attrName, controllingName, requiredValue),
		)
	}
	return diags
}
