package responsepolicy

import (
	"fmt"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// boolRequiresPlatform validates that a boolean attribute is only enabled
// for specific platform values.
//
// This is used in ValidateConfig methods for platform-specific validation.
// Returns empty diagnostics if validation passes, or diagnostics with an error
// if the attribute is enabled for an invalid platform.
//
// Null (unconfigured) and unknown (known after apply) values are skipped.
//
// Example: Validate that "falcon_scripts" can only be used on Windows:
//
//	resp.Diagnostics.Append(
//	    boolRequiresPlatform(
//	        config.FalconScripts,
//	        config.PlatformName,
//	        "falcon_scripts",
//	        []string{"Windows"},
//	    )...)
func boolRequiresPlatform(
	attrValue types.Bool,
	platformValue types.String,
	attrName string,
	validPlatforms []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if !attrValue.ValueBool() || !utils.IsKnown(platformValue) {
		return diags
	}

	platform := platformValue.ValueString()
	for _, validPlatform := range validPlatforms {
		if platform == validPlatform {
			return diags
		}
	}

	platformList := strings.Join(validPlatforms, "' or '")
	diags.AddAttributeError(
		path.Root(attrName),
		fmt.Sprintf("Invalid platform for %s", attrName),
		fmt.Sprintf("%s can only be used with platform_name '%s', but platform_name is '%s'.",
			attrName, platformList, platform),
	)
	return diags
}
