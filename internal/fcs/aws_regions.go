package fcs

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AWS region regex patterns based on AWS SDK validation logic.
var (
	// Commercial regions: (us|eu|ap|sa|ca|me|af|il|mx)-direction-number.
	CommercialRegionRegex = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx)-\w+-[1-9]\d*$`)

	// GovCloud regions: us-gov-direction-number.
	GovCloudRegionRegex = regexp.MustCompile(`^us-gov-\w+-[1-9]\d*$`)

	// China regions: cn-direction-number.
	ChinaRegionRegex = regexp.MustCompile(`^cn-\w+-[1-9]\d*$`)

	// ISO regions: us-iso/isob/isoe/isof-direction-number.
	ISORegionRegex = regexp.MustCompile(`^us-iso[bf]?-\w+-[1-9]\d*$`)

	// European Sovereign Cloud: eusc-de-direction-number.
	EUSCRegionRegex = regexp.MustCompile(`^eusc-de-\w+-[1-9]\d*$`)
)

// IsValidAWSRegion validates if a region string matches AWS region patterns.
func IsValidAWSRegion(region string) bool {
	return CommercialRegionRegex.MatchString(region) ||
		GovCloudRegionRegex.MatchString(region) ||
		ChinaRegionRegex.MatchString(region) ||
		ISORegionRegex.MatchString(region) ||
		EUSCRegionRegex.MatchString(region)
}

// AWSRegionValidator returns a validator that checks if strings match AWS region patterns.
func AWSRegionValidator() validator.String {
	return &awsRegionValidator{}
}

type awsRegionValidator struct{}

func (v *awsRegionValidator) Description(ctx context.Context) string {
	return "must be a valid AWS region (e.g., us-east-1, eu-west-1, us-gov-west-1)"
}

func (v *awsRegionValidator) MarkdownDescription(ctx context.Context) string {
	return "must be a valid AWS region (e.g., `us-east-1`, `eu-west-1`, `us-gov-west-1`)"
}

func (v *awsRegionValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	region := req.ConfigValue.ValueString()

	if !IsValidAWSRegion(region) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid AWS Region",
			fmt.Sprintf("'%s' is not a valid AWS region format. Must match AWS region naming conventions for commercial, GovCloud, China, ISO, or EUSC regions.", region),
		)
	}
}

// AWSRegionsOrAllListValidator returns a validator that ensures the list contains either:
// - A single element with value "all"
// - One or more valid AWS regions.
func AWSRegionsOrAllListValidator() validator.List {
	return &awsRegionsOrAllListValidator{}
}

type awsRegionsOrAllListValidator struct{}

func (v *awsRegionsOrAllListValidator) Description(ctx context.Context) string {
	return "must be either a single element 'all' or a list of valid AWS regions"
}

func (v *awsRegionsOrAllListValidator) MarkdownDescription(ctx context.Context) string {
	return "must be either a single element `all` or a list of valid AWS regions"
}

func (v *awsRegionsOrAllListValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	var elements []types.String
	diags := req.ConfigValue.ElementsAs(ctx, &elements, false)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if len(elements) == 0 {
		return
	}

	for i, element := range elements {
		if element.IsNull() || element.IsUnknown() {
			continue
		}

		region := element.ValueString()
		if region == "all" {
			if len(elements) == 1 {
				return
			}
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid Region Configuration",
				"When using 'all', it must be the only element in the list. Cannot mix 'all' with specific regions.",
			)
			return
		}

		if !IsValidAWSRegion(region) {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtListIndex(i),
				"Invalid AWS Region",
				fmt.Sprintf("'%s' is not a valid AWS region format. Must match AWS region naming conventions.", region),
			)
		}
	}
}
