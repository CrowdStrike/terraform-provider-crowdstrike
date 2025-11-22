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

// AWSRegionOrAllValidator returns a validator that checks if strings match AWS region patterns or the special value "all".
func AWSRegionOrAllValidator() validator.String {
	return &awsRegionOrAllValidator{}
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
			fmt.Sprintf("'%s' is not a valid AWS region. AWS regions must follow the pattern like 'us-east-1', 'eu-west-1', or 'us-gov-west-1'.", region),
		)
	}
}

type awsRegionOrAllValidator struct{}

func (v *awsRegionOrAllValidator) Description(ctx context.Context) string {
	return "must be either 'all' or a valid AWS region (e.g., us-east-1, eu-west-1, us-gov-west-1)"
}

func (v *awsRegionOrAllValidator) MarkdownDescription(ctx context.Context) string {
	return "must be either `all` or a valid AWS region (e.g., `us-east-1`, `eu-west-1`, `us-gov-west-1`)"
}

func (v *awsRegionOrAllValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()

	// Allow "all" as a special value
	if value == "all" {
		return
	}

	// Otherwise, must be a valid AWS region
	if !IsValidAWSRegion(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid AWS Region or Special Value",
			fmt.Sprintf("'%s' is not valid. Value must be either 'all' or a valid AWS region like 'us-east-1', 'eu-west-1', or 'us-gov-west-1'.", value),
		)
	}
}

// AWSRegionsOrAllNonEmptyListValidator returns a validator that ensures the list contains either:
// - A single element with value "all"
// - One or more valid AWS regions
// - Cannot be an empty list (must be null/unset or have at least one element).
func AWSRegionsOrAllNonEmptyListValidator() validator.List {
	return &awsRegionsOrAllNonEmptyListValidator{}
}

type awsRegionsOrAllNonEmptyListValidator struct{}

func (v *awsRegionsOrAllNonEmptyListValidator) Description(ctx context.Context) string {
	return "must be either a single element 'all' or a list of valid AWS regions (cannot be empty)"
}

func (v *awsRegionsOrAllNonEmptyListValidator) MarkdownDescription(ctx context.Context) string {
	return "must be either a single element `all` or a list of valid AWS regions (cannot be empty)"
}

func (v *awsRegionsOrAllNonEmptyListValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
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
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty Regions List Not Allowed",
			"When specifying regions, you must provide at least one region. Use ['all'] to ingest events from all regions, or specify specific regions like ['us-east-1', 'us-west-2']. To use default behavior, omit the regions attribute entirely.",
		)
		return
	}

	// If there's exactly one element and it's "all", that's valid
	if len(elements) == 1 {
		value := elements[0].ValueString()
		if value == "all" {
			return // Valid: single element "all"
		}
	}

	// If "all" is present with other elements, that's invalid
	hasAll := false
	for _, element := range elements {
		if element.ValueString() == "all" {
			hasAll = true
			break
		}
	}

	if hasAll && len(elements) > 1 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Region Configuration",
			"When using 'all', it must be the only element in the list. Cannot mix 'all' with specific regions.",
		)
		return
	}

	// Validate each element as a valid AWS region (if not "all")
	for i, element := range elements {
		if element.IsNull() || element.IsUnknown() {
			continue
		}

		region := element.ValueString()
		if region != "all" && !IsValidAWSRegion(region) {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtListIndex(i),
				"Invalid AWS Region",
				fmt.Sprintf("'%s' is not a valid AWS region. AWS regions must follow the pattern like 'us-east-1', 'eu-west-1', or 'us-gov-west-1'.", region),
			)
		}
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
		return // Empty list is allowed
	}

	// If there's exactly one element and it's "all", that's valid
	if len(elements) == 1 {
		value := elements[0].ValueString()
		if value == "all" {
			return // Valid: single element "all"
		}
	}

	// If "all" is present with other elements, that's invalid
	hasAll := false
	for _, element := range elements {
		if element.ValueString() == "all" {
			hasAll = true
			break
		}
	}

	if hasAll && len(elements) > 1 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Region Configuration",
			"When using 'all', it must be the only element in the list. Cannot mix 'all' with specific regions.",
		)
		return
	}

	// Validate each element as a valid AWS region (if not "all")
	for i, element := range elements {
		if element.IsNull() || element.IsUnknown() {
			continue
		}

		region := element.ValueString()
		if region != "all" && !IsValidAWSRegion(region) {
			resp.Diagnostics.AddAttributeError(
				req.Path.AtListIndex(i),
				"Invalid AWS Region",
				fmt.Sprintf("'%s' is not a valid AWS region. AWS regions must follow the pattern like 'us-east-1', 'eu-west-1', or 'us-gov-west-1'.", region),
			)
		}
	}
}
