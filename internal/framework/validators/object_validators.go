package validators

import (
	"context"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// atLeastOneNonEmptyAttributeValidator validates that at least one attribute in an object is non-empty.
type atLeastOneNonEmptyAttributeValidator struct {
	attributeNames []string
}

func (v atLeastOneNonEmptyAttributeValidator) Description(_ context.Context) string {
	return "At least one attribute must be non-empty (not null/unknown and containing actual values)"
}

func (v atLeastOneNonEmptyAttributeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v atLeastOneNonEmptyAttributeValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if !utils.IsKnown(req.ConfigValue) {
		return
	}

	objectAttrs := req.ConfigValue.Attributes()

	hasNonEmptyAttribute := false
	hasUnknownAttribute := false
	for _, attrName := range v.attributeNames {
		if attrValue, exists := objectAttrs[attrName]; exists {
			if attrValue.IsUnknown() {
				hasUnknownAttribute = true
			} else if isAttributeNonEmpty(attrValue) {
				hasNonEmptyAttribute = true
				break
			}
		}
	}

	if hasUnknownAttribute && !hasNonEmptyAttribute {
		return
	}

	if !hasNonEmptyAttribute {
		attrList := strings.Join(v.attributeNames, ", ")
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty Object",
			"When this object is defined, at least one of the following attributes must be specified and non-empty: "+attrList+".",
		)
	}
}

func isAttributeNonEmpty(attrValue attr.Value) bool {
	if attrValue.IsNull() || attrValue.IsUnknown() {
		return false
	}

	switch val := attrValue.(type) {
	case basetypes.SetValue:
		return len(val.Elements()) > 0
	case basetypes.ListValue:
		return len(val.Elements()) > 0
	case basetypes.TupleValue:
		return len(val.Elements()) > 0
	case basetypes.DynamicValue:
		if val.IsNull() || val.IsUnknown() {
			return false
		}
		return isAttributeNonEmpty(val.UnderlyingValue())
	case basetypes.StringValue:
		return val.ValueString() != ""
	case basetypes.NumberValue:
		return true
	case basetypes.BoolValue:
		return true
	case basetypes.ObjectValue:
		return !val.IsNull()
	case basetypes.MapValue:
		return len(val.Elements()) > 0
	default:
		return true
	}
}

// AtLeastOneNonEmptyAttribute returns a validator that ensures at least one of the specified
// attributes in an object is non-empty (not null/unknown and containing actual values).
//
// This is useful for validating nested objects where at least one attribute
// must be provided with actual values.
//
// Example usage:
//
//	Validators: []validator.Object{
//	    validators.AtLeastOneNonEmptyAttribute("ids", "names", "types"),
//	}
func AtLeastOneNonEmptyAttribute(attributeNames ...string) validator.Object {
	return atLeastOneNonEmptyAttributeValidator{
		attributeNames: attributeNames,
	}
}
