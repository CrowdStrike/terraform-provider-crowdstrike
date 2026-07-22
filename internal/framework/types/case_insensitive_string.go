package types

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ basetypes.StringTypable                    = (*CaseInsensitiveStringType)(nil)
	_ basetypes.StringValuableWithSemanticEquals = (*CaseInsensitiveString)(nil)
)

// CaseInsensitiveStringType is an attribute type that treats two strings as
// semantically equal when they differ only by letter case. This prevents
// Terraform data consistency errors and drift when the API normalizes the
// casing of a value (for example, title-casing a category name).
type CaseInsensitiveStringType struct {
	basetypes.StringType
}

// String returns a human-readable string of the type name.
func (t CaseInsensitiveStringType) String() string {
	return "types.CaseInsensitiveStringType"
}

// ValueType returns the Value type.
func (t CaseInsensitiveStringType) ValueType(ctx context.Context) attr.Value {
	return CaseInsensitiveString{}
}

// Equal returns true if the given type is equivalent.
func (t CaseInsensitiveStringType) Equal(o attr.Type) bool {
	other, ok := o.(CaseInsensitiveStringType)
	if !ok {
		return false
	}

	return t.StringType.Equal(other.StringType)
}

// ValueFromString returns a StringValuable type given a StringValue.
func (t CaseInsensitiveStringType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return CaseInsensitiveString{
		StringValue: in,
	}, nil
}

// ValueFromTerraform returns a Value given a tftypes.Value.
func (t CaseInsensitiveStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}

	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}

	stringValuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to StringValuable: %v", diags)
	}

	return stringValuable, nil
}

// CaseInsensitiveString represents a string whose semantic equality logic
// ignores letter case.
type CaseInsensitiveString struct {
	basetypes.StringValue
}

// Type returns a CaseInsensitiveStringType.
func (v CaseInsensitiveString) Type(_ context.Context) attr.Type {
	return CaseInsensitiveStringType{}
}

// Equal returns true if the given value is equivalent.
func (v CaseInsensitiveString) Equal(o attr.Value) bool {
	other, ok := o.(CaseInsensitiveString)
	if !ok {
		return false
	}

	return v.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals returns true if the given string value is equal to the
// current string value when ignoring letter case. This treats an API-normalized
// casing as equal to the configured value, preventing spurious drift.
func (v CaseInsensitiveString) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	newValue, ok := newValuable.(CaseInsensitiveString)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			"An unexpected value type was received while performing semantic equality checks. "+
				"Please report this to the provider developers.\n\n"+
				"Expected Value Type: "+fmt.Sprintf("%T", v)+"\n"+
				"Got Value Type: "+fmt.Sprintf("%T", newValuable),
		)

		return false, diags
	}

	return strings.EqualFold(v.ValueString(), newValue.ValueString()), diags
}
