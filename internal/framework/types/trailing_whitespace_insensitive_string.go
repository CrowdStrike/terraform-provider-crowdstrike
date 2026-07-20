package types

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ basetypes.StringTypable                    = (*TrailingWhitespaceInsensitiveStringType)(nil)
	_ basetypes.StringValuableWithSemanticEquals = (*TrailingWhitespaceInsensitiveString)(nil)
)

// TrailingWhitespaceInsensitiveStringType is an attribute type that treats two strings as
// semantically equal when they differ only by trailing whitespace characters. This handles
// all Unicode whitespace characters including spaces, tabs, newlines, carriage returns,
// vertical tabs, form feeds, non-breaking spaces, and other Unicode whitespace. This prevents
// Terraform data consistency errors when the API strips trailing whitespace from a field.
type TrailingWhitespaceInsensitiveStringType struct {
	basetypes.StringType
}

// String returns a human-readable string of the type name.
func (t TrailingWhitespaceInsensitiveStringType) String() string {
	return "types.TrailingWhitespaceInsensitiveStringType"
}

// ValueType returns the Value type.
func (t TrailingWhitespaceInsensitiveStringType) ValueType(ctx context.Context) attr.Value {
	return TrailingWhitespaceInsensitiveString{}
}

// Equal returns true if the given type is equivalent.
func (t TrailingWhitespaceInsensitiveStringType) Equal(o attr.Type) bool {
	other, ok := o.(TrailingWhitespaceInsensitiveStringType)
	if !ok {
		return false
	}

	return t.StringType.Equal(other.StringType)
}

// ValueFromString returns a StringValuable type given a StringValue.
func (t TrailingWhitespaceInsensitiveStringType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return TrailingWhitespaceInsensitiveString{
		StringValue: in,
	}, nil
}

// ValueFromTerraform returns a Value given a tftypes.Value.
func (t TrailingWhitespaceInsensitiveStringType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
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

// TrailingWhitespaceInsensitiveString represents a string whose semantic equality logic
// ignores trailing whitespace characters.
type TrailingWhitespaceInsensitiveString struct {
	basetypes.StringValue
}

// Type returns a TrailingWhitespaceInsensitiveStringType.
func (v TrailingWhitespaceInsensitiveString) Type(_ context.Context) attr.Type {
	return TrailingWhitespaceInsensitiveStringType{}
}

// Equal returns true if the given value is equivalent.
func (v TrailingWhitespaceInsensitiveString) Equal(o attr.Value) bool {
	other, ok := o.(TrailingWhitespaceInsensitiveString)
	if !ok {
		return false
	}

	return v.StringValue.Equal(other.StringValue)
}

// StringSemanticEquals returns true if the given string value is equal to the
// current string value when ignoring all trailing whitespace (all Unicode whitespace
// characters). This treats an API-normalized value (with trailing whitespace stripped)
// as equal to the configured value, preventing spurious drift.
func (v TrailingWhitespaceInsensitiveString) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	newValue, ok := newValuable.(TrailingWhitespaceInsensitiveString)
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

	currentTrimmed := strings.TrimRightFunc(v.ValueString(), unicode.IsSpace)
	newTrimmed := strings.TrimRightFunc(newValue.ValueString(), unicode.IsSpace)

	return currentTrimmed == newTrimmed, diags
}
