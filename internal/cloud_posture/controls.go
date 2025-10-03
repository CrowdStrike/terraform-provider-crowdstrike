package cloudposture

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type policyControl struct {
	Authority types.String `tfsdk:"authority"`
	Code      types.String `tfsdk:"code"`
}

func (p policyControl) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"authority": types.StringType,
		"code":      types.StringType,
	}
}
