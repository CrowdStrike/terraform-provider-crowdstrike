package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ validator.List = listObjectUniqueStringValidator{}

type listObjectUniqueStringValidator struct {
	attributeName string
}

func (v listObjectUniqueStringValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("ensures each object in the list has a unique value for the '%s' attribute", v.attributeName)
}

func (v listObjectUniqueStringValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("ensures each object in the list has a unique value for the `%s` attribute", v.attributeName)
}

func (v listObjectUniqueStringValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if !utils.IsKnown(req.ConfigValue) {
		return
	}

	elements := req.ConfigValue.Elements()
	valueIndices := make(map[string][]int)

	for i, elem := range elements {
		obj, ok := elem.(types.Object)
		if !ok {
			continue
		}

		attrs := obj.Attributes()
		attrValue, ok := attrs[v.attributeName]
		if !ok {
			continue
		}

		strValue, ok := attrValue.(types.String)
		if !ok {
			continue
		}

		if !utils.IsKnown(strValue) {
			continue
		}

		value := strValue.ValueString()
		valueIndices[value] = append(valueIndices[value], i)
	}

	var duplicates []string
	for value, indices := range valueIndices {
		if len(indices) > 1 {
			duplicates = append(duplicates, fmt.Sprintf("'%s' at indices %v", value, indices))
		}
	}

	if len(duplicates) > 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			fmt.Sprintf("Duplicate %s Values", v.attributeName),
			fmt.Sprintf("Found duplicate %s values: %s. Each %s must be unique.", v.attributeName, strings.Join(duplicates, ", "), v.attributeName),
		)
	}
}

// ListObjectUniqueString returns a validator that ensures each object in a list
// has a unique value for the specified string attribute.
//
// This validator is designed for lists of objects where you need to ensure that
// a particular string field is unique across all objects. For example, when validating
// a list of image objects where each object has a "registry" string attribute, this
// validator ensures that no two objects have the same registry value.
//
// attributeName: The name of the string attribute to check for uniqueness across all objects in the list.
func ListObjectUniqueString(attributeName string) validator.List {
	return listObjectUniqueStringValidator{
		attributeName: attributeName,
	}
}
