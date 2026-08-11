package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ validator.Set = setJoinedLengthAtMostValidator{}

type setJoinedLengthAtMostValidator struct {
	separator string
	maxLength int
}

func (v setJoinedLengthAtMostValidator) Description(ctx context.Context) string {
	return fmt.Sprintf(
		"ensures the elements joined with %q are at most %d characters",
		v.separator, v.maxLength,
	)
}

func (v setJoinedLengthAtMostValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf(
		"ensures the elements joined with `%s` are at most %d characters",
		v.separator, v.maxLength,
	)
}

func (v setJoinedLengthAtMostValidator) ValidateSet(
	ctx context.Context,
	req validator.SetRequest,
	resp *validator.SetResponse,
) {
	if !utils.IsKnown(req.ConfigValue) {
		return
	}

	// Elements copies the internal slice on every call, so it is read once.
	configElements := req.ConfigValue.Elements()

	elements := make([]string, 0, len(configElements))
	for _, element := range configElements {
		value, ok := element.(types.String)
		if !ok {
			return
		}

		// The join cannot be computed while any element is unknown. The value is
		// re-validated at apply, when every element is resolved.
		if !utils.IsKnown(value) {
			return
		}

		elements = append(elements, value.ValueString())
	}

	joined := strings.Join(elements, v.separator)
	if len(joined) <= v.maxLength {
		return
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Joined value too long",
		fmt.Sprintf(
			"The %d elements of %s are serialized as a single %q-separated value, and that value is "+
				"bounded rather than any one element. Joined it is %d characters, above the maximum of "+
				"%d. No single element is at fault; remove elements or shorten several of them.",
			len(elements), req.Path, v.separator, len(joined), v.maxLength,
		),
	)
}

// SetJoinedLengthAtMost validates that the set's elements, joined with separator,
// are at most maxLength characters.
//
// For an attribute the provider serializes as a single delimited string, the API's
// limit applies to the joined value rather than to any one element. A per-element
// length check is the wrong bound: it accepts any number of short elements whose
// join overruns the limit, which is the case the API actually rejects.
//
// Null and unknown sets are skipped, as are sets containing an unknown element,
// because the join cannot be computed until every element is known.
func SetJoinedLengthAtMost(separator string, maxLength int) validator.Set {
	return setJoinedLengthAtMostValidator{separator: separator, maxLength: maxLength}
}
