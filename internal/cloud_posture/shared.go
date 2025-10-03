package cloudposture

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityInformational = "informational"
)

var (
	severityToInt32 = map[string]int32{
		SeverityCritical:      0,
		SeverityHigh:          1,
		SeverityMedium:        2,
		SeverityInformational: 3,
	}
	severityToInt64 = map[string]int64{
		SeverityCritical:      0,
		SeverityHigh:          1,
		SeverityMedium:        2,
		SeverityInformational: 3,
	}
	int32ToSeverity = map[int32]string{
		0: SeverityCritical,
		1: SeverityHigh,
		2: SeverityMedium,
		3: SeverityInformational,
	}
	int64ToSeverity = map[int64]string{
		0: SeverityCritical,
		1: SeverityHigh,
		2: SeverityMedium,
		3: SeverityInformational,
	}
)

type fqlFilters struct {
	value string
	field string
}

func convertAlertRemediationInfoToTerraformState(input *string) basetypes.ListValue {
	if input == nil {
		return basetypes.NewListValueMust(basetypes.StringType{}, []attr.Value{})
	}

	*input = strings.TrimSpace(*input)
	*input = strings.TrimSuffix(*input, "|")

	parts := strings.Split(*input, "|")
	values := make([]attr.Value, 0, len(parts))

	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(trimmed, fmt.Sprintf("Step %d. ", index+1)); ok {
			trimmed = strings.TrimSpace(after)
		} else {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, fmt.Sprintf("%d. ", index+1)))
		}
		if trimmed != "" {
			values = append(values, basetypes.NewStringValue(trimmed))
		}
	}

	return basetypes.NewListValueMust(basetypes.StringType{}, values)
}
