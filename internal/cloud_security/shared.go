package cloudsecurity

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityInformational = "informational"
)

var (
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
	severityToString = map[string]string{
		SeverityCritical:      "0",
		SeverityHigh:          "1",
		SeverityMedium:        "2",
		SeverityInformational: "3",
	}
	stringToSeverity = map[string]string{
		"0": SeverityCritical,
		"1": SeverityHigh,
		"2": SeverityMedium,
		"3": SeverityInformational,
	}
	suppressionRuleSubdomainDefault = "IOM"
	suppressionRuleDomainDefault    = "CSPM"
	suppressionRuleReasonValues     = []string{
		"accept-risk",
		"compensating-control",
		"false-positive",
	}
	ruleSeverityValues = []string{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityInformational,
	}
	ruleOriginValues = []string{
		"Custom",
		"Default",
	}
)

func convertAlertRemediationInfoToTerraformState(input *string) basetypes.ListValue {
	if input == nil || *input == "" {
		return types.ListValueMust(types.StringType, []attr.Value{})
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
			values = append(values, types.StringValue(trimmed))
		}
	}

	return types.ListValueMust(types.StringType, values)
}

// GetPageLimit returns the page limit for API requests. It checks the TF_CROWDSTRIKE_PAGE_LIMIT
// environment variable and falls back to 100 if not set or invalid.
func GetPageLimit() int64 {
	if envLimit := os.Getenv("TF_CROWDSTRIKE_PAGE_LIMIT"); envLimit != "" {
		if limit, err := strconv.ParseInt(envLimit, 10, 64); err == nil && limit > 0 {
			return limit
		}
	}
	return 100
}
