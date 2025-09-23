package cloud_posture

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func convertAlertRemediationInfoToTerraformState(input *string) basetypes.ListValue {
	if input == nil {
		return basetypes.NewListValueMust(basetypes.StringType{}, []attr.Value{})
	}

	parts := strings.Split(*input, "|")
	values := make([]attr.Value, 0, len(parts))

	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, fmt.Sprintf("Step %d. ", index+1)) {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, fmt.Sprintf("Step %d. ", index+1)))
		} else {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, fmt.Sprintf("%d. ", index+1)))
		}
		values = append(values, basetypes.NewStringValue(trimmed))
	}

	return basetypes.NewListValueMust(basetypes.StringType{}, values)
}
