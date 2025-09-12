package cloud_posture

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func unmarshallAlertInfoToTerraformState(alertInfo string) basetypes.ListValue {
	var err error

	if alertInfo == "" {
		return basetypes.NewListValueMust(basetypes.StringType{}, []attr.Value{})
	}

	alertInfoMap := make(map[string]string)
	err = json.Unmarshal([]byte(alertInfo), &alertInfoMap)
	if err != nil {
		alertInfoList := strings.Split(alertInfo, "|")
		for i, item := range alertInfoList {
			item = strings.TrimSpace(item)
			if strings.Contains(item, ".") {
				item = strings.TrimSpace(strings.SplitN(item, ".", 2)[1])
			}
			alertInfoMap[strconv.Itoa(i+1)] = item
		}
	}

	keys := make([]string, 0, len(alertInfo))
	for k := range alertInfoMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	alertInfoSlice := make([]attr.Value, len(keys))
	for i, k := range keys {
		alertInfoSlice[i] = types.StringValue(alertInfoMap[k])
	}

	return types.ListValueMust(types.StringType, alertInfoSlice)
}
