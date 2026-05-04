package iocindicator

import (
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Export for testing.
var BuildUpdateExpiration = buildUpdateExpiration

// SuppressExpiredActionDrift wraps suppressExpiredActionDrift for tests in the
// external package. Callers pass the planned and actual (post-wrap) values;
// the returned strings are what state would carry after suppression.
func SuppressExpiredActionDrift(
	expiration timetypes.RFC3339,
	plannedAction, plannedMobileAction types.String,
	actualAction, actualMobileAction types.String,
) (types.String, types.String, diag.Diagnostics) {
	r := &iocIndicatorResource{}
	m := &iocIndicatorResourceModel{
		Action:       actualAction,
		MobileAction: actualMobileAction,
	}
	var diags diag.Diagnostics
	r.suppressExpiredActionDrift(expiration, plannedAction, plannedMobileAction, m, &diags)
	return m.Action, m.MobileAction, diags
}
