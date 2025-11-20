package contentupdatepolicy

import (
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
)

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "content-update-policies",
		Read:  true,
		Write: false,
	},
}
