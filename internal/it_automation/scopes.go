package itautomation

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var itAutomationScopes = []scopes.Scope{
	{
		Name:  "IT Automation - Policies",
		Read:  true,
		Write: true,
	},
	{
		Name:  "IT Automation - Task Executions",
		Read:  true,
		Write: true,
	},
	{
		Name:  "IT Automation - Tasks",
		Read:  true,
		Write: true,
	},
	{
		Name:  "IT Automation - User Groups",
		Read:  true,
		Write: true,
	},
}
