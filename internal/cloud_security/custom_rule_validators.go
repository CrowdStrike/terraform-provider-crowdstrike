package cloudsecurity

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Custom validator to ensure resource_type and rule_provider are required when domain is CSPM and subdomain is IOM
type resourceTypeRequiredForCSPMValidator struct{}

func (v resourceTypeRequiredForCSPMValidator) Description(ctx context.Context) string {
	return "resource_type and rule_provider are required when domain is 'CSPM' and subdomain is 'IOM'"
}

func (v resourceTypeRequiredForCSPMValidator) MarkdownDescription(ctx context.Context) string {
	return "resource_type and rule_provider are required when domain is 'CSPM' and subdomain is 'IOM'"
}

func (v resourceTypeRequiredForCSPMValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config cloudSecurityCustomRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get domain value - use default if not explicitly set
	domainValue := DefaultDomain
	if !config.Domain.IsNull() && !config.Domain.IsUnknown() {
		domainValue = config.Domain.ValueString()
	}

	// Get subdomain value - use default if not explicitly set
	subdomainValue := DefaultSubdomain
	if !config.Subdomain.IsNull() && !config.Subdomain.IsUnknown() {
		subdomainValue = config.Subdomain.ValueString()
	}

	// Check if domain is CSPM and subdomain is IOM (considering defaults)
	if domainValue == "CSPM" && subdomainValue == "IOM" {
		// Check resource_type
		if config.ResourceType.IsNull() || config.ResourceType.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("resource_type"),
				"Missing required attribute",
				"resource_type is required when domain is 'CSPM' and subdomain is 'IOM'",
			)
		}

		// Check rule_provider (new field) or cloud_provider (deprecated field)
		ruleProviderValue := config.RuleProvider.ValueString()
		cloudProviderValue := config.CloudProvider.ValueString()

		// If neither field is set, add an error
		if (config.RuleProvider.IsNull() || ruleProviderValue == "") && (config.CloudProvider.IsNull() || cloudProviderValue == "") {
			resp.Diagnostics.AddAttributeError(
				path.Root("rule_provider"),
				"Missing required attribute",
				"rule_provider (or deprecated cloud_provider) is required when domain is 'CSPM' and subdomain is 'IOM'",
			)
		}
	}
}

// Custom validator to disable certain fields when domain is Runtime and subdomain is IOM
type runtimeIOMFieldsDisabledValidator struct{}

func (v runtimeIOMFieldsDisabledValidator) Description(ctx context.Context) string {
	return "alert_info, controls, attack_types, parent_rule_id, remediation_info, and resource_type are not allowed when domain is 'Runtime' and subdomain is 'IOM'"
}

func (v runtimeIOMFieldsDisabledValidator) MarkdownDescription(ctx context.Context) string {
	return "alert_info, controls, attack_types, parent_rule_id, remediation_info, and resource_type are not allowed when domain is 'Runtime' and subdomain is 'IOM'"
}

func (v runtimeIOMFieldsDisabledValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config cloudSecurityCustomRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get domain value - use default if not explicitly set
	domainValue := DefaultDomain
	if !config.Domain.IsNull() && !config.Domain.IsUnknown() {
		domainValue = config.Domain.ValueString()
	}

	// Get subdomain value - use default if not explicitly set
	subdomainValue := DefaultSubdomain
	if !config.Subdomain.IsNull() && !config.Subdomain.IsUnknown() {
		subdomainValue = config.Subdomain.ValueString()
	}

	// Check if domain is Runtime and subdomain is IOM
	if domainValue == "Runtime" && subdomainValue == "IOM" {
		// Check alert_info
		if !config.AlertInfo.IsNull() && !config.AlertInfo.IsUnknown() && len(config.AlertInfo.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("alert_info"),
				"Invalid attribute configuration",
				"alert_info is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}

		// Check controls
		if !config.Controls.IsNull() && !config.Controls.IsUnknown() && len(config.Controls.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("controls"),
				"Invalid attribute configuration",
				"controls is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}

		// Check attack_types
		if !config.AttackTypes.IsNull() && !config.AttackTypes.IsUnknown() && len(config.AttackTypes.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("attack_types"),
				"Invalid attribute configuration",
				"attack_types is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}

		// Check parent_rule_id
		if !config.ParentRuleId.IsNull() && !config.ParentRuleId.IsUnknown() && config.ParentRuleId.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("parent_rule_id"),
				"Invalid attribute configuration",
				"parent_rule_id is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}

		// Check remediation_info
		if !config.RemediationInfo.IsNull() && !config.RemediationInfo.IsUnknown() && len(config.RemediationInfo.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("remediation_info"),
				"Invalid attribute configuration",
				"remediation_info is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}

		// Check resource_type
		if !config.ResourceType.IsNull() && !config.ResourceType.IsUnknown() && config.ResourceType.ValueString() != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("resource_type"),
				"Invalid attribute configuration",
				"resource_type is not allowed when domain is 'Runtime' and subdomain is 'IOM'",
			)
		}
	}
}

// Custom plan modifier to set Kubernetes as default when domain is Runtime
type kubernetesDefaultForRuntimeModifier struct{}

func (m kubernetesDefaultForRuntimeModifier) Description(ctx context.Context) string {
	return "Sets default value to 'Kubernetes' when domain is 'Runtime'"
}

func (m kubernetesDefaultForRuntimeModifier) MarkdownDescription(ctx context.Context) string {
	return "Sets default value to 'Kubernetes' when domain is 'Runtime'"
}

func (m kubernetesDefaultForRuntimeModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Don't modify if config value is explicitly set (user provided a value)
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() {
		return
	}

	// Don't modify if plan value is already set to a non-empty value
	if !req.PlanValue.IsNull() && !req.PlanValue.IsUnknown() && req.PlanValue.ValueString() != "" {
		return
	}

	// Get the domain and subdomain values from the plan, considering defaults
	var domain, subdomain types.String
	req.Plan.GetAttribute(ctx, path.Root("domain"), &domain)
	req.Plan.GetAttribute(ctx, path.Root("subdomain"), &subdomain)

	// Use default values if not explicitly set
	domainValue := DefaultDomain
	if !domain.IsNull() && !domain.IsUnknown() {
		domainValue = domain.ValueString()
	}

	subdomainValue := DefaultSubdomain
	if !subdomain.IsNull() && !subdomain.IsUnknown() {
		subdomainValue = subdomain.ValueString()
	}

	// Don't set defaults if domain is CSPM and subdomain is IOM - these fields are required
	// and should be validated by the custom validator
	if domainValue == "CSPM" && subdomainValue == "IOM" {
		return
	}

	// If domain is Runtime, set default to Kubernetes
	if domainValue == "Runtime" {
		resp.PlanValue = types.StringValue("Kubernetes")
	}
}

// Custom plan modifier to prevent "known after apply" for required fields
type requireWhenCSPMIOMModifier struct{}

func (m requireWhenCSPMIOMModifier) Description(ctx context.Context) string {
	return "Prevents 'known after apply' for fields required when domain is 'CSPM' and subdomain is 'IOM'"
}

func (m requireWhenCSPMIOMModifier) MarkdownDescription(ctx context.Context) string {
	return "Prevents 'known after apply' for fields required when domain is 'CSPM' and subdomain is 'IOM'"
}

func (m requireWhenCSPMIOMModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Get the domain and subdomain values from the plan, considering defaults
	var domain, subdomain types.String
	req.Plan.GetAttribute(ctx, path.Root("domain"), &domain)
	req.Plan.GetAttribute(ctx, path.Root("subdomain"), &subdomain)

	// Use default values if not explicitly set
	domainValue := DefaultDomain
	if !domain.IsNull() && !domain.IsUnknown() {
		domainValue = domain.ValueString()
	}

	subdomainValue := DefaultSubdomain
	if !subdomain.IsNull() && !subdomain.IsUnknown() {
		subdomainValue = subdomain.ValueString()
	}

	// If domain is CSPM and subdomain is IOM, and no config value is provided,
	// set plan value to null so validation will catch it
	if domainValue == "CSPM" && subdomainValue == "IOM" {
		if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
			resp.PlanValue = types.StringNull()
		}
	}
}

// KubernetesDefaultForRuntime returns a plan modifier that sets Kubernetes as default for Runtime domain
func KubernetesDefaultForRuntime() planmodifier.String {
	return kubernetesDefaultForRuntimeModifier{}
}

// RequireWhenCSPMIOM returns a plan modifier that prevents "known after apply" for required fields
func RequireWhenCSPMIOM() planmodifier.String {
	return requireWhenCSPMIOMModifier{}
}
