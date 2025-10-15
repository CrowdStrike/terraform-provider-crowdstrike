package itautomation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &itAutomationPolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &itAutomationPolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationPolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string         = "IT Automation"
	precedenceMarkdownDescription  string         = "IT Automation policy precedence --- This resource allows you to set the precedence of IT Automation policies based on the order of policy IDs."
	precedenceRequiredScopes       []scopes.Scope = itAutomationScopes
)

const (
	strictEnforcement  = "strict"
	dynamicEnforcement = "dynamic"
)

// NewItAutomationPolicyPrecedenceResource is a helper function to simplify the provider implementation.
func NewItAutomationPolicyPrecedenceResource() resource.Resource {
	return &itAutomationPolicyPrecedenceResource{}
}

// itAutomationPolicyPrecedenceResource is the resource implementation.
type itAutomationPolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

// itAutomationPolicyPrecedenceResourceModel is the resource model.
type itAutomationPolicyPrecedenceResourceModel struct {
	ID          types.String `tfsdk:"id"`
	IDs         types.List   `tfsdk:"ids"`
	Enforcement types.String `tfsdk:"enforcement"`
	LastUpdated types.String `tfsdk:"last_updated"`
	Platform    types.String `tfsdk:"platform"`
}

func (d *itAutomationPolicyPrecedenceResourceModel) wrap(
	ctx context.Context,
	policies []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	policyList, diag := types.ListValueFrom(ctx, types.StringType, policies)
	diags.Append(diag...)
	if diags.HasError() {
		return diags
	}

	d.IDs = policyList

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *itAutomationPolicyPrecedenceResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *itAutomationPolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_policy_precedence"
}

// Schema defines the schema for the resource.
func (r *itAutomationPolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(precedenceDocumentationSection, precedenceMarkdownDescription, precedenceRequiredScopes),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for this precedence resource. Based on platform to ensure one precedence resource per platform.",
			},
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy IDs in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"enforcement": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all policy IDs for the platform to be specified. `dynamic` allows managing a subset of policies with precedence over unmanaged policies.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(strictEnforcement, dynamicEnforcement),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "The platform of the IT automation policies (Windows, Linux, Mac).",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Linux", "Mac"),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *itAutomationPolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planPolicyIDs []string
	resp.Diagnostics.Append(plan.IDs.ElementsAs(ctx, &planPolicyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		dynamicOrderedPolicyIDs, diags := r.generateDynamicPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	} else if strings.EqualFold(plan.Enforcement.ValueString(), strictEnforcement) {
		strictOrderedPolicyIDs, diags := r.generateStrictPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = strictOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setItAutomationPolicyPrecedence(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, policies, diags := getItAutomationPolicies(
		ctx,
		r.client,
		plan.Platform.ValueString(),
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) &&
		len(policies) > len(plan.IDs.Elements()) {
		policies = policies[:len(plan.IDs.Elements())]
	}

	plan.ID = types.StringValue(
		fmt.Sprintf("it_automation_policy_precedence_%s",
			strings.ToLower(plan.Platform.ValueString()),
		),
	)
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))
	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *itAutomationPolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, policies, diags := getItAutomationPolicies(
		ctx,
		r.client,
		state.Platform.ValueString(),
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(state.Enforcement.ValueString(), dynamicEnforcement) &&
		len(policies) > len(state.IDs.Elements()) {
		policies = policies[:len(state.IDs.Elements())]
	}

	resp.Diagnostics.Append(state.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *itAutomationPolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planPolicyIDs []string
	resp.Diagnostics.Append(plan.IDs.ElementsAs(ctx, &planPolicyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		dynamicOrderedPolicyIDs, diags := r.generateDynamicPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	} else if strings.EqualFold(plan.Enforcement.ValueString(), strictEnforcement) {
		strictOrderedPolicyIDs, diags := r.generateStrictPolicyOrder(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = strictOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setItAutomationPolicyPrecedence(
			ctx,
			planPolicyIDs,
			plan.Platform.ValueString(),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, policies, diags := getItAutomationPolicies(
		ctx,
		r.client,
		plan.Platform.ValueString(),
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) &&
		len(policies) > len(plan.IDs.Elements()) {
		policies = policies[:len(plan.IDs.Elements())]
	}

	plan.ID = types.StringValue(fmt.Sprintf(
		"it_automation_policy_precedence_%s",
		strings.ToLower(plan.Platform.ValueString())))
	plan.LastUpdated = types.StringValue(time.Now().Format(timeFormat))

	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *itAutomationPolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

// ValidateConfig validates the resource configuration.
func (r *itAutomationPolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config itAutomationPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.IDs.IsUnknown() || config.Enforcement.IsUnknown() || config.Platform.IsUnknown() {
		return
	}

	if config.IDs.IsNull() {
		return
	}
}

// setItAutomationPolicyPrecedence sets the precedence order for policies.
func (r *itAutomationPolicyPrecedenceResource) setItAutomationPolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
	platform string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	body := &models.ItautomationUpdatePoliciesPrecedenceRequest{
		Ids: policyIDs,
	}

	params := &it_automation.ITAutomationUpdatePoliciesPrecedenceParams{
		Context:  ctx,
		Body:     body,
		Platform: platform,
	}

	_, err := r.client.ItAutomation.ITAutomationUpdatePoliciesPrecedence(params)
	if err != nil {
		diags.AddError(
			"Error updating IT automation policy precedence",
			fmt.Sprintf("Could not update policy precedence: %s", err.Error()),
		)
	}

	return diags
}

// generateDynamicPolicyOrder creates the policy order for dynamic enforcement mode.
func (r *itAutomationPolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
	platform string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	_, currentPrecedence, policyDiags := getItAutomationPolicies(ctx, r.client, platform)
	diags.Append(policyDiags...)
	if diags.HasError() {
		return nil, diags
	}

	managedPolicyMap := make(map[string]bool)
	for _, policyID := range managedPolicyIDs {
		managedPolicyMap[policyID] = true
	}

	var finalOrder []string
	finalOrder = append(finalOrder, managedPolicyIDs...)
	for _, policyID := range currentPrecedence {
		if !managedPolicyMap[policyID] {
			finalOrder = append(finalOrder, policyID)
		}
	}

	return finalOrder, diags
}

// generateStrictPolicyOrder validates that all policies are specified for strict enforcement.
func (r *itAutomationPolicyPrecedenceResource) generateStrictPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
	platform string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	_, currentPrecedence, policyDiags := getItAutomationPolicies(ctx, r.client, platform)
	diags.Append(policyDiags...)
	if diags.HasError() {
		return nil, diags
	}

	// strict mode requires all policies for the platform to be specified.
	if len(managedPolicyIDs) != len(currentPrecedence) {
		managedPolicyMap := make(map[string]bool)
		for _, policyID := range managedPolicyIDs {
			managedPolicyMap[policyID] = true
		}

		var missingPolicyIDs []string
		for _, policyID := range currentPrecedence {
			if !managedPolicyMap[policyID] {
				missingPolicyIDs = append(missingPolicyIDs, policyID)
			}
		}

		diags.AddError(
			"Strict enforcement validation failed",
			fmt.Sprintf(
				"Strict enforcement requires all policy IDs for the platform to be specified. Missing policy IDs: %s",
				strings.Join(missingPolicyIDs, ", "),
			),
		)
		return nil, diags
	}

	return managedPolicyIDs, diags
}
