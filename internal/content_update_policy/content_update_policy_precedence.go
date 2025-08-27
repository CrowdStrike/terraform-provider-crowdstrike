package contentupdatepolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &contentUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &contentUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &contentUpdatePolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string         = "Content Update Policy"
	precedenceMarkdownDescription  string         = "This resource allows you to set the precedence of Content Update Policies based on the order of IDs."
	precedencerequiredScopes       []scopes.Scope = []scopes.Scope{
		{
			Name:  "Content update policies",
			Read:  true,
			Write: true,
		},
	}

	dynamicEnforcement = "dynamic"
)

func NewContentUpdatePolicyPrecedenceResource() resource.Resource {
	return &contentUpdatePolicyPrecedenceResource{}
}

type contentUpdatePolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type contentUpdatePolicyPrecedenceResourceModel struct {
	IDs         types.List   `tfsdk:"ids"`
	Enforcement types.String `tfsdk:"enforcement"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

func (d *contentUpdatePolicyPrecedenceResourceModel) wrap(
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

func (r *contentUpdatePolicyPrecedenceResource) Configure(
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

func (r *contentUpdatePolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policy_precedence"
}

func (r *contentUpdatePolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(precedenceDocumentationSection, precedenceMarkdownDescription, precedencerequiredScopes),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"enforcement": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default content update policy ids to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy ids not included in `ids` will retain their current ordering after the managed ids.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *contentUpdatePolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan contentUpdatePolicyPrecedenceResourceModel
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
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setContentUpdatePolicyPrecedence(ctx, planPolicyIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *contentUpdatePolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {

	var state contentUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(state.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(state.IDs.Elements()) {
			policies = policies[:len(state.IDs.Elements())]
		}
	}

	resp.Diagnostics.Append(state.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *contentUpdatePolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {

	var plan contentUpdatePolicyPrecedenceResourceModel
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
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		planPolicyIDs = dynamicOrderedPolicyIDs
	}

	resp.Diagnostics.Append(
		r.setContentUpdatePolicyPrecedence(ctx, planPolicyIDs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getContentUpdatePoliciesByPrecedence(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(plan.Enforcement.ValueString(), dynamicEnforcement) {
		if len(policies) > len(plan.IDs.Elements()) {
			policies = policies[:len(plan.IDs.Elements())]
		}
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *contentUpdatePolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *contentUpdatePolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config contentUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

// getContentUpdatePoliciesByPrecedence retrieves all content update policies ordered by precedence.
func (r *contentUpdatePolicyPrecedenceResource) getContentUpdatePoliciesByPrecedence(
	ctx context.Context,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policies []string

	sort := "precedence.asc"
	limit := int64(5000)
	offset := int64(0)

	for {
		res, err := r.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
			&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
				Context: ctx,
				Sort:    &sort,
				Limit:   &limit,
				Offset:  &offset,
			},
		)

		if err != nil {
			diags.AddError(
				"Error reading CrowdStrike content update policies",
				fmt.Sprintf(
					"Could not read CrowdStrike content update policies\n\n %s",
					err.Error(),
				),
			)
			return policies, diags
		}

		if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
			break
		}

		for _, policy := range res.Payload.Resources {
			if policy != nil && policy.ID != nil {
				policies = append(policies, *policy.ID)
			}
		}

		if res.Payload.Meta == nil || res.Payload.Meta.Pagination == nil ||
			res.Payload.Meta.Pagination.Offset == nil || res.Payload.Meta.Pagination.Total == nil {

			tflog.Warn(ctx, "Missing pagination metadata in API response, using offset+limit for next page",
				map[string]interface{}{
					"meta": res.Payload.Meta,
				})
			offset += limit
			continue
		}

		offset = int64(*res.Payload.Meta.Pagination.Offset)
		if offset >= *res.Payload.Meta.Pagination.Total {
			break
		}
	}

	if len(policies) > 0 {
		policies = policies[:len(policies)-1]
	}

	return policies, diags
}

// generateDynamicPolicyOrder takes the dynamic managed policies and returns a slice of all policies in the correct order.
func (r *contentUpdatePolicyPrecedenceResource) generateDynamicPolicyOrder(
	ctx context.Context,
	managedPolicyIDs []string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	allPolicies, diag := r.getContentUpdatePoliciesByPrecedence(ctx)
	diags.Append(diag...)
	if diags.HasError() {
		return managedPolicyIDs, diags
	}

	missingPolicies := utils.MissingElements(managedPolicyIDs, allPolicies)
	if len(missingPolicies) > 0 {
		diags.AddAttributeError(
			path.Root("ids"),
			"Invalid policy ids provided.",
			fmt.Sprintf(
				"ids contains policy ids that do not exist, the following ids are invalid:\n\n%s",
				strings.Join(missingPolicies, "\n"),
			),
		)
	}

	for _, id := range allPolicies {
		if !slices.Contains(managedPolicyIDs, id) {
			managedPolicyIDs = append(managedPolicyIDs, id)
		}
	}

	return managedPolicyIDs, diags
}

// setContentUpdatePolicyPrecedence sets the precedence of the content update policies.
func (r *contentUpdatePolicyPrecedenceResource) setContentUpdatePolicyPrecedence(
	ctx context.Context,
	policyIDs []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := r.client.ContentUpdatePolicies.SetContentUpdatePoliciesPrecedence(
		&content_update_policies.SetContentUpdatePoliciesPrecedenceParams{
			Context: ctx,
			Body: &models.BaseSetContentUpdatePolicyPrecedenceReqV1{
				Ids: policyIDs,
			},
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			diags.AddAttributeError(
				path.Root("ids"),
				"Error setting CrowdStrike content update policies precedence",
				"One or more content update policy ids were not found. Verify all the content update policy ids provided are valid.",
			)

			return diags
		}
		diags.AddError(
			"Error setting CrowdStrike content update policies precedence",
			fmt.Sprintf(
				"Could not set CrowdStrike content update policies precedence\n\n %s",
				err.Error(),
			),
		)
		return diags
	}

	return diags
}
