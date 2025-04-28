package preventionpolicy

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	_ resource.Resource                   = &preventionPolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyPrecedenceResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string         = "Prevention Policy"
	precedenceMarkdownDescription  string         = "This resource allows you set the precedence of Prevention Policies based on the order of IDs."
	precedenceRequiredScopes       []scopes.Scope = apiScopes

	dynamicEnforcment = "dynamic"
	strictEnforcement = "strict"
)

func NewPreventionPolicyPrecedenceResource() resource.Resource {
	return &preventionPolicyPrecedenceResource{}
}

type preventionPolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type preventionPolicyPrecedenceResourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	Enforcement  types.String `tfsdk:"enforcement"`
	PlatformName types.String `tfsdk:"platform_name"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

func (d *preventionPolicyPrecedenceResourceModel) wrap(
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

func (r *preventionPolicyPrecedenceResource) Configure(
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

func (r *preventionPolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_precedence"
}

func (r *preventionPolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			precedenceDocumentationSection,
			precedenceMarkdownDescription,
			precedenceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
			},
			"enforcement": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The enforcement type for this resource. `strict` requires all non-default prevention policy ids for platform to be provided. `dynamic` will ensure the provided policies have precedence over others. Policies not included in `ids` will retain their current order.",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("strict", "dynamic"),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "That platform of the prevention policies. (Windows, Mac, Linux)",
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

func (r *preventionPolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *preventionPolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getPreventionPoliciesByPrecedence(ctx, state.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if strings.EqualFold(state.Enforcement.ValueString(), dynamicEnforcment) {
		if len(policies) > len(state.IDs.Elements()) {
			policies = policies[:len(state.IDs.Elements())+1]
		}
	}

	resp.Diagnostics.Append(state.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *preventionPolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var newState preventionPolicyPrecedenceResourceModel

	var plan preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *preventionPolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *preventionPolicyPrecedenceResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *preventionPolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config preventionPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

func (r *preventionPolicyPrecedenceResource) getPreventionPoliciesByPrecedence(
	ctx context.Context,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policies []string

	caser := cases.Title(language.English)

	filter := fmt.Sprintf("platform_name:'%s'", caser.String(platformName))
	sort := "precedence.asc"
	res, err := r.client.PreventionPolicies.QueryCombinedPreventionPolicies(
		&prevention_policies.QueryCombinedPreventionPoliciesParams{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)

	if err != nil {
		diags.AddError(
			"Error reading CrowdStrike prevention policies",
			fmt.Sprintf(
				"Could not read CrowdStrike prevention policies\n\n %s",
				err.Error(),
			),
		)
		return policies, diags
	}

	if res != nil && res.Payload != nil {
		for _, policy := range res.Payload.Resources {
			policies = append(policies, *policy.ID)
		}
	}

	return policies, diags
}
