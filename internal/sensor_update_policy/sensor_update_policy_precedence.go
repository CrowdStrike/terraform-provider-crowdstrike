package sensorupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	_ resource.Resource                   = &sensorUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &sensorUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithImportState    = &sensorUpdatePolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &sensorUpdatePolicyPrecedenceResource{}
)

var (
	precedenceDocumentationSection string         = "Sensor Update Policy"
	precedenceMarkdownDescription  string         = "This resource allows you to set the precedence of Sensor Update Policies based on the order of IDs."
	precedencerequiredScopes       []scopes.Scope = []scopes.Scope{}
)

func NewSensorUpdatePolicyPrecedenceResource() resource.Resource {
	return &sensorUpdatePolicyPrecedenceResource{}
}

type sensorUpdatePolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type sensorUpdatePolicyPrecedenceResourceModel struct {
	IDs          types.List   `tfsdk:"ids"`
	PlatformName types.String `tfsdk:"platform_name"`
	LastUpdated  types.String `tfsdk:"last_updated"`
	// TODO: Define resource model
}

type BaseSetPolicyPrecedenceReqV1 struct {
	Ids          []string `json:"ids"`
	PlatformName *string  `json:"platform_name"`
}

func (d *sensorUpdatePolicyPrecedenceResourceModel) wrap(
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

func (r *sensorUpdatePolicyPrecedenceResource) Configure(
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

func (r *sensorUpdatePolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policy_precedence"
}

func (r *sensorUpdatePolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(precedenceDocumentationSection, precedenceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "That platform of the sensor update policies. (Windows, Mac, Linux)",
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

func (r *sensorUpdatePolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan sensorUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ids := utils.ListTypeAs[string](ctx, plan.IDs, &resp.Diagnostics)

	_, err := publishSensorUpdatePolicyPrecedence(r.client, ids, plan.PlatformName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating sensor update policy precedence",
			err.Error(),
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *sensorUpdatePolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {

	var state sensorUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies, diags := r.getSensorUpdatePoliciesByPrecedence(ctx, state.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(policies) > len(state.IDs.Elements()) {
		policies = policies[:len(state.IDs.Elements())+1]
	}

	resp.Diagnostics.Append(state.wrap(ctx, policies)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sensorUpdatePolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {

	var plan sensorUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	ids := utils.ListTypeAs[string](ctx, plan.IDs, &resp.Diagnostics)

	_, err := publishSensorUpdatePolicyPrecedence(r.client, ids, plan.PlatformName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating sensor update policy precedence",
			err.Error(),
		)
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sensorUpdatePolicyPrecedenceResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
}

func (r *sensorUpdatePolicyPrecedenceResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *sensorUpdatePolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config sensorUpdatePolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

func (r *sensorUpdatePolicyPrecedenceResource) getSensorUpdatePoliciesByPrecedence(
	ctx context.Context,
	platformName string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var policies []string

	caser := cases.Title(language.English)

	filter := fmt.Sprintf("platform_name:'%s'", caser.String(platformName))
	sort := "precedence.asc"
	res, err := r.client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(
		&sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)

	if err != nil {
		diags.AddError(
			"Error reading CrowdStrike sensor update policies",
			fmt.Sprintf(
				"Could not read CrowdStrike sensor update policies\n\n %s",
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

func publishSensorUpdatePolicyPrecedence(client *client.CrowdStrikeAPISpecification, ids []string, platform string) (*sensor_update_policies.SetSensorUpdatePoliciesPrecedenceOK, error) {
	precedence_request := BaseSetPolicyPrecedenceReqV1{
		Ids:          ids,
		PlatformName: &platform,
	}

	response, err := client.SensorUpdatePolicies.SetSensorUpdatePoliciesPrecedence(
		&sensor_update_policies.SetSensorUpdatePoliciesPrecedenceParams{
			Body: (*models.BaseSetPolicyPrecedenceReqV1)(&precedence_request),
		},
	)
	if err != nil {
		panic(falcon.ErrorExplain((err)))
	}
	if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
		panic(err)
	}

	return response, nil

}
