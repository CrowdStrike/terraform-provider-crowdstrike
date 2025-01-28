package fcs

import (
	"context"
	"fmt"
	"regexp"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type cloudAWSAccountResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudProduct struct {
	Product  types.String `tfsdk:"product"`
	Features types.Set    `tfsdk:"features"`
}
type cloudAWSAccountModel struct {
	AccountID              types.String `tfsdk:"account_id"`
	OrganizationID         types.String `tfsdk:"organization_id"`
	IsOrgManagementAccount types.Bool   `tfsdk:"is_organization_management_account"`
	AccountType            types.String `tfsdk:"account_type"`
	CSPEvents              types.Bool   `tfsdk:"csp_events"`
	Products               types.Set    `tfsdk:"products"`
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &cloudAWSAccountResource{}
	_ resource.ResourceWithConfigure      = &cloudAWSAccountResource{}
	_ resource.ResourceWithImportState    = &cloudAWSAccountResource{}
	_ resource.ResourceWithValidateConfig = &cloudAWSAccountResource{}
)

// NewCloudAWSAccountResource a helper function to simplify the provider implementation.
func NewCloudAWSAccountResource() resource.Resource {
	return &cloudAWSAccountResource{}
}

// Metadata returns the resource type name.
func (r *cloudAWSAccountResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_aws_account"
}

// Schema defines the schema for the resource.
func (r *cloudAWSAccountResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"FCS AWS Account --- This resource allows management of a CSPM Account. A FileVantage policy is a collection of file integrity rules and rule groups that you can apply to host groups.\n\n%s",
			scopes.GenerateScopeDescription(fcsScopes),
		),
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "The AWS Account ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(12, 12),
					stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9]+$`), "must be exactly 12 digits"),
				},
			},
			"organization_id": schema.StringAttribute{
				Optional:    true,
				Description: "The AWS Organization ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(12, 34),
					stringvalidator.RegexMatches(regexp.MustCompile(`^o-[a-z0-9]{10,32}$`), "must be in the format of o-xxxxxxxxxx"),
				},
			},
			"is_organization_management_account": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Indicates whether this is the management account (formerly known as the root account) of an AWS Organization",
			},
			"account_type": schema.StringAttribute{
				Optional:    true,
				Default:     stringdefault.StaticString("commercial"),
				Computed:    true,
				Description: "The type of account. Not needed for non-govcloud environment",
				Validators: []validator.String{
					stringvalidator.OneOf("commercial", "gov"),
				},
			},
			"csp_events": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
				Description: "Indicates whether Cloud Service Provider live events are enabled",
			},
			"products": schema.SetNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The list of products to enable for this account",
				Default: setdefault.StaticValue(types.SetValueMust(types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"product":  types.StringType,
						"features": types.SetType{ElemType: types.StringType},
					},
				}, []attr.Value{})),

				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"product": schema.StringAttribute{
							Required: true,
						},
						"features": schema.SetAttribute{
							Required:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *cloudAWSAccountResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudAWSAccountModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	account, diags := r.createAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "fcs cloud registration account created", map[string]interface{}{"account": account})

	plan.AccountID = types.StringValue(account.AccountID)
	if account.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(account.OrganizationID)
	}
	plan.AccountType = types.StringValue(account.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
	plan.CSPEvents = types.BoolValue(account.CspEvents)
	if len(account.Products) > 0 {
		products, d := productsToState(ctx, account.Products)
		if d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
		plan.Products = products
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func extractProducts(ctx context.Context, set types.Set) ([]*models.RestAccountProductUpsertRequestExtV1, diag.Diagnostics) {
	var products []cloudProduct
	diags := set.ElementsAs(ctx, &products, false)
	if diags.HasError() {
		return nil, diags
	}
	var rest []*models.RestAccountProductUpsertRequestExtV1
	for _, v := range products {
		name := v.Product.ValueString()

		var features []string
		diags := v.Features.ElementsAs(ctx, &features, false)
		if diags.HasError() {
			return nil, diags
		}
		rest = append(rest, &models.RestAccountProductUpsertRequestExtV1{
			Product:  &name,
			Features: features,
		})
	}
	return rest, diags
}

// createAccount creates a new Cloud AWS account from the resource model.
func (r *cloudAWSAccountResource) createAccount(
	ctx context.Context,
	config cloudAWSAccountModel,
) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	products, diags := extractProducts(ctx, config.Products)
	if diags.HasError() {
		return nil, diags
	}
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsCreateAccount(&cloud_aws_registration.CloudRegistrationAwsCreateAccountParams{
		Context: ctx,
		Body: &models.RestAWSAccountCreateRequestExtv1{
			Resources: []*models.RestCloudAWSAccountCreateExtV1{
				{
					AccountID:      config.AccountID.ValueString(),
					OrganizationID: config.OrganizationID.ValueStringPointer(),
					IsMaster:       config.IsOrgManagementAccount.ValueBool(),
					AccountType:    config.AccountType.ValueString(),
					CspEvents:      config.CSPEvents.ValueBool(),
					Products:       products,
				},
			},
		},
	})
	if err != nil {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			fmt.Sprintf("Failed to create Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			fmt.Sprintf("Failed to create Cloud Registration AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to create Cloud Registration AWS account",
			"No error returned from api but Cloud Registration account was not created. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func productsToState(ctx context.Context, apiProducts []*models.DomainProductFeatures) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	products := make([]cloudProduct, 0, len(apiProducts))
	for _, apiProduct := range apiProducts {
		feature, d := types.SetValueFrom(ctx, types.StringType, apiProduct.Features)
		if d.HasError() {
			diags.Append(d...)
			return types.SetNull(types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"product":  types.StringType,
					"features": types.SetType{ElemType: types.StringType},
				},
			}), diags
		}

		product := cloudProduct{
			Product:  types.StringValue(*apiProduct.Product),
			Features: feature,
		}
		products = append(products, product)
	}

	// convert the slice of products to types.Set
	productsSet, d := types.SetValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"product":  types.StringType,
			"features": types.SetType{ElemType: types.StringType},
		},
	}, products)
	if d.HasError() {
		diags.Append(d...)
		return types.SetNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"product":  types.StringType,
				"features": types.SetType{ElemType: types.StringType},
			},
		}), diags
	}

	return productsSet, diags
}

// Read refreshes the Terraform state with the latest data.
func (r *cloudAWSAccountResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudAWSAccountModel
	var oldState cloudAWSAccountModel
	diags := req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.AccountID.ValueString() == "" {
		return
	}
	account, diags := r.getAccount(ctx, oldState.AccountID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if account != nil {
		state.AccountID = types.StringValue(account.AccountID)
		if account.OrganizationID != "" {
			state.OrganizationID = types.StringValue(account.OrganizationID)
		}
		state.AccountType = types.StringValue(account.AccountType)
		state.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
		state.CSPEvents = types.BoolValue(account.CspEvents)
		if len(account.Products) > 0 {
			products, d := productsToState(ctx, account.Products)
			if d.HasError() {
				resp.Diagnostics.Append(d...)
				return
			}
			state.Products = products
		} else {
			state.Products = oldState.Products
		}
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudAWSAccountResource) getAccount(
	ctx context.Context,
	accountID string,
) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsGetAccounts(&cloud_aws_registration.CloudRegistrationAwsGetAccountsParams{
		Context: ctx,
		Ids:     []string{accountID},
	})
	if err != nil {
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf("Failed to read Cloud Registration AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			fmt.Sprintf("Failed to read Cloud Registration AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to read Cloud Registration AWS account",
			"No error returned from api but Cloud Registration account was not returned. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *cloudAWSAccountResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan cloudAWSAccountModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state cloudAWSAccountModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	account, diags := r.updateAccount(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.AccountID = types.StringValue(account.AccountID)
	if account.OrganizationID != "" {
		plan.OrganizationID = types.StringValue(account.OrganizationID)
	}
	plan.AccountType = types.StringValue(account.AccountType)
	plan.IsOrgManagementAccount = types.BoolValue(account.IsMaster)
	plan.CSPEvents = types.BoolValue(account.CspEvents)
	if len(account.Products) > 0 {
		products, d := productsToState(ctx, account.Products)
		if d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
		plan.Products = products
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudAWSAccountResource) updateAccount(
	ctx context.Context,
	account cloudAWSAccountModel,
) (*models.DomainCloudAWSAccountV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	products, diags := extractProducts(ctx, account.Products)
	if diags.HasError() {
		return nil, diags
	}
	res, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsUpdateAccount(&cloud_aws_registration.CloudRegistrationAwsUpdateAccountParams{
		Context: ctx,
		Body: &models.RestAWSAccountCreateRequestExtv1{
			Resources: []*models.RestCloudAWSAccountCreateExtV1{
				{
					AccountID:      account.AccountID.ValueString(),
					OrganizationID: account.OrganizationID.ValueStringPointer(),
					IsMaster:       account.IsOrgManagementAccount.ValueBool(),
					AccountType:    account.AccountType.ValueString(),
					CspEvents:      account.CSPEvents.ValueBool(),
					Products:       products,
				},
			},
		},
	})

	if err != nil {
		diags.AddError(
			"Failed to update CSPM AWS account",
			fmt.Sprintf("Failed to update CSPM AWS account: %s", err.Error()),
		)
		return nil, diags
	}
	if status != nil {
		diags.AddError(
			"Failed to update CSPM AWS account",
			fmt.Sprintf("Failed to update CSPM AWS account: %s", status.Error()),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to update CSPM AWS account",
			"No error returned from api but CSPM account was not returned. Please report this issue to the provider developers.",
		)
		return nil, diags
	}
	return res.Payload.Resources[0], diags
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *cloudAWSAccountResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudAWSAccountModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteAccount(ctx, state)...)
}

func (r *cloudAWSAccountResource) deleteAccount(
	ctx context.Context,
	account cloudAWSAccountModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// deleting a resource that does not exist.
	if account.AccountID.ValueString() == "" && account.OrganizationID.ValueString() == "" {
		return diags
	}
	params := &cloud_aws_registration.CloudRegistrationAwsDeleteAccountParams{
		Context: ctx,
	}
	tflog.Debug(ctx, "deleting Cloud Registration account", map[string]interface{}{
		"account_id":                account.AccountID.ValueString(),
		"organization_id":           account.OrganizationID.ValueString(),
		"is_org_management_account": account.IsOrgManagementAccount.ValueBool(),
	})
	if account.IsOrgManagementAccount.ValueBool() {
		params.OrganizationIds = []string{account.OrganizationID.ValueString()}
	} else {
		params.Ids = []string{account.AccountID.ValueString()}
	}

	_, status, err := r.client.CloudAwsRegistration.CloudRegistrationAwsDeleteAccount(params)
	if err != nil {
		diags.AddError(
			"Failed to delete Cloud Registration AWS account",
			fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", err.Error()),
		)
		return diags
	}
	if status != nil {
		diags.AddError(
			"Failed to delete Cloud Registration AWS account",
			fmt.Sprintf("Failed to delete Cloud Registration AWS account: %s", status.Error()),
		)
		return diags
	}
	return diags
}

// Configure adds the provider configured client to the resource.
func (r *cloudAWSAccountResource) Configure(
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

// ImportState implements the logic to support resource imports.
func (r *cloudAWSAccountResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("account_id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *cloudAWSAccountResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudAWSAccountModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
