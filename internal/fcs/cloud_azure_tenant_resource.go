package fcs

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/resource_cloud_azure_tenant"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &cloudAzureTenantResource{}
	_ resource.ResourceWithConfigure = &cloudAzureTenantResource{}
	// _ resource.ResourceWithImportState    = &cloudAzureTenantResource{}
	// _ resource.ResourceWithValidateConfig = &cloudAzureTenantResource{}
)

func NewCloudAzureTenantResource() resource.Resource {
	return &cloudAzureTenantResource{}
}

type cloudAzureTenantResource struct {
	client *client.CrowdStrikeAPISpecification
}

// Configure adds the provider configured client to the resource.
func (r *cloudAzureTenantResource) Configure(
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

func (r *cloudAzureTenantResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_azure_tenant"
}

func (r *cloudAzureTenantResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = resource_cloud_azure_tenant.CloudAzureTenantResourceSchema(ctx)
}

func wrap(
	ctx context.Context,
	model *resource_cloud_azure_tenant.CloudAzureTenantModel,
	registration models.AzureTenantRegistration,
) diag.Diagnostics {
	var diags diag.Diagnostics

	model.TenantId = types.StringValue(*registration.TenantID)
	model.AppRegistrationId = types.StringValue(registration.AppRegistrationID)

	graphPermissionIDs, err := types.ListValueFrom(
		ctx,
		types.StringType,
		registration.MicrosoftGraphPermissionIds,
	)
	diags.Append(err...)
	if diags.HasError() {
		return diags
	}

	model.MicrosoftGraphPermissionIds = graphPermissionIDs
	return diags
}

func (r *cloudAzureTenantResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, err := r.createRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, diags := r.getRegistration(ctx, data.TenantId.ValueString())
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf(
					"registration for tenant %s not found, removing from state",
					data.TenantId.ValueString(),
				),
			)

			resp.State.RemoveResource(ctx)
			return
		}
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	registration, err := r.updateRegistration(ctx, &data)
	resp.Diagnostics.Append(err...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(wrap(ctx, &data, *registration)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteRegistration(ctx, data.TenantId.ValueString())...)
}

func (r *cloudAzureTenantResource) deleteRegistration(
	ctx context.Context,
	tenantID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	_, err := r.client.CloudAzureRegistration.CloudRegistrationAzureDeleteRegistration(
		&cloud_azure_registration.CloudRegistrationAzureDeleteRegistrationParams{
			TenantIds: []string{tenantID},
			Context:   ctx,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to delete registration",
			fmt.Sprintf("Failed to delete azure tenant registration: %s", err),
		)

		return diags
	}

	return diags
}

func (r *cloudAzureTenantResource) getRegistration(
	ctx context.Context,
	tenantID string,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureGetRegistration(
		&cloud_azure_registration.CloudRegistrationAzureGetRegistrationParams{
			TenantID: tenantID,
			Context:  ctx,
		},
	)

	if err != nil {
		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureGetRegistrationNotFound); ok {
			diags.Append(
				newNotFoundError(
					fmt.Sprintf("No registration found for tenant: %s.", tenantID),
				),
			)
			return nil, diags
		}

		diags.AddError(
			"Failed to get registration",
			fmt.Sprintf("Failed to get azure tenant registration: %s", err),
		)

		return nil, diags
	}

	//TODO fix
	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to get registration",
			"Get registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}

func (r *cloudAzureTenantResource) createRegistration(
	ctx context.Context,
	data *resource_cloud_azure_tenant.CloudAzureTenantModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	microsoftGraphPermissionIDs := utils.ListTypeAs[string](
		ctx,
		data.MicrosoftGraphPermissionIds,
		&diags,
	)

	if diags.HasError() {
		return nil, diags
	}

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureCreateRegistration(
		&cloud_azure_registration.CloudRegistrationAzureCreateRegistrationParams{
			Body: &models.AzureAzureRegistrationCreateRequestExtV1{
				Resource: &models.AzureTenantRegistrationBase{
					TenantID:                    data.TenantId.ValueStringPointer(),
					MicrosoftGraphPermissionIds: microsoftGraphPermissionIDs,
					DeploymentMethod:            "terraform-native",
				},
			},
			Context: ctx,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to register tenant",
			fmt.Sprintf("Failed to register azure tenant: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to register tenant",
			"Registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}

func (r *cloudAzureTenantResource) updateRegistration(
	ctx context.Context,
	data *resource_cloud_azure_tenant.CloudAzureTenantModel,
) (*models.AzureTenantRegistration, diag.Diagnostics) {
	var diags diag.Diagnostics

	microsoftGraphPermissionIDs := utils.ListTypeAs[string](
		ctx,
		data.MicrosoftGraphPermissionIds,
		&diags,
	)

	if diags.HasError() {
		return nil, diags
	}

	res, err := r.client.CloudAzureRegistration.CloudRegistrationAzureUpdateRegistration(
		&cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationParams{
			Body: &models.AzureAzureRegistrationUpdateRequestExtV1{
				Resource: &models.AzureTenantRegistrationBase{
					TenantID:                    data.TenantId.ValueStringPointer(),
					MicrosoftGraphPermissionIds: microsoftGraphPermissionIDs,
					DeploymentMethod:            "terraform-native",
				},
			},
			Context: ctx,
		},
	)

	if err != nil {
		if _, ok := err.(*cloud_azure_registration.CloudRegistrationAzureUpdateRegistrationNotFound); ok {
			diags.Append(
				newNotFoundError(
					fmt.Sprintf(
						"No registration found for tenant: %s.",
						data.TenantId.ValueString(),
					),
				),
			)
			return nil, diags
		}

		diags.AddError(
			"Failed to update registration",
			fmt.Sprintf("Failed to update azure tenant registration: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || res.Payload.Resource == nil {
		diags.AddError(
			"Failed to update registration",
			"Update registration api call returned a successful status code, but no registration information was returned. Please report this issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)

		return nil, diags
	}

	return res.Payload.Resource, diags
}
