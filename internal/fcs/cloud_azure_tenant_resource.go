package fcs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_azure_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/resource_cloud_azure_tenant"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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

	// Create API call logic
	_, err := r.client.CloudAzureRegistration.CloudRegistrationAzureCreateRegistration(
		&cloud_azure_registration.CloudRegistrationAzureCreateRegistrationParams{
			Body: &models.AzureAzureRegistrationCreateRequestExtV1{
				Resource: &models.AzureTenantRegistrationBase{
					TenantID:                    data.TenantId.ValueStringPointer(),
					MicrosoftGraphPermissionIds: []string{"9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"},
					DeploymentMethod:            "terraform-native",
				},
			},
			Context: ctx,
		},
	)

	if err != nil {
		s, _ := json.MarshalIndent(err, "", "    ")
		panic(string(s))

		utils.PancicPrettyPrint(err.Error())
	}

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

	// Read API call logic

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

	// Update API call logic

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

	// Delete API call logic
}
