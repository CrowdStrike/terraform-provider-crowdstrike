package fcs

import (
	"context"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/resource_cloud_azure_tenant"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ resource.Resource = (*cloudAzureTenantResource)(nil)

func NewCloudAzureTenantResource() resource.Resource {
	return &cloudAzureTenantResource{}
}

type cloudAzureTenantResource struct{}

func (r *cloudAzureTenantResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_azure_tenant"
}

func (r *cloudAzureTenantResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resource_cloud_azure_tenant.CloudAzureTenantResourceSchema(ctx)
}

func (r *cloudAzureTenantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create API call logic

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read API call logic

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update API call logic

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudAzureTenantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data resource_cloud_azure_tenant.CloudAzureTenantModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete API call logic
}
