package cidgroup

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	dataSourceDocumentationSection = "Host Setup and Management"
	dataSourceMarkdownDescription  = "Provides information about a single CID group in CrowdStrike Falcon Flight Control. Use this to look up a CID group by name or ID and reference its attributes in other resources."
)

var dataSourceApiScopes = []scopes.Scope{
	{
		Name:  "Flight Control",
		Read:  true,
		Write: false,
	},
}

var (
	_ datasource.DataSource              = &cidGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &cidGroupDataSource{}
)

func NewCIDGroupDataSource() datasource.DataSource {
	return &cidGroupDataSource{}
}

type cidGroupDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type CIDGroupDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	CID         types.String `tfsdk:"cid"`
	IsDefault   types.Bool   `tfsdk:"is_default"`
	CIDs        types.Set    `tfsdk:"cids"`
}

func (m *CIDGroupDataSourceModel) wrap(group *models.DomainCIDGroup) {
	m.ID = flex.StringPointerToFramework(group.CidGroupID)
	m.Name = flex.StringPointerToFramework(group.Name)
	m.Description = flex.StringPointerToFramework(group.Description)
	m.CID = types.StringValue(group.Cid)
	m.IsDefault = types.BoolValue(group.IsDefault)
}

func (d *cidGroupDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = config.Client
}

func (d *cidGroupDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cid_group"
}

func (d *cidGroupDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			dataSourceDocumentationSection,
			dataSourceMarkdownDescription,
			dataSourceApiScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The CID group ID. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id")),
				},
			},
			"name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The CID group name. Exactly one of 'id' or 'name' must be provided.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The description of the CID group.",
			},
			"cid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The CID identifier associated with this group.",
			},
			"is_default": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this is the default CID group.",
			},
			"cids": schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The set of CID identifiers that are members of this group.",
			},
		},
	}
}

func (d *cidGroupDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data CIDGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var groupID string
	if utils.IsKnown(data.ID) {
		groupID = data.ID.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up CID group by ID", map[string]any{
			"id": groupID,
		})
	} else {
		name := data.Name.ValueString()
		tflog.Debug(ctx, "[datasource] Looking up CID group by name", map[string]any{
			"name": name,
		})

		id, findDiags := d.findCIDGroupIDByName(ctx, name)
		resp.Diagnostics.Append(findDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		groupID = id
	}

	group, getDiags := d.getCIDGroupByID(ctx, groupID)
	resp.Diagnostics.Append(getDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.wrap(group)

	memberCIDs, memberDiags := d.getCIDGroupMembers(ctx, groupID)
	resp.Diagnostics.Append(memberDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cidsSet, setDiags := flex.FlattenStringValueSet(ctx, memberCIDs)
	resp.Diagnostics.Append(setDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.CIDs = cidsSet

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *cidGroupDataSource) findCIDGroupIDByName(
	ctx context.Context,
	name string,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	notFoundDetail := fmt.Sprintf("No CID group found with name %q.", name)

	res, err := d.client.Mssp.QueryCIDGroups(&mssp.QueryCIDGroupsParams{
		Context: ctx,
		Name:    &name,
	})
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return "", diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return "", diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return "", diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return "", diags
	}

	if len(res.Payload.Resources) > 1 {
		diags.AddError(
			"Multiple CID groups matched",
			fmt.Sprintf(
				"The name %q matched %d CID groups, but this data source must resolve to exactly one. Provide a more specific name or use the 'id' attribute to look up a specific CID group.",
				name, len(res.Payload.Resources),
			),
		)
		return "", diags
	}

	return res.Payload.Resources[0], diags
}

func (d *cidGroupDataSource) getCIDGroupByID(
	ctx context.Context,
	id string,
) (*models.DomainCIDGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	notFoundDetail := fmt.Sprintf("No CID group found with ID %q.", id)

	res, multi, err := d.client.Mssp.GetCIDGroupByIDV2(&mssp.GetCIDGroupByIDV2Params{
		Context: ctx,
		Ids:     []string{id},
	})
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)))
		return nil, diags
	}

	if multi != nil {
		if multiDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, multi, dataSourceApiScopes, tferrors.WithNotFoundDetail(notFoundDetail)); multiDiag != nil {
			diags.Append(multiDiag)
			return nil, diags
		}
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	if payloadDiag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); payloadDiag != nil {
		diags.Append(payloadDiag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (d *cidGroupDataSource) getCIDGroupMembers(
	ctx context.Context,
	id string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, multi, err := d.client.Mssp.GetCIDGroupMembersByV2(&mssp.GetCIDGroupMembersByV2Params{
		Context: ctx,
		Ids:     []string{id},
	})
	if err != nil {
		errDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, dataSourceApiScopes)
		if errDiag != nil && errDiag.Summary() != tferrors.NotFoundErrorSummary {
			diags.Append(errDiag)
			return nil, diags
		}
	}

	if multi != nil {
		multiDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Read, multi, dataSourceApiScopes)
		if multiDiag != nil && multiDiag.Summary() != tferrors.NotFoundErrorSummary {
			diags.Append(multiDiag)
			return nil, diags
		}
	}

	var memberCIDs []string
	if res != nil && res.Payload != nil {
		for _, group := range res.Payload.Resources {
			if group == nil {
				continue
			}
			memberCIDs = append(memberCIDs, group.Cids...)
		}
	}

	return memberCIDs, diags
}
