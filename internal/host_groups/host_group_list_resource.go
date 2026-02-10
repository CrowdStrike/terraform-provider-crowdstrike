package hostgroups

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/host_group"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ list.ListResource              = &hostGroupListResource{}
	_ list.ListResourceWithConfigure = &hostGroupListResource{}
)

type hostGroupListResource struct {
	client *client.CrowdStrikeAPISpecification
}

type HostGroupListResourceModel struct {
	Filter types.String `tfsdk:"filter"`
}

func NewHostGroupListResource() list.ListResource {
	return &hostGroupListResource{}
}

func (r *hostGroupListResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected List Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *hostGroupListResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_host_group"
}

func (r *hostGroupListResource) ListResourceConfigSchema(
	_ context.Context,
	_ list.ListResourceSchemaRequest,
	resp *list.ListResourceSchemaResponse,
) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"List Host Groups --- Query host groups in the CrowdStrike Falcon Platform.\n\n%s",
			scopes.GenerateScopeDescription([]scopes.Scope{
				{
					Name: "Host groups",
					Read: true,
				},
			}),
		),
		Attributes: map[string]listschema.Attribute{
			"filter": listschema.StringAttribute{
				MarkdownDescription: "FQL filter to apply when listing host groups. Examples: `name:'Production'`, `group_type:'dynamic'`.",
				Optional:            true,
			},
		},
	}
}

func (r *hostGroupListResource) List(
	ctx context.Context,
	req list.ListRequest,
	stream *list.ListResultsStream,
) {
	var data HostGroupListResourceModel

	diags := req.Config.Get(ctx, &data)
	if diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}

	params := &host_group.QueryHostGroupsParams{
		Context: ctx,
	}

	if !data.Filter.IsNull() {
		filter := data.Filter.ValueString()
		params.Filter = &filter
	}

	hostGroupIDs, err := r.client.HostGroup.QueryHostGroups(params)
	if err != nil {
		var forbiddenError *host_group.QueryHostGroupsForbidden
		if errors.As(err, &forbiddenError) {
			forbiddenDiag := tferrors.NewForbiddenError(tferrors.Read, []scopes.Scope{
				{
					Name: "Host groups",
					Read: true,
				},
			})
			stream.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{forbiddenDiag})
			return
		}

		errorDiag := tferrors.NewOperationError(tferrors.Read, err)
		stream.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{errorDiag})
		return
	}

	if len(hostGroupIDs.Payload.Resources) == 0 {
		stream.Results = list.NoListResults
		return
	}

	hostGroups, err := r.client.HostGroup.GetHostGroups(
		&host_group.GetHostGroupsParams{
			Context: ctx,
			Ids:     hostGroupIDs.Payload.Resources,
		},
	)
	if err != nil {
		var forbiddenError *host_group.GetHostGroupsForbidden
		if errors.As(err, &forbiddenError) {
			forbiddenDiag := tferrors.NewForbiddenError(tferrors.Read, []scopes.Scope{
				{
					Name: "Host groups",
					Read: true,
				},
			})
			stream.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{forbiddenDiag})
			return
		}

		errorDiag := tferrors.NewOperationError(tferrors.Read, err)
		stream.Results = list.ListResultsStreamDiagnostics(diag.Diagnostics{errorDiag})
		return
	}

	stream.Results = func(push func(list.ListResult) bool) {
		for _, hostGroup := range hostGroups.Payload.Resources {
			result := req.NewListResult(ctx)

			result.DisplayName = *hostGroup.Name

			identityData := struct {
				ID types.String `tfsdk:"id"`
			}{
				ID: types.StringValue(*hostGroup.ID),
			}
			identityDiags := result.Identity.Set(ctx, identityData)
			for _, d := range identityDiags {
				result.Diagnostics.Append(d)
			}

			resourceData := HostGroupResourceModel{
				ID:          types.StringValue(*hostGroup.ID),
				Name:        types.StringValue(*hostGroup.Name),
				Description: flex.StringPointerToFramework(hostGroup.Description),
				GroupType:   types.StringValue(hostGroup.GroupType),
				HostIDs:     types.SetNull(types.StringType),
				Hostnames:   types.SetNull(types.StringType),
			}

			assignmentDiags := AssignAssignmentRule(ctx, hostGroup.AssignmentRule, &resourceData)
			for _, d := range assignmentDiags {
				result.Diagnostics.Append(d)
			}

			resourceDiags := result.Resource.Set(ctx, resourceData)
			for _, d := range resourceDiags {
				result.Diagnostics.Append(d)
			}

			if !push(result) {
				return
			}
		}
	}
}
