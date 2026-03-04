package iocindicator

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &iocIndicatorResource{}
	_ resource.ResourceWithConfigure      = &iocIndicatorResource{}
	_ resource.ResourceWithImportState    = &iocIndicatorResource{}
	_ resource.ResourceWithValidateConfig = &iocIndicatorResource{}
)

// NewIOCIndicatorResource creates a new IOC indicator resource.
func NewIOCIndicatorResource() resource.Resource {
	return &iocIndicatorResource{}
}

// iocIndicatorResource defines the resource implementation.
type iocIndicatorResource struct {
	client *client.CrowdStrikeAPISpecification
}

// iocIndicatorResourceModel describes the resource data model.
type iocIndicatorResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Type            types.String `tfsdk:"type"`
	Value           types.String `tfsdk:"value"`
	Action          types.String `tfsdk:"action"`
	Severity        types.String `tfsdk:"severity"`
	Description     types.String `tfsdk:"description"`
	Platforms       types.Set    `tfsdk:"platforms"`
	HostGroups      types.Set    `tfsdk:"host_groups"`
	AppliedGlobally types.Bool   `tfsdk:"applied_globally"`
	Expiration      types.String `tfsdk:"expiration"`
	Source          types.String `tfsdk:"source"`
	Tags            types.Set    `tfsdk:"tags"`
	CreatedBy       types.String `tfsdk:"created_by"`
	CreatedOn       types.String `tfsdk:"created_on"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
	ModifiedOn      types.String `tfsdk:"modified_on"`
	LastUpdated     types.String `tfsdk:"last_updated"`
}

// wrap maps an API response model to the Terraform resource model.
func (m *iocIndicatorResourceModel) wrap(
	ctx context.Context,
	indicator *models.APIIndicatorV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(indicator.ID)
	m.Type = types.StringValue(indicator.Type)
	m.Value = types.StringValue(indicator.Value)
	m.Action = types.StringValue(indicator.Action)
	m.Severity = types.StringValue(indicator.Severity)
	m.Description = types.StringValue(indicator.Description)
	m.AppliedGlobally = types.BoolValue(indicator.AppliedGlobally)
	m.Source = types.StringValue(indicator.Source)
	m.CreatedBy = types.StringValue(indicator.CreatedBy)
	m.CreatedOn = types.StringValue(indicator.CreatedOn.String())
	m.ModifiedBy = types.StringValue(indicator.ModifiedBy)
	m.ModifiedOn = types.StringValue(indicator.ModifiedOn.String())

	if indicator.Expiration.String() != "0001-01-01T00:00:00.000Z" {
		m.Expiration = types.StringValue(indicator.Expiration.String())
	} else {
		m.Expiration = types.StringNull()
	}

	platforms, d := types.SetValueFrom(ctx, types.StringType, indicator.Platforms)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	m.Platforms = platforms

	if len(indicator.HostGroups) > 0 {
		hostGroups, d := types.SetValueFrom(ctx, types.StringType, indicator.HostGroups)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.HostGroups = hostGroups
	} else {
		m.HostGroups = types.SetNull(types.StringType)
	}

	if len(indicator.Tags) > 0 {
		tags, d := types.SetValueFrom(ctx, types.StringType, indicator.Tags)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.Tags = tags
	} else {
		m.Tags = types.SetNull(types.StringType)
	}

	return diags
}

func (r *iocIndicatorResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *iocIndicatorResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ioc_indicator"
}

func (r *iocIndicatorResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"IOC Management --- Manages IOC (Indicator of Compromise) indicators in CrowdStrike Falcon. IOC indicators allow you to create custom indicators based on SHA256 hashes, MD5 hashes, domains, IPv4 addresses, or IPv6 addresses with actions such as allow, detect, or prevent.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier of the IOC indicator.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The type of the IOC indicator. Valid values are: `sha256`, `md5`, `domain`, `ipv4`, `ipv6`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"sha256",
						"md5",
						"domain",
						"ipv4",
						"ipv6",
					),
				},
			},
			"value": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The value of the IOC indicator. For hash types, this is the hash value. For domain types, this is the domain name. For IP types, this is the IP address.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"action": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The action to take when the IOC indicator is matched. Valid values are: `allow`, `detect`, `prevent`, `prevent_no_ui`, `no_action`.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"allow",
						"detect",
						"prevent",
						"prevent_no_ui",
						"no_action",
					),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The severity level of the IOC indicator. Valid values are: `informational`, `low`, `medium`, `high`, `critical`.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"informational",
						"low",
						"medium",
						"high",
						"critical",
					),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "A description of the IOC indicator.",
			},
			"platforms": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The platforms this IOC indicator applies to. Valid values are: `windows`, `mac`, `linux`.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf("windows", "mac", "linux"),
					),
					setvalidator.SizeAtLeast(1),
				},
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A set of host group IDs to apply this indicator to. Cannot be used together with `applied_globally`.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"applied_globally": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to apply the indicator globally to all hosts. Cannot be used together with `host_groups`.",
			},
			"expiration": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The expiration date of the IOC indicator in RFC 3339 format (e.g. `2025-12-31T23:59:59Z`).",
			},
			"source": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The source of the IOC indicator.",
			},
			"tags": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A set of tags to apply to the IOC indicator.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the IOC indicator.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the IOC indicator was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the IOC indicator.",
			},
			"modified_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the IOC indicator was last modified.",
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
		},
	}
}

// ValidateConfig runs during validate, plan, and apply to check configuration validity.
func (r *iocIndicatorResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg iocIndicatorResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.AppliedGlobally.IsUnknown() || cfg.HostGroups.IsUnknown() {
		return
	}

	hasAppliedGlobally := cfg.AppliedGlobally.ValueBool()
	hasHostGroups := !cfg.HostGroups.IsNull() && len(cfg.HostGroups.Elements()) > 0

	if hasAppliedGlobally && hasHostGroups {
		resp.Diagnostics.AddAttributeError(
			path.Root("applied_globally"),
			"Invalid Configuration",
			"Cannot specify both applied_globally=true and host_groups. "+
				"Please use either applied_globally=true for global indicators or provide specific host_groups.",
		)
		return
	}

	if !hasAppliedGlobally && !hasHostGroups {
		resp.Diagnostics.AddAttributeError(
			path.Root("applied_globally"),
			"Invalid Configuration",
			"Either applied_globally must be true or host_groups must be provided. "+
				"An IOC indicator must be scoped to at least one target.",
		)
		return
	}
}

func (r *iocIndicatorResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan iocIndicatorResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating IOC indicator", map[string]any{
		"type":  plan.Type.ValueString(),
		"value": plan.Value.ValueString(),
	})

	var platforms []string
	resp.Diagnostics.Append(plan.Platforms.ElementsAs(ctx, &platforms, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var hostGroups []string
	if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var tags []string
	if !plan.Tags.IsNull() && !plan.Tags.IsUnknown() {
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	appliedGlobally := plan.AppliedGlobally.ValueBool()

	indicator := &models.APIIndicatorCreateReqV1{
		Type:            plan.Type.ValueString(),
		Value:           plan.Value.ValueString(),
		Action:          plan.Action.ValueString(),
		Severity:        plan.Severity.ValueString(),
		Description:     plan.Description.ValueString(),
		Platforms:       platforms,
		HostGroups:      hostGroups,
		AppliedGlobally: &appliedGlobally,
		Source:          plan.Source.ValueString(),
		Tags:            tags,
	}

	if !plan.Expiration.IsNull() && !plan.Expiration.IsUnknown() {
		exp, err := parseDateTime(plan.Expiration.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid expiration format",
				fmt.Sprintf(
					"Failed to parse expiration date: %s. Expected RFC 3339 format (e.g. 2025-12-31T23:59:59Z).",
					err,
				),
			)
			return
		}
		indicator.Expiration = exp
	}

	body := &models.APIIndicatorCreateReqsV1{
		Indicators: []*models.APIIndicatorCreateReqV1{indicator},
	}

	params := ioc.NewIndicatorCreateV1Params().WithBody(body)
	ignoreWarnings := true
	params.SetIgnoreWarnings(&ignoreWarnings)

	res, err := r.client.Ioc.IndicatorCreateV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopes,
		)
		if diag != nil {
			resp.Diagnostics.Append(diag)
		}
		return
	}

	payload := res.GetPayload()
	if payload == nil || len(payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(
		tferrors.Create,
		payload.Errors,
	); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	createdIndicator := payload.Resources[0]

	tflog.Info(ctx, "Created IOC indicator", map[string]any{
		"id": createdIndicator.ID,
	})

	resp.Diagnostics.Append(plan.wrap(ctx, createdIndicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *iocIndicatorResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state iocIndicatorResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Info(ctx, "Reading IOC indicator", map[string]any{
		"id": id,
	})

	indicator, diags := getIOCIndicator(ctx, r.client, id)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		if tferrors.HasNotFoundError(resp.Diagnostics) {
			tflog.Warn(ctx, "IOC indicator not found, removing from state", map[string]any{
				"id": id,
			})
			resp.Diagnostics = diag.Diagnostics{}
			resp.State.RemoveResource(ctx)
			return
		}
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, indicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *iocIndicatorResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan iocIndicatorResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state iocIndicatorResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Info(ctx, "Updating IOC indicator", map[string]any{
		"id": id,
	})

	var platforms []string
	resp.Diagnostics.Append(plan.Platforms.ElementsAs(ctx, &platforms, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var hostGroups []string
	if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	var tags []string
	if !plan.Tags.IsNull() && !plan.Tags.IsUnknown() {
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateReq := &models.APIIndicatorUpdateReqV1{
		ID:              id,
		Action:          plan.Action.ValueString(),
		Severity:        plan.Severity.ValueString(),
		Description:     plan.Description.ValueString(),
		Platforms:       platforms,
		HostGroups:      hostGroups,
		AppliedGlobally: plan.AppliedGlobally.ValueBool(),
		Source:          plan.Source.ValueString(),
		Tags:            tags,
	}

	if !plan.Expiration.IsNull() && !plan.Expiration.IsUnknown() {
		exp, err := parseDateTime(plan.Expiration.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid expiration format",
				fmt.Sprintf(
					"Failed to parse expiration date: %s. Expected RFC 3339 format (e.g. 2025-12-31T23:59:59Z).",
					err,
				),
			)
			return
		}
		updateReq.Expiration = *exp
	}

	body := &models.APIIndicatorUpdateReqsV1{
		BulkUpdate: &models.APIBulkUpdateReqV1{},
		Indicators: []*models.APIIndicatorUpdateReqV1{updateReq},
	}

	params := ioc.NewIndicatorUpdateV1Params().WithBody(body)
	ignoreWarnings := true
	params.SetIgnoreWarnings(&ignoreWarnings)

	res, err := r.client.Ioc.IndicatorUpdateV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			apiScopes,
		)
		if diag != nil {
			resp.Diagnostics.Append(diag)
		}
		return
	}

	payload := res.GetPayload()
	if payload == nil || len(payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(
		tferrors.Update,
		payload.Errors,
	); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	// Re-read the resource to get the canonical state from the API.
	updatedIndicator, diags := getIOCIndicator(ctx, r.client, id)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated IOC indicator", map[string]any{
		"id": id,
	})

	resp.Diagnostics.Append(plan.wrap(ctx, updatedIndicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *iocIndicatorResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state iocIndicatorResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Info(ctx, "Deleting IOC indicator", map[string]any{
		"id": id,
	})

	params := ioc.NewIndicatorDeleteV1Params().WithIds([]string{id})
	_, err := r.client.Ioc.IndicatorDeleteV1(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			apiScopes,
		)
		if diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				tflog.Warn(ctx, "IOC indicator already deleted", map[string]any{
					"id": id,
				})
				return
			}
			resp.Diagnostics.Append(diag)
		}
		return
	}

	tflog.Info(ctx, "Deleted IOC indicator", map[string]any{
		"id": id,
	})
}

func (r *iocIndicatorResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// parseDateTime parses a date-time string in RFC 3339 format into a strfmt.DateTime pointer.
func parseDateTime(value string) (*strfmt.DateTime, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		// Try with just a date.
		t, err = time.Parse("2006-01-02", value)
		if err != nil {
			return nil, fmt.Errorf("unable to parse %q as RFC 3339 or date: %w", value, err)
		}
	}
	dt := strfmt.DateTime(t)
	return &dt, nil
}
