package responsepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
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

var (
	_ resource.Resource                   = &responsePolicyResource{}
	_ resource.ResourceWithConfigure      = &responsePolicyResource{}
	_ resource.ResourceWithImportState    = &responsePolicyResource{}
	_ resource.ResourceWithValidateConfig = &responsePolicyResource{}
)

func NewResponsePolicyResource() resource.Resource {
	return &responsePolicyResource{}
}

type responsePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type responsePolicyResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	PlatformName     types.String `tfsdk:"platform_name"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	HostGroups       types.Set    `tfsdk:"host_groups"`
	RealTimeResponse types.Bool   `tfsdk:"real_time_response"`
	CustomScripts    types.Bool   `tfsdk:"custom_scripts"`
	GetCommand       types.Bool   `tfsdk:"get_command"`
	PutCommand       types.Bool   `tfsdk:"put_command"`
	ExecCommand      types.Bool   `tfsdk:"exec_command"`
	FalconScripts    types.Bool   `tfsdk:"falcon_scripts"`
	MemdumpCommand   types.Bool   `tfsdk:"memdump_command"`
	XmemdumpCommand  types.Bool   `tfsdk:"xmemdump_command"`
	PutAndRunCommand types.Bool   `tfsdk:"put_and_run_command"`
	LastUpdated      types.String `tfsdk:"last_updated"`
}

func (r *responsePolicyResource) Configure(
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
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *responsePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_response_policy"
}

func (r *responsePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Host Setup and Management",
			"Manages CrowdStrike Real Time Response (RTR) policies that control endpoint response capabilities. RTR policies determine what remote response actions (commands, scripts, file operations) are available to responders on endpoints.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the response policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the response policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the response policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the response policy. (Windows, Mac, Linux). Changing this value will require replacing the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Mac", "Linux"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the response policy.",
				Default:     booldefault.StaticBool(false),
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host group IDs to attach to the policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"real_time_response": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Allow those with Real Time Responder roles to remotely connect to hosts.",
				Default:     booldefault.StaticBool(false),
			},
			"custom_scripts": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Allows those with RTR Active Responder and RTR Administrator roles to run custom scripts.",
				Default:     booldefault.StaticBool(false),
			},
			"get_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Extract files from a remote host via the CrowdStrike cloud.",
				Default:     booldefault.StaticBool(false),
			},
			"put_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Send files to a remote host via the CrowdStrike cloud.",
				Default:     booldefault.StaticBool(false),
			},
			"exec_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Run any executable on the remote host.",
				Default:     booldefault.StaticBool(false),
			},
			"falcon_scripts": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Allows those with the RTR Administrator role to run Falcon scripts (Windows only). Requires custom_scripts.",
				Default:     booldefault.StaticBool(false),
			},
			"memdump_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Dump process memory of a remote host (Windows only).",
				Default:     booldefault.StaticBool(false),
			},
			"xmemdump_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Dump the complete memory of a remote host (Windows only).",
				Default:     booldefault.StaticBool(false),
			},
			"put_and_run_command": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Send files and execute them with a single command (Windows and Mac only).",
				Default:     booldefault.StaticBool(false),
			},
		},
	}
}

func (m *responsePolicyResourceModel) wrap(
	ctx context.Context,
	policy *models.RemoteResponsePolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID = flex.StringPointerToFramework(policy.ID)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.PlatformName = flex.StringPointerToFramework(policy.PlatformName)
	m.Enabled = types.BoolPointerValue(policy.Enabled)

	hostGroupSet, diag := flex.FlattenHostGroupsToSet(ctx, policy.Groups)
	if diag.HasError() {
		diags.Append(diag...)
		return diags
	}
	m.HostGroups = hostGroupSet

	settingsMap := map[string]bool{
		"RealTimeFunctionality": false,
		"CustomScripts":         false,
		"GetCommand":            false,
		"PutCommand":            false,
		"ExecCommand":           false,
		"FalconScripts":         false,
		"MemDumpCommand":        false,
		"XMemDumpCommand":       false,
		"PutAndRunCommand":      false,
	}

	for _, category := range policy.Settings {
		if category.Name == nil {
			continue
		}

		for _, setting := range category.Settings {
			if setting.ID == nil {
				continue
			}

			if setting.Value != nil {
				if valueMap, ok := setting.Value.(map[string]interface{}); ok {
					if enabledVal, exists := valueMap["enabled"]; exists {
						if enabledBool, ok := enabledVal.(bool); ok {
							settingsMap[*setting.ID] = enabledBool
						}
					}
				}
			}
		}
	}

	m.RealTimeResponse = types.BoolValue(settingsMap["RealTimeFunctionality"])
	m.CustomScripts = types.BoolValue(settingsMap["CustomScripts"])
	m.GetCommand = types.BoolValue(settingsMap["GetCommand"])
	m.PutCommand = types.BoolValue(settingsMap["PutCommand"])
	m.ExecCommand = types.BoolValue(settingsMap["ExecCommand"])
	m.FalconScripts = types.BoolValue(settingsMap["FalconScripts"])
	m.MemdumpCommand = types.BoolValue(settingsMap["MemDumpCommand"])
	m.XmemdumpCommand = types.BoolValue(settingsMap["XMemDumpCommand"])
	m.PutAndRunCommand = types.BoolValue(settingsMap["PutAndRunCommand"])

	return diags
}

func (m *responsePolicyResourceModel) expandSettings() []*models.PreventionSettingReqV1 {
	var settings []*models.PreventionSettingReqV1

	addSetting := func(id string, enabled bool) {
		idStr := id
		settings = append(settings, &models.PreventionSettingReqV1{
			ID: &idStr,
			Value: map[string]interface{}{
				"enabled": enabled,
			},
		})
	}

	addSetting("RealTimeFunctionality", m.RealTimeResponse.ValueBool())
	addSetting("CustomScripts", m.CustomScripts.ValueBool())
	addSetting("GetCommand", m.GetCommand.ValueBool())
	addSetting("PutCommand", m.PutCommand.ValueBool())
	addSetting("ExecCommand", m.ExecCommand.ValueBool())

	if m.PlatformName.ValueString() == "Windows" {
		addSetting("FalconScripts", m.FalconScripts.ValueBool())
		addSetting("MemDumpCommand", m.MemdumpCommand.ValueBool())
		addSetting("XMemDumpCommand", m.XmemdumpCommand.ValueBool())
		addSetting("PutAndRunCommand", m.PutAndRunCommand.ValueBool())
	} else if m.PlatformName.ValueString() == "Mac" {
		addSetting("PutAndRunCommand", m.PutAndRunCommand.ValueBool())
	}

	return settings
}

func (r *responsePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting response policy create")

	var plan responsePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings := plan.expandSettings()

	policyParams := response_policies.CreateRTResponsePoliciesParams{
		Context: ctx,
		Body: &models.RemoteResponseCreatePoliciesV1{
			Resources: []*models.RemoteResponseCreatePolicyReqV1{
				{
					Name:         plan.Name.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					PlatformName: plan.PlatformName.ValueStringPointer(),
					Settings:     settings,
				},
			},
		},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to create response policy")
	res, err := r.client.ResponsePolicies.CreateRTResponsePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopesReadWrite,
			// TODO: Remove this detail when the API is fixed to return 409 for duplicate names
			tferrors.WithBadRequestDetail("This could be due to a duplicate name. Verify that no policy with this name already exists."),
		))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	policy := res.Payload.Resources[0]
	tflog.Info(ctx, "Successfully created response policy", map[string]interface{}{
		"policy_id": *policy.ID,
	})

	plan.ID = types.StringPointerValue(policy.ID)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		updatedPolicy, diag := r.setResponsePolicyEnabled(ctx, plan.ID.ValueString(), "enable")
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	if len(plan.HostGroups.Elements()) > 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		updatedPolicy, diag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupIDs, nil)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *responsePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting response policy read")

	var state responsePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving response policy", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})

	policy, diags := r.getResponsePolicy(ctx, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *responsePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting response policy update")

	var plan responsePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state responsePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings := plan.expandSettings()

	policyParams := response_policies.UpdateRTResponsePoliciesParams{
		Context: ctx,
		Body: &models.RemoteResponseUpdatePoliciesReqV1{
			Resources: []*models.RemoteResponseUpdatePolicyReqV1{
				{
					ID:          plan.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: flex.FrameworkToStringPointer(plan.Description),
					Settings:    settings,
				},
			},
		},
	}

	res, err := r.client.ResponsePolicies.UpdateRTResponsePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	policy := res.Payload.Resources[0]

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionName := "disable"
		if plan.Enabled.ValueBool() {
			actionName = "enable"
		}

		updatedPolicy, diag := r.setResponsePolicyEnabled(ctx, plan.ID.ValueString(), actionName)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	hostGroupsToAdd, hostGroupsToRemove, diags := utils.SetIDsToModify(
		ctx,
		plan.HostGroups,
		state.HostGroups,
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(hostGroupsToAdd) > 0 || len(hostGroupsToRemove) > 0 {
		updatedPolicy, diag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupsToAdd, hostGroupsToRemove)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
		if updatedPolicy != nil {
			policy = updatedPolicy
		}
	}

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *responsePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting response policy delete")

	var state responsePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Enabled.ValueBool() {
		tflog.Debug(ctx, "Disabling response policy before deletion", map[string]interface{}{
			"policy_id": state.ID.ValueString(),
		})

		_, diag := r.setResponsePolicyEnabled(ctx, state.ID.ValueString(), "disable")
		if diag != nil {
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
			return
		}
	}

	_, err := r.client.ResponsePolicies.DeleteRTResponsePolicies(
		&response_policies.DeleteRTResponsePoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *responsePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *responsePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config responsePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// ValueBool() returns false for null/unknown values, which is the correct behavior for this check.
	// We want to know if ANY RTR setting is explicitly enabled (true), treating unset values as not enabled.
	anyRTREnabled := config.CustomScripts.ValueBool() ||
		config.GetCommand.ValueBool() ||
		config.PutCommand.ValueBool() ||
		config.ExecCommand.ValueBool() ||
		config.FalconScripts.ValueBool() ||
		config.MemdumpCommand.ValueBool() ||
		config.XmemdumpCommand.ValueBool() ||
		config.PutAndRunCommand.ValueBool()

	if anyRTREnabled && utils.IsKnown(config.RealTimeResponse) && !config.RealTimeResponse.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("real_time_response"),
			"Real Time Response required",
			"When any RTR setting is enabled (custom_scripts, get_command, put_command, exec_command, falcon_scripts, memdump_command, xmemdump_command, put_and_run_command), real_time_response must be enabled.",
		)
	}

	resp.Diagnostics.Append(
		fwvalidators.BoolRequiresBool(
			config.FalconScripts,
			config.CustomScripts,
			"falcon_scripts",
			"custom_scripts",
		)...)

	resp.Diagnostics.Append(
		boolRequiresPlatform(
			config.FalconScripts,
			config.PlatformName,
			"falcon_scripts",
			[]string{"Windows"},
		)...)

	resp.Diagnostics.Append(
		boolRequiresPlatform(
			config.MemdumpCommand,
			config.PlatformName,
			"memdump_command",
			[]string{"Windows"},
		)...)

	resp.Diagnostics.Append(
		boolRequiresPlatform(
			config.XmemdumpCommand,
			config.PlatformName,
			"xmemdump_command",
			[]string{"Windows"},
		)...)

	resp.Diagnostics.Append(
		boolRequiresPlatform(
			config.PutAndRunCommand,
			config.PlatformName,
			"put_and_run_command",
			[]string{"Windows", "Mac"},
		)...)
}

func (r *responsePolicyResource) setResponsePolicyEnabled(
	ctx context.Context,
	policyID string,
	actionName string,
) (*models.RemoteResponsePolicyV1, diag.Diagnostic) {
	res, err := r.client.ResponsePolicies.PerformRTResponsePoliciesAction(&response_policies.PerformRTResponsePoliciesActionParams{
		Context:    ctx,
		ActionName: actionName,
		Body: &models.MsaEntityActionRequestV2{
			Ids: []string{policyID},
		},
	})
	if err != nil {
		return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
	}

	if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 && res.Payload.Resources[0] != nil {
		return res.Payload.Resources[0], nil
	}
	return nil, nil
}

func (r *responsePolicyResource) syncHostGroups(
	ctx context.Context,
	policyID string,
	groupsToAdd []string,
	groupsToRemove []string,
) (*models.RemoteResponsePolicyV1, diag.Diagnostic) {
	var lastPolicy *models.RemoteResponsePolicyV1

	if len(groupsToAdd) > 0 {
		nameStr := "group_id"
		var actionParams []*models.MsaspecActionParameter
		for _, groupID := range groupsToAdd {
			groupIDCopy := groupID
			actionParams = append(actionParams, &models.MsaspecActionParameter{
				Name:  &nameStr,
				Value: &groupIDCopy,
			})
		}

		res, err := r.client.ResponsePolicies.PerformRTResponsePoliciesAction(&response_policies.PerformRTResponsePoliciesActionParams{
			Context:    ctx,
			ActionName: "add-host-group",
			Body: &models.MsaEntityActionRequestV2{
				Ids:              []string{policyID},
				ActionParameters: actionParams,
			},
		})
		if err != nil {
			return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
		}
		if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 && res.Payload.Resources[0] != nil {
			lastPolicy = res.Payload.Resources[0]
		}
	}

	if len(groupsToRemove) > 0 {
		nameStr := "group_id"
		var actionParams []*models.MsaspecActionParameter
		for _, groupID := range groupsToRemove {
			groupIDCopy := groupID
			actionParams = append(actionParams, &models.MsaspecActionParameter{
				Name:  &nameStr,
				Value: &groupIDCopy,
			})
		}

		res, err := r.client.ResponsePolicies.PerformRTResponsePoliciesAction(&response_policies.PerformRTResponsePoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-host-group",
			Body: &models.MsaEntityActionRequestV2{
				Ids:              []string{policyID},
				ActionParameters: actionParams,
			},
		})
		if err != nil {
			return nil, tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
		}
		if res != nil && res.Payload != nil && len(res.Payload.Resources) > 0 && res.Payload.Resources[0] != nil {
			lastPolicy = res.Payload.Resources[0]
		}
	}

	return lastPolicy, nil
}

func (r *responsePolicyResource) getResponsePolicy(
	ctx context.Context,
	policyID string,
) (*models.RemoteResponsePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := response_policies.GetRTResponsePoliciesParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	res, err := r.client.ResponsePolicies.GetRTResponsePolicies(&params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
