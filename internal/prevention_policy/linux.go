package preventionpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithConfigure      = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithImportState    = &preventionPolicyLinuxResource{}
	_ resource.ResourceWithValidateConfig = &preventionPolicyLinuxResource{}
)

// NewPreventionPolicyLinuxResource is a helper function to simplify the provider implementation.
func NewPreventionPolicyLinuxResource() resource.Resource {
	return &preventionPolicyLinuxResource{}
}

// preventionPolicyLinuxResource is the resource implementation.
type preventionPolicyLinuxResource struct {
	client *client.CrowdStrikeAPISpecification
}

// preventionPolicyLinuxResourceModel is the resource implementation.
type preventionPolicyLinuxResourceModel struct {
	ID                                 types.String `tfsdk:"id"`
	Enabled                            types.Bool   `tfsdk:"enabled"`
	Name                               types.String `tfsdk:"name"`
	Description                        types.String `tfsdk:"description"`
	HostGroups                         types.Set    `tfsdk:"host_groups"`
	RuleGroups                         types.Set    `tfsdk:"ioa_rule_groups"`
	LastUpdated                        types.String `tfsdk:"last_updated"`
	CloudAntiMalware                   *mlSlider    `tfsdk:"cloud_anti_malware"`
	OnSensorMLSlider                   *mlSlider    `tfsdk:"sensor_anti_malware"`
	UnknownDetectionRelatedExecutables types.Bool   `tfsdk:"upload_unknown_detection_related_executables"`
	UnknownExecutables                 types.Bool   `tfsdk:"upload_unknown_executables"`
	ScriptBasedExecutionMonitoring     types.Bool   `tfsdk:"script_based_execution_monitoring"`
	NextGenAV                          types.Bool   `tfsdk:"quarantine"`
	CustomBlacklisting                 types.Bool   `tfsdk:"custom_blocking"`
	PreventSuspiciousProcesses         types.Bool   `tfsdk:"prevent_suspicious_processes"`
	DriftPrevention                    types.Bool   `tfsdk:"drift_prevention"`
	FilesystemVisibility               types.Bool   `tfsdk:"filesystem_visibility"`
	NetworkVisibility                  types.Bool   `tfsdk:"network_visibility"`
	HTTPVisibility                     types.Bool   `tfsdk:"http_visibility"`
	FTPVisibility                      types.Bool   `tfsdk:"ftp_visibility"`
	TLSVisibility                      types.Bool   `tfsdk:"tls_visibility"`
	EmailProtocolVisibility            types.Bool   `tfsdk:"email_protocol_visibility"`
}

// Configure adds the provider configured client to the resource.
func (r *preventionPolicyLinuxResource) Configure(
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

// Metadata returns the resource type name.
func (r *preventionPolicyLinuxResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_prevention_policy_linux"
}

// Schema defines the schema for the resource.
func (r *preventionPolicyLinuxResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Prevention Policy --- This resource allows you to manage CrowdStrike Falcon prevention policies for Linux hosts. Prevention policies allow you to manage what activity will trigger detections and preventions on your hosts.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the prevention policy.",
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
				Description: "Name of the prevention policy.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the prevention policy.",
				Default:     booldefault.StaticBool(true),
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the prevention policy.",
			},
			"ioa_rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IOA Rule Group to attach to the prevention policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the prevention policy.",
			},
			"cloud_anti_malware": mlSLiderAttribute(
				"Use cloud-based machine learning informed by global analysis of executables to detect and prevent known malware for your online hosts.",
			),
			"sensor_anti_malware": mlSLiderAttribute(
				"For offline and online hosts, use sensor-based machine learning to identify and analyze unknown executables as they run to detect and prevent malware.",
			),
			"quarantine": toggleAttribute(
				"Quarantine executable files after they’re prevented by NGAV. When this is enabled, we recommend setting anti-malware prevention levels to Moderate or higher and not using other antivirus solutions.",
			),
			"upload_unknown_detection_related_executables": toggleAttribute(
				"Upload all unknown detection-related executables for advanced analysis in the cloud.",
			),
			"upload_unknown_executables": toggleAttribute(
				"Upload all unknown executables for advanced analysis in the cloud.",
			),
			"script_based_execution_monitoring": toggleAttribute(
				"Provides visibility into suspicious scripts, including shell and other scripting languages.",
			),
			"custom_blocking": toggleAttribute(
				"Block processes matching hashes that you add to IOC Management with the action set to \"Block\" or \"Block, hide detection\".",
			),
			"prevent_suspicious_processes": toggleAttribute(
				"Block processes that CrowdStrike analysts classify as suspicious. These are focused on dynamic IOAs, such as malware, exploits and other threats.",
			),
			"drift_prevention": toggleAttribute(
				"Block new processes originating from files written in a container. This prevents a container from drifting from its immutable runtime state.",
			),
			"filesystem_visibility": toggleAttribute(
				"Allows the sensor to monitor filesystem activity for additional telemetry and improved detections.",
			),
			"network_visibility": toggleAttribute(
				"Allows the sensor to monitor network activity for additional telemetry and improved detections.",
			),
			"http_visibility": toggleAttribute(
				"Allows the sensor to monitor unencrypted HTTP traffic for malicious patterns and improved detections.",
			),
			"ftp_visibility": toggleAttribute(
				"Allows the sensor to monitor unencrypted FTP traffic for malicious patterns and improved detections.",
			),
			"tls_visibility": toggleAttribute(
				"Allows the sensor to monitor TLS traffic for malicious patterns and improved detections.",
			),
			"email_protocol_visibility": toggleAttribute(
				"Allows the sensor to monitor SMTP, IMAP, and POP3 traffic for malicious patterns and improved detections.",
			),
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *preventionPolicyLinuxResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan preventionPolicyLinuxResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings := r.generatePreventionSettings(plan)
	res, diags := createPreventionPolicy(
		ctx,
		r.client,
		plan.Name.ValueString(),
		plan.Description.ValueString(),
		linuxPlatformName,
		preventionSettings,
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionPolicy := res.Payload.Resources[0]
	plan.ID = types.StringValue(*preventionPolicy.ID)
	plan.Description = types.StringValue(*preventionPolicy.Description)
	plan.Name = types.StringValue(*preventionPolicy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		actionResp, diags := updatePolicyEnabledState(
			ctx,
			r.client,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	} else {
		plan.Enabled = types.BoolValue(*preventionPolicy.Enabled)
	}

	r.assignPreventionSettings(&plan, preventionPolicy.PreventionSettings)

	emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *preventionPolicyLinuxResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state preventionPolicyLinuxResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getPreventionPolicy(ctx, r.client, state.ID.ValueString())

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ID = types.StringValue(*policy.ID)
	state.Name = types.StringValue(*policy.Name)
	state.Description = types.StringValue(*policy.Description)
	state.Enabled = types.BoolValue(*policy.Enabled)
	r.assignPreventionSettings(&state, policy.PreventionSettings)

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &state, policy.Groups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &state, policy.IoaRuleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *preventionPolicyLinuxResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan preventionPolicyLinuxResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state preventionPolicyLinuxResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncHostGroups(ctx, r.client, plan.HostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		syncRuleGroups(ctx, r.client, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	preventionSettings := r.generatePreventionSettings(plan)

	preventionPolicy, diags := updatePreventionPolicy(
		ctx,
		r.client,
		plan.Name.ValueString(),
		plan.Description.ValueString(),
		preventionSettings,
		plan.ID.ValueString(),
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*preventionPolicy.ID)
	plan.Description = types.StringValue(*preventionPolicy.Description)
	plan.Name = types.StringValue(*preventionPolicy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	r.assignPreventionSettings(&plan, preventionPolicy.PreventionSettings)

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionResp, diags := updatePolicyEnabledState(
			ctx,
			r.client,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	} else {
		plan.Enabled = types.BoolValue(*preventionPolicy.Enabled)
	}

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &plan, preventionPolicy.Groups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &plan, preventionPolicy.IoaRuleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *preventionPolicyLinuxResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state preventionPolicyLinuxResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	resp.Diagnostics.Append(deletePreventionPolicy(ctx, r.client, id)...)
}

// ImportState implements the logic to support resource imports.
func (r *preventionPolicyLinuxResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *preventionPolicyLinuxResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config preventionPolicyLinuxResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateHostGroups(ctx, config.HostGroups)...)
	resp.Diagnostics.Append(validateIOARuleGroups(ctx, config.RuleGroups)...)

	if config.CloudAntiMalware != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"cloud_anti_malware",
				*config.CloudAntiMalware,
			)...)
	}

	if config.OnSensorMLSlider != nil {
		resp.Diagnostics.Append(
			validateMlSlider(
				"sensor_anti_malware",
				*config.OnSensorMLSlider,
			)...)
	}
}

// assignRuleGroups assigns the rule groups returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignRuleGroups(
	ctx context.Context,
	config *preventionPolicyLinuxResourceModel,
	groups []*models.IoaRuleGroupsRuleGroupV1,
) diag.Diagnostics {

	ruleGroups := make([]types.String, 0, len(groups))
	for _, ruleGroup := range groups {
		ruleGroups = append(ruleGroups, types.StringValue(*ruleGroup.ID))
	}

	ruleGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)
	config.RuleGroups = ruleGroupIDs

	return diags
}

// assignHostGroups assigns the host groups returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignHostGroups(
	ctx context.Context,
	config *preventionPolicyLinuxResourceModel,
	groups []*models.HostGroupsHostGroupV1,
) diag.Diagnostics {

	hostGroups := make([]types.String, 0, len(groups))
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, types.StringValue(*hostGroup.ID))
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)
	config.HostGroups = hostGroupIDs

	return diags
}

// assignPreventionSettings assigns the prevention settings returned from the api into the resource model.
func (r *preventionPolicyLinuxResource) assignPreventionSettings(
	state *preventionPolicyLinuxResourceModel,
	categories []*models.PreventionCategoryRespV1,
) {
	toggleSettings, mlSliderSettings, _ := mapPreventionSettings(categories)

	// toggle settings
	state.UnknownDetectionRelatedExecutables = defaultBoolFalse(
		toggleSettings["UnknownDetectionRelatedExecutables"],
	)
	state.UnknownExecutables = defaultBoolFalse(toggleSettings["UnknownExecutables"])
	state.ScriptBasedExecutionMonitoring = defaultBoolFalse(
		toggleSettings["ScriptBasedExecutionMonitoring"],
	)
	state.NextGenAV = defaultBoolFalse(toggleSettings["NextGenAV"])
	state.CustomBlacklisting = defaultBoolFalse(toggleSettings["CustomBlacklisting"])
	state.PreventSuspiciousProcesses = defaultBoolFalse(
		toggleSettings["PreventSuspiciousProcesses"],
	)
	state.DriftPrevention = defaultBoolFalse(toggleSettings["DriftPrevention"])
	state.FilesystemVisibility = defaultBoolFalse(toggleSettings["FilesystemVisibility"])
	state.NetworkVisibility = defaultBoolFalse(toggleSettings["NetworkVisibility"])
	state.HTTPVisibility = defaultBoolFalse(toggleSettings["HTTPVisibility"])
	state.FTPVisibility = defaultBoolFalse(toggleSettings["FTPVisibility"])
	state.TLSVisibility = defaultBoolFalse(toggleSettings["TLSVisibility"])
	state.EmailProtocolVisibility = defaultBoolFalse(toggleSettings["EmailProtocolVisibility"])

	// mlslider settings
	state.CloudAntiMalware = mlSliderSettings["CloudAntiMalware"]
	state.OnSensorMLSlider = mlSliderSettings["OnSensorMLSlider"]
}

// generatePreventionSettings maps plan prevention settings to api params for create and update.
func (r *preventionPolicyLinuxResource) generatePreventionSettings(
	config preventionPolicyLinuxResourceModel,
) []*models.PreventionSettingReqV1 {
	preventionSettings := []*models.PreventionSettingReqV1{}

	toggleSettings := map[string]types.Bool{
		"UnknownDetectionRelatedExecutables": config.UnknownDetectionRelatedExecutables,
		"UnknownExecutables":                 config.UnknownExecutables,
		"ScriptBasedExecutionMonitoring":     config.ScriptBasedExecutionMonitoring,
		"NextGenAV":                          config.NextGenAV,
		"CustomBlacklisting":                 config.CustomBlacklisting,
		"PreventSuspiciousProcesses":         config.PreventSuspiciousProcesses,
		"DriftPrevention":                    config.DriftPrevention,
		"FilesystemVisibility":               config.FilesystemVisibility,
		"NetworkVisibility":                  config.NetworkVisibility,
		"HTTPVisibility":                     config.HTTPVisibility,
		"FTPVisibility":                      config.FTPVisibility,
		"TLSVisibility":                      config.TLSVisibility,
		"EmailProtocolVisibility":            config.EmailProtocolVisibility,
	}

	mlSliderSettings := map[string]mlSlider{
		"CloudAntiMalware": *config.CloudAntiMalware,
		"OnSensorMLSlider": *config.OnSensorMLSlider,
	}

	for k, v := range toggleSettings {
		kCopy := k
		vCopy := v
		preventionSettings = append(preventionSettings, &models.PreventionSettingReqV1{
			ID:    &kCopy,
			Value: apiToggle{Enabled: vCopy.ValueBool()},
		})
	}

	for k, v := range mlSliderSettings {
		kCopy := k
		vCopy := v
		preventionSettings = append(preventionSettings, &models.PreventionSettingReqV1{
			ID: &kCopy,
			Value: apiMlSlider{
				Prevention: vCopy.Prevention.ValueString(),
				Detection:  vCopy.Detection.ValueString(),
			},
		})
	}

	return preventionSettings
}
