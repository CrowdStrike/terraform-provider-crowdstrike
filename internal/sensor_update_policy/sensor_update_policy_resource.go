package sensorupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/exp/maps"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &sensorUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &sensorUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &sensorUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &sensorUpdatePolicyResource{}
)

// NewSensorUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewSensorUpdatePolicyResource() resource.Resource {
	return &sensorUpdatePolicyResource{}
}

// sensorUpdatePolicyResource is the resource implementation.
type sensorUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// sensorUpdatePolicyResourceModel is the resource model.
type sensorUpdatePolicyResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Name                types.String `tfsdk:"name"`
	Build               types.String `tfsdk:"build"`
	BuildArm64          types.String `tfsdk:"build_arm64"`
	Description         types.String `tfsdk:"description"`
	PlatformName        types.String `tfsdk:"platform_name"`
	UninstallProtection types.Bool   `tfsdk:"uninstall_protection"`
	LastUpdated         types.String `tfsdk:"last_updated"`
	HostGroups          types.Set    `tfsdk:"host_groups"`
	Schedule            types.Object `tfsdk:"schedule"`

	schedule *policySchedule `tfsdk:"-"`
}

// extract extracts the Go values form their terraform wrapped values.
func (d *sensorUpdatePolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics
	if !d.Schedule.IsNull() {
		d.schedule = &policySchedule{}
		diags = d.Schedule.As(ctx, d.schedule, basetypes.ObjectAsOptions{})
	}

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *sensorUpdatePolicyResourceModel) wrap(
	ctx context.Context,
	policy models.SensorUpdatePolicyV2,
	validateBuilds bool,
	validateHostGroups bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
	d.Name = types.StringValue(*policy.Name)
	d.Description = types.StringValue(*policy.Description)
	d.Enabled = types.BoolValue(*policy.Enabled)

	less := func(a, b string) bool { return a < b }
	hostGroupDiff := cmp.Diff(d.HostGroups, policy.Groups, cmpopts.SortSlices(less))
	if hostGroupDiff != "" && validateHostGroups {
		summary := "Apply ran without issue, but sensor update policy is still missing host groups. This usually happens when an invalid host group is provided."

		if len(policy.Groups) > 0 {
			hostGroupIds := []string{}

			for _, hostGroup := range policy.Groups {
				hostGroupIds = append(hostGroupIds, *hostGroup.ID)
			}
			summary = fmt.Sprintf(
				"%s\n\nThe following host groups are assigned to the policy:\n%s",
				summary,
				strings.Join(hostGroupIds, "\n"),
			)
		}
		diags.AddAttributeError(path.Root("host_groups"), "Host group mismatch", summary)
	}

	diags.Append(d.assignHostGroups(ctx, policy.Groups)...)

	if validateBuilds && d.Build.ValueString() != *policy.Settings.Build {
		diags.AddError(
			"Inconsistent build returned",
			fmt.Sprintf(
				"The API returned a build that did not match the build in plan: %s This normally occurs when an invalid build is provided, please check the build you are passing is valid. It is recommended to use crowdstrike_sensor_update_policy_builds data source to query for build numbers.\n\nIf you believe there is a bug in the provider or need help please let us know by opening a github issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
				d.Build,
			),
		)
	}
	d.Build = types.StringValue(*policy.Settings.Build)

	if d.PlatformName.IsNull() {
		d.PlatformName = types.StringValue(*policy.PlatformName)
	}

	if strings.ToLower(d.PlatformName.ValueString()) == "linux" &&
		policy.Settings.Variants != nil {
		for _, v := range policy.Settings.Variants {
			vCopy := *v
			if vCopy.Platform == nil {
				continue
			}

			if strings.EqualFold(*vCopy.Platform, linuxArm64Varient) {
				if validateBuilds && d.BuildArm64.ValueString() != *vCopy.Build {
					diags.AddError(
						"Inconsistent build_arm64 returned",
						fmt.Sprintf(
							"The API returned a build_arm64 that did not match the build in plan: %s This normally occurs when an invalid build is provided, please check the build you are passing is valid. It is recommended to use crowdstrike_sensor_update_policy_builds data source to query for build numbers.\n\nIf you believe there is a bug in the provider or need help please let us know by opening a github issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
							d.BuildArm64,
						),
					)
				}
				d.BuildArm64 = types.StringValue(*vCopy.Build)
			}
		}
	}

	if *policy.Settings.UninstallProtection == "ENABLED" {
		d.UninstallProtection = types.BoolValue(true)
	} else {
		d.UninstallProtection = types.BoolValue(false)
	}

	if policy.Settings.Scheduler != nil {
		d.schedule = &policySchedule{}
		d.schedule.Enabled = types.BoolValue(*policy.Settings.Scheduler.Enabled)

		// ignore the timzezone and time_blocks if the schedule is DISABLED
		// this allows terraform import to work correctly
		if d.schedule.Enabled.ValueBool() {
			d.schedule.Timezone = types.StringValue(*policy.Settings.Scheduler.Timezone)

			if policy.Settings.Scheduler.Schedules != nil {
				if len(policy.Settings.Scheduler.Schedules) > 0 {
					d.schedule.TimeBlocks = []timeBlock{}

					for _, s := range policy.Settings.Scheduler.Schedules {
						sCopy := s
						daysStr := []string{}

						for _, d := range sCopy.Days {
							dCopy := d
							daysStr = append(daysStr, int64ToDay[dCopy])
						}

						days, diags := types.SetValueFrom(ctx, types.StringType, daysStr)
						diags.Append(diags...)
						if diags.HasError() {
							return diags
						}
						d.schedule.TimeBlocks = append(d.schedule.TimeBlocks, timeBlock{
							Days:      days,
							StartTime: types.StringValue(*sCopy.Start),
							EndTime:   types.StringValue(*sCopy.End),
						})
					}
				}
			}
		}
	}

	if d.schedule != nil {
		policyScheduleObj, diag := types.ObjectValueFrom(
			ctx,
			d.schedule.AttributeTypes(),
			d.schedule,
		)
		d.Schedule = policyScheduleObj
		diags.Append(diag...)

	}

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *sensorUpdatePolicyResource) Configure(
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
func (r *sensorUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_update_policy"
}

// Schema defines the schema for the resource.
func (r *sensorUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Sensor Update Policy --- This resource allows management of sensor update policies in the CrowdStrike Falcon platform. Sensor update policies allow you to control the update process across a set of hosts.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Sensor update policies",
						Read:  true,
						Write: true,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the sensor update policy.",
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
				Description: "Name of the sensor update policy.",
			},
			"build": schema.StringAttribute{
				Required:    true,
				Description: "Sensor build to use for the sensor update policy.",
			},
			"build_arm64": schema.StringAttribute{
				Optional:    true,
				Description: "Sensor arm64 build to use for the sensor update policy (Linux only). Required if platform_name is Linux.",
			},
			// todo: make this case insensitive
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the sensor update policy to manage. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the sensor update policy.",
				Default:     booldefault.StaticBool(true),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the sensor update policy.",
			},
			"uninstall_protection": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable uninstall protection. Windows and Mac only.",
				Default:     booldefault.StaticBool(false),
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the sensor update policy.",
			},
			"schedule": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Prohibit sensor updates during a set of time blocks.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:    true,
						Description: "Enable the scheduler for sensor update policy.",
					},
					"timezone": schema.StringAttribute{
						Optional:    true,
						Description: "The time zones that will be used for the time blocks. Only set when enabled is true.",
						Validators: []validator.String{
							stringvalidator.OneOf(timezones...),
						},
					},
					"time_blocks": schema.SetNestedAttribute{
						Optional:    true,
						Description: "The time block to prevent sensor updates. Only set when enabled is true.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"days": schema.SetAttribute{
									Required:    true,
									ElementType: types.StringType,
									Description: "The days of the week the time block should be active.",
									Validators: []validator.Set{
										setvalidator.ValueStringsAre(
											stringvalidator.OneOfCaseInsensitive(
												maps.Keys(dayToInt64)...,
											),
										),
									},
								},
								"start_time": schema.StringAttribute{
									Required:    true,
									Description: "The start time for the time block in 24HR format. Must be atleast 1 hour before end_time.",
								},
								"end_time": schema.StringAttribute{
									Required:    true,
									Description: "The end time for the time block in 24HR format. Must be atleast 1 hour more than start_time.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *sensorUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan sensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyParams := sensor_update_policies.CreateSensorUpdatePoliciesV2Params{
		Context: ctx,
		Body: &models.SensorUpdateCreatePoliciesReqV2{
			Resources: []*models.SensorUpdateCreatePolicyReqV2{
				{
					Name:         plan.Name.ValueStringPointer(),
					PlatformName: plan.PlatformName.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					Settings: &models.SensorUpdateSettingsReqV2{
						Build: plan.Build.ValueString(),
					},
				},
			},
		},
	}

	if strings.ToLower(plan.PlatformName.ValueString()) == "linux" {
		variants := []*models.SensorUpdateBuildReqV1{
			{
				Build:    plan.BuildArm64.ValueStringPointer(),
				Platform: &linuxArm64Varient,
			},
		}
		policyParams.Body.Resources[0].Settings.Variants = variants
	}

	var uninstallProtection string
	if plan.UninstallProtection.ValueBool() {
		uninstallProtection = "ENABLED"
	} else {
		uninstallProtection = "DISABLED"
	}
	policyParams.Body.Resources[0].Settings.UninstallProtection = uninstallProtection

	if plan.schedule.Enabled.ValueBool() {
		updateSchedular := models.PolicySensorUpdateScheduler{}
		updateSchedular.Enabled = plan.schedule.Enabled.ValueBoolPointer()
		updateSchedular.Timezone = plan.schedule.Timezone.ValueStringPointer()

		if len(plan.schedule.TimeBlocks) > 0 {
			updateSchedules, diags := createUpdateSchedules(ctx, plan.schedule.TimeBlocks)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			updateSchedular.Schedules = updateSchedules
		}
		policyParams.Body.Resources[0].Settings.Scheduler = &updateSchedular
	}

	res, err := r.client.SensorUpdatePolicies.CreateSensorUpdatePoliciesV2(&policyParams)

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating sensor update policy",
			"Could not create sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}

	policy := res.Payload.Resources[0]

	plan.ID = types.StringValue(*policy.ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// by default a policy is disabled, so there is no reason to call this unless enabled is true
	if plan.Enabled.ValueBool() {
		actionResp, err := r.updatePolicyEnabledState(ctx, plan.ID.ValueString(), true)

		// todo: if we should handle scope and timeout errors instead of giving a vague error
		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling sensor update policy",
				"Could not enable sensor update policy, unexpected error: "+err.Error(),
			)
			return
		}

		if actionResp == nil {
			resp.Diagnostics.AddError(
				"Error enabling sensor update policy",
				"Could not enable sensor update policy, unexpected response of nil received",
			)
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	}

	if len(plan.HostGroups.Elements()) > 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		err = r.updateHostGroups(ctx, hostgroups.AddHostGroup, hostGroupIDs, plan.ID.ValueString())

		if err != nil {
			resp.Diagnostics.AddError(
				"Error assinging host group to policy",
				"Could not assign host group to policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	policy, diags := getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *sensorUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state sensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.SensorUpdatePolicies.GetSensorUpdatePoliciesV2(
		&sensor_update_policies.GetSensorUpdatePoliciesV2Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if notFound, ok := err.(*sensor_update_policies.GetSensorUpdatePoliciesV2NotFound); ok {
		tflog.Warn(
			ctx,
			fmt.Sprintf("sensor update policy %s not found, removing from state", state.ID),
			map[string]interface{}{"resp": notFound},
		)

		resp.State.RemoveResource(ctx)
		return
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading CrowdStrike sensor update policy",
			"Could not read CrowdStrike sensor update policy: "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	policy := res.Payload.Resources[0]

	resp.Diagnostics.Append(state.wrap(ctx, *policy, false, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *sensorUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan sensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Retrieve values from state
	var state sensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
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

	if len(hostGroupsToAdd) != 0 {
		err := r.updateHostGroups(
			ctx,
			hostgroups.AddHostGroup,
			hostGroupsToAdd,
			plan.ID.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating CrowdStrike sensor update policy",
				fmt.Sprintf(
					"Could not add host groups: (%s) to policy with id: %s \n\n %s",
					strings.Join(hostGroupsToAdd, ", "),
					plan.ID.ValueString(),
					err.Error(),
				),
			)
			return
		}
	}

	if len(hostGroupsToRemove) != 0 {
		err := r.updateHostGroups(
			ctx,
			hostgroups.RemoveHostGroup,
			hostGroupsToRemove,
			plan.ID.ValueString(),
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error updating CrowdStrike sensor update policy",
				fmt.Sprintf(
					"Could not remove host groups: (%s) from policy with id: %s \n\n %s",
					strings.Join(hostGroupsToAdd, ", "),
					plan.ID.ValueString(),
					err.Error(),
				),
			)
			return
		}
	}

	policyParams := sensor_update_policies.UpdateSensorUpdatePoliciesV2Params{
		Context: ctx,
		Body: &models.SensorUpdateUpdatePoliciesReqV2{
			Resources: []*models.SensorUpdateUpdatePolicyReqV2{
				{
					Name:        plan.Name.ValueString(),
					ID:          plan.ID.ValueStringPointer(),
					Description: plan.Description.ValueString(),
					Settings: &models.SensorUpdateSettingsReqV2{
						Build: plan.Build.ValueString(),
					},
				},
			},
		},
	}

	if strings.ToLower(plan.PlatformName.ValueString()) == "linux" {
		variants := []*models.SensorUpdateBuildReqV1{
			{
				Build:    plan.BuildArm64.ValueStringPointer(),
				Platform: &linuxArm64Varient,
			},
		}
		policyParams.Body.Resources[0].Settings.Variants = variants
	}

	if plan.UninstallProtection.ValueBool() {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "ENABLED"
	} else {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "DISABLED"

	}

	updateSchedular := models.PolicySensorUpdateScheduler{}
	updateSchedular.Timezone = plan.schedule.Timezone.ValueStringPointer()
	updateSchedular.Enabled = plan.schedule.Enabled.ValueBoolPointer()

	// WORKAROUND: The API requires a timezone when we are trying to enable/diable the Scheduler
	// due to other limitiations when it comes to imports we need to allow timezone to be null.
	// Everything should exist in state etc so knowingly adding drift isn't the best, but
	// when the schedule is disabled the timezone does not matter.
	// When the schedule is enabled the timezone is required so we will not have issues.
	// Permanent fix is to update the API to allow us to provide a null value for timezone when
	// the schedule is disabled.
	defaultTimezone := "Etc/UTC"
	if !*updateSchedular.Enabled && updateSchedular.Timezone == nil {
		updateSchedular.Timezone = &defaultTimezone
	}

	if len(plan.schedule.TimeBlocks) > 0 {
		updateSchedules, diags := createUpdateSchedules(ctx, plan.schedule.TimeBlocks)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		updateSchedular.Schedules = updateSchedules
	}
	policyParams.Body.Resources[0].Settings.Scheduler = &updateSchedular

	res, err := r.client.SensorUpdatePolicies.UpdateSensorUpdatePoliciesV2(&policyParams)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating CrowdStrike sensor update policy",
			"Could not update sensor update policy with ID: "+plan.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	policy := res.Payload.Resources[0]

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionResp, err := r.updatePolicyEnabledState(
			ctx,
			plan.ID.ValueString(),
			plan.Enabled.ValueBool(),
		)

		// todo: if we should handle scope and timeout errors instead of giving a vague error
		if err != nil {
			resp.Diagnostics.AddError(
				"Error changing sensor update policy enabled state",
				"Could not change sensor update policy enabled state, unexpected error: "+err.Error(),
			)
			return
		}

		if actionResp == nil {
			resp.Diagnostics.AddError(
				"Error enabling sensor update policy",
				"Could not enable sensor update policy, unexpected response of nil received",
			)
			return
		}

		plan.Enabled = types.BoolValue(*actionResp.Payload.Resources[0].Enabled)
	} else {
		plan.Enabled = types.BoolValue(*policy.Enabled)
	}

	policy, diags = getSensorUpdatePolicy(ctx, r.client, plan.ID.ValueString())

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *sensorUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state sensorUpdatePolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// need to make sure the policy is disabled before delete
	_, err := r.updatePolicyEnabledState(
		ctx,
		state.ID.ValueString(),
		false,
	)

	if notFound, ok := err.(*sensor_update_policies.PerformSensorUpdatePoliciesActionNotFound); ok {
		tflog.Warn(
			ctx,
			fmt.Sprintf("sensor update policy %s not found, removing from state", state.ID),
			map[string]interface{}{"resp": notFound},
		)
		return
	}

	// todo: if we should handle scope and timeout errors instead of giving a vague error
	if err != nil {
		resp.Diagnostics.AddError(
			"Error disabling sensor update policy for delete",
			"Could not disable sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}

	_, err = r.client.SensorUpdatePolicies.DeleteSensorUpdatePolicies(
		&sensor_update_policies.DeleteSensorUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if notFound, ok := err.(*sensor_update_policies.DeleteSensorUpdatePoliciesNotFound); ok {
		tflog.Warn(
			ctx,
			fmt.Sprintf("sensor update policy %s not found, removing from state", state.ID),
			map[string]interface{}{"resp": notFound},
		)
		return
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting CrowdStrike sensor update policy",
			"Could not delete sensor update policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *sensorUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *sensorUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config sensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	platform := strings.ToLower(config.PlatformName.ValueString())

	if platform == "linux" && config.BuildArm64.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("build_arm64"),
			"Attribute build_arm64 missing",
			"Attribute build_arm64 is required when platform_name is linux.",
		)

		return
	}

	if config.UninstallProtection.ValueBool() && platform == "linux" {
		resp.Diagnostics.AddAttributeError(
			path.Root("uninstall_protection"),
			"Linux doesn't support uninstall protection",
			"Uninstall protection is not supported by linux sensor update policies. Set to false or remove attribute.",
		)

		return
	}

	scheduleEnabled := config.schedule.Enabled.ValueBool()

	if !scheduleEnabled && !config.schedule.Timezone.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("schedule"),
			"Invalid schedule block: timezone provided",
			"To implement idempotency timezone and time_blocks should not be provided when enabled is false.",
		)

		return
	}

	if !scheduleEnabled && len(config.schedule.TimeBlocks) > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("schedule"),
			"Invalid schedule block: time_blocks provided",
			"To implement idempotency timezone and time_blocks should not be provided when enabled is false.",
		)

		return
	}

	if scheduleEnabled {
		if config.schedule.Timezone.IsUnknown() || config.schedule.Timezone.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("schedule"),
				"missing required attribute",
				"timezone is required when the schedule is set to enabled true.",
			)
			return
		}

		if len(config.schedule.TimeBlocks) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("schedule"),
				"missing required attribute",
				"time_blocks is required when the schedule is set to enabled true.",
			)
			return
		}
		usedDays := make(map[string]interface{})

		for _, b := range config.schedule.TimeBlocks {
			ok, err := validTime(b.StartTime.ValueString(), b.EndTime.ValueString())

			if err != nil {
				resp.Diagnostics.AddError(
					"Unable to validate config",
					"Error while validating start and end times for time_block: "+err.Error(),
				)
				return
			}

			if !ok {
				resp.Diagnostics.AddAttributeError(
					path.Root("schedule"),
					"Invalid start_time or end_time",
					"start_time and end_time should be at least 1 hour apart.",
				)
				return
			}

			days := []string{}
			resp.Diagnostics.Append(b.Days.ElementsAs(ctx, &days, false)...)

			for _, day := range days {
				_, ok := usedDays[day]
				if ok {
					resp.Diagnostics.AddAttributeError(
						path.Root("schedule"),
						"Duplicate days in schedule",
						fmt.Sprintf(
							"Day %s declared in multiple time_blocks. Multiple time_blocks can't reference the same day.",
							day,
						),
					)
				}

				usedDays[day] = nil
			}
		}
	}
}

// updatePolicyEnabledState enables or disables a sensor update policy.
func (r *sensorUpdatePolicyResource) updatePolicyEnabledState(
	ctx context.Context,
	policyID string,
	enabled bool,
) (*sensor_update_policies.PerformSensorUpdatePoliciesActionOK, error) {
	state := "disable"
	if enabled {
		state = "enable"
	}

	res, err := r.client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			ActionName: state,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	return res, err
}

// updateHostGroups will remove or add a slice of host groups
// to a slice of sensor update policies.
func (r *sensorUpdatePolicyResource) updateHostGroups(
	ctx context.Context,
	action hostgroups.HostGroupAction,
	hostGroupIDs []string,
	policyID string,
) error {
	var actionParams []*models.MsaspecActionParameter
	name := "group_id"

	for _, g := range hostGroupIDs {
		gCopy := g
		actionParam := &models.MsaspecActionParameter{
			Name:  &name,
			Value: &gCopy,
		}

		actionParams = append(actionParams, actionParam)
	}

	_, err := r.client.SensorUpdatePolicies.PerformSensorUpdatePoliciesAction(
		&sensor_update_policies.PerformSensorUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: action.String(),
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	return err
}

// assignHostGroups assigns the host groups returned from the api into the resource model.
func (r *sensorUpdatePolicyResourceModel) assignHostGroups(
	ctx context.Context,
	groups []*models.HostGroupsHostGroupV1,
) diag.Diagnostics {

	hostGroups := make([]types.String, 0, len(groups))
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, types.StringValue(*hostGroup.ID))
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)

	// allow host_groups to stay null instead of defaulting to an empty set when there are no host groups
	if r.HostGroups.IsNull() && len(hostGroupIDs.Elements()) == 0 {
		return diags
	}

	r.HostGroups = hostGroupIDs

	return diags
}
