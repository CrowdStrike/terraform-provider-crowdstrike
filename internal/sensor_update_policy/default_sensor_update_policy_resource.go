package sensorupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &defaultSensorUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &defaultSensorUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &defaultSensorUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &defaultSensorUpdatePolicyResource{}
)

// NewDefaultSensorUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewDefaultSensorUpdatePolicyResource() resource.Resource {
	return &defaultSensorUpdatePolicyResource{}
}

// defaultSensorUpdatePolicyResource is the resource implementation.
type defaultSensorUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// defaultSensorUpdatePolicyResourceModel is the resource model.
type defaultSensorUpdatePolicyResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Build               types.String `tfsdk:"build"`
	BuildArm64          types.String `tfsdk:"build_arm64"`
	PlatformName        types.String `tfsdk:"platform_name"`
	UninstallProtection types.Bool   `tfsdk:"uninstall_protection"`
	LastUpdated         types.String `tfsdk:"last_updated"`
	Schedule            types.Object `tfsdk:"schedule"`

	schedule *policySchedule `tfsdk:"-"`
}

// extract extracts the Go values form their terraform wrapped values.
func (d *defaultSensorUpdatePolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics
	if !d.Schedule.IsNull() {
		d.schedule = &policySchedule{}
		diags = d.Schedule.As(ctx, d.schedule, basetypes.ObjectAsOptions{})
	}

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *defaultSensorUpdatePolicyResourceModel) wrap(
	ctx context.Context,
	policy models.SensorUpdatePolicyV2,
	validateBuilds bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
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

	if strings.ToLower(d.PlatformName.ValueString()) != strings.ToLower(*policy.PlatformName) {
		diags.AddError(
			"Mismatch platform_name",
			fmt.Sprintf(
				"The api returned the following platform_name: %s for default sensor update policy: %s, the terraform config has a platform_name value of %s. This should not be possible, if you imported this resource ensure you updated the platform_name to the correct value in your terraform config.\n\nIf you believe there is a bug in the provider or need help please let us know by opening a github issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
				*policy.PlatformName,
				d.ID,
				d.PlatformName.ValueString(),
			),
		)

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
func (r *defaultSensorUpdatePolicyResource) Configure(
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
func (r *defaultSensorUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_sensor_update_policy"
}

// Schema defines the schema for the resource.
func (r *defaultSensorUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Default Sensor Update Policy --- This resource allows management of the default sensor update policy in the CrowdStrike Falcon platform.\n\n%s",
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
			"build": schema.StringAttribute{
				Required:    true,
				Description: "Sensor build to use for the default sensor update policy.",
			},
			"build_arm64": schema.StringAttribute{
				Optional:    true,
				Description: "Sensor arm64 build to use for the default sensor update policy (Linux only). Required if platform_name is Linux.",
			},
			// todo: make this case insensitive
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Chooses which default sensor update policy to manage. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Linux", "Mac"),
				},
			},
			"uninstall_protection": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable uninstall protection. Windows and Mac only.",
				Default:     booldefault.StaticBool(false),
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

// Create imports the resource into state and configures it. The default resource policy can't be created or deleted.
func (r *defaultSensorUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan defaultSensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.getDefaultPolicy(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	resp.Diagnostics.Append(
		resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, diags = r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *defaultSensorUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultSensorUpdatePolicyResourceModel
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

	resp.Diagnostics.Append(state.wrap(ctx, *policy, false)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *defaultSensorUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultSensorUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(plan.wrap(ctx, *policy, true)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *defaultSensorUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// We can not delete the default sensor update policy, so we will just remove it from state.
	return
}

// ImportState implements the logic to support resource imports.
func (r *defaultSensorUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *defaultSensorUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {

	var config defaultSensorUpdatePolicyResourceModel
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

func (r *defaultSensorUpdatePolicyResource) updateDefaultPolicy(
	ctx context.Context,
	config *defaultSensorUpdatePolicyResourceModel,
) (*models.SensorUpdatePolicyV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	policyParams := sensor_update_policies.UpdateSensorUpdatePoliciesV2Params{
		Context: ctx,
		Body: &models.SensorUpdateUpdatePoliciesReqV2{
			Resources: []*models.SensorUpdateUpdatePolicyReqV2{
				{
					ID: config.ID.ValueStringPointer(),
					Settings: &models.SensorUpdateSettingsReqV2{
						Build: config.Build.ValueString(),
					},
				},
			},
		},
	}

	if strings.ToLower(config.PlatformName.ValueString()) == "linux" {
		variants := []*models.SensorUpdateBuildReqV1{
			{
				Build:    config.BuildArm64.ValueStringPointer(),
				Platform: &linuxArm64Varient,
			},
		}
		policyParams.Body.Resources[0].Settings.Variants = variants
	}

	if config.UninstallProtection.ValueBool() {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "ENABLED"
	} else {
		policyParams.Body.Resources[0].Settings.UninstallProtection = "DISABLED"

	}

	updateSchedular := models.PolicySensorUpdateScheduler{}
	updateSchedular.Timezone = config.schedule.Timezone.ValueStringPointer()
	updateSchedular.Enabled = config.schedule.Enabled.ValueBoolPointer()

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

	if len(config.schedule.TimeBlocks) > 0 {
		updateSchedules, diags := createUpdateSchedules(ctx, config.schedule.TimeBlocks)
		diags.Append(diags...)
		if diags.HasError() {
			return nil, diags
		}

		updateSchedular.Schedules = updateSchedules
	}
	policyParams.Body.Resources[0].Settings.Scheduler = &updateSchedular

	res, err := r.client.SensorUpdatePolicies.UpdateSensorUpdatePoliciesV2(&policyParams)

	if err != nil {
		diags.AddError(
			"Error updating CrowdStrike sensor update policy",
			"Could not update sensor update policy with ID: "+config.ID.ValueString()+": "+err.Error(),
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]

	return policy, diags
}

func (r *defaultSensorUpdatePolicyResource) getDefaultPolicy(
	ctx context.Context,
	platformName string,
) (*models.SensorUpdatePolicyV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platformName = caser.String(platformName)

	filter := fmt.Sprintf(
		`platform_name:'%s'+name.raw:'platform_default'+description:'platform'+description:'default'+description:'policy'`,
		platformName,
	)
	sort := "precedence.desc"

	res, err := r.client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(
		&sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to get default sensor update policy",
			fmt.Sprintf("Failed to get default sensor update policy: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Unable to find default sensor update policy",
			fmt.Sprintf(
				"No policy matched filter: %s, a default policy should exist. Please report this issue to the provider developers.",
				filter,
			),
		)

		return nil, diags
	}

	// we sort by descending precedence, default policy is always first
	defaultPolicy := res.Payload.Resources[0]

	return defaultPolicy, diags
}
