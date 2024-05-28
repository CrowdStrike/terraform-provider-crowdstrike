package fim

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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

// hostGroupAction action for policies-host-group api.
type hostGroupAction int

const (
	removeHostGroup hostGroupAction = iota
	addHostGroup
)

// String convert hostGroupAction to string value the api accepts.
func (h hostGroupAction) String() string {
	return [...]string{"unassign", "assign"}[h]
}

// ruleGroupAction action for policies-host-group api.
type ruleGroupAction int

const (
	removeRuleGroup ruleGroupAction = iota
	addRuleGroup
	precedenceRuleGroup
)

// String convert hostGroupAction to string value the api accepts.
func (h ruleGroupAction) String() string {
	return [...]string{"unassign", "assign", "precedence"}[h]
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &fimPolicyResource{}
	_ resource.ResourceWithConfigure      = &fimPolicyResource{}
	_ resource.ResourceWithImportState    = &fimPolicyResource{}
	_ resource.ResourceWithValidateConfig = &fimPolicyResource{}
)

// NewFIMPolicyResource is a helper function to simplify the provider implementation.
func NewFIMPolicyResource() resource.Resource {
	return &fimPolicyResource{}
}

// fimPolicyResource is the resource implementation.
type fimPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// fimPolicyResourceModel is the resource implementation.
type fimPolicyResourceModel struct {
	ID                  types.String          `tfsdk:"id"`
	Name                types.String          `tfsdk:"name"`
	Description         types.String          `tfsdk:"description"`
	PlatformName        types.String          `tfsdk:"platform_name"`
	Enabled             types.Bool            `tfsdk:"enabled"`
	HostGroups          types.Set             `tfsdk:"host_groups"`
	RuleGroups          types.Set             `tfsdk:"rule_groups"`
	LastUpdated         types.String          `tfsdk:"last_updated"`
	ScheduledExclusions []*scheduledExclusion `tfsdk:"scheduled_exclusions"`
}

type scheduledExclusion struct {
	ID          types.String       `tfsdk:"id"`
	Name        types.String       `tfsdk:"name"`
	Description types.String       `tfsdk:"description"`
	Processes   types.String       `tfsdk:"processes"`
	Users       types.String       `tfsdk:"users"`
	StartDate   types.String       `tfsdk:"start_date"`
	StartTime   types.String       `tfsdk:"start_time"`
	EndDate     types.String       `tfsdk:"end_date"`
	EndTime     types.String       `tfsdk:"end_time"`
	Timezone    types.String       `tfsdk:"timezone"`
	Repeated    *repeatedExclusion `tfsdk:"repeated"`
}

type repeatedExclusion struct {
	AllDay            types.Bool   `tfsdk:"all_day"`
	StartTime         types.String `tfsdk:"start_time"`
	EndTime           types.String `tfsdk:"end_time"`
	Frequency         types.String `tfsdk:"frequency"`
	MonthlyOccurrence types.String `tfsdk:"monthly_occurrence"`
	DaysOfWeek        types.Set    `tfsdk:"days_of_week"`
	DaysOfMonth       types.Set    `tfsdk:"days_of_month"`
}

// Configure adds the provider configured client to the resource.
func (r *fimPolicyResource) Configure(
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
func (r *fimPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_filevantage_policy"
}

// Schema defines the schema for the resource.
func (r *fimPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the filevantage policy.",
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
				Description: "Name of the filevantage policy.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable the filevantage policy.",
				Default:     booldefault.StaticBool(true),
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the filevantage policy to manage. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the filevantage policy.",
			},
			"rule_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Rule Group ids to attach to the filevantage policy. Rule groups must be the same type as the policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the filevantage policy.",
			},
			"scheduled_exclusions": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Scheduled exclusions for the filevantage policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the scheduled exclusion.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the scheduled exclusion.",
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Description of the scheduled exclusion.",
						},
						"processes": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "A comma separated list of processes to exclude changes from. Example: **/run_me.sh excludes changes made by run_me.sh in any location",
						},
						"users": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "A comma separated list of users to exclude changes from. Example: user1,user2,admin* excludes changes made by user1, user2, and any user starting with admin",
						},
						"start_date": schema.StringAttribute{
							Required:    true,
							Description: "The start date of the scheduled exclusion. Format: YYYY-MM-DD",
						},
						"start_time": schema.StringAttribute{
							Required:    true,
							Description: "The start time of the scheduled exclusion in 24 hour format. Format: HH:MM",
						},
						"end_date": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The end date of the scheduled exclusion. Format: YYYY-MM-DD",
						},
						"end_time": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "The end time of the scheduled exclusion in 24 hour format. Format: HH:MM",
						},
						"timezone": schema.StringAttribute{
							Required:    true,
							Description: "The timezone to use for the time fields. See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.",
						},
						"repeated": schema.SingleNestedAttribute{
							Optional:    true,
							Description: "Repeated scheduled exclusion",
							Attributes: map[string]schema.Attribute{
								"all_day": schema.BoolAttribute{
									Required:    true,
									Description: "If the exclusion is all day.",
								},
								"start_time": schema.StringAttribute{
									Optional:    true,
									Computed:    true,
									Description: "The start time to allow the scheduled exclusion in 24 hour format. Format: HH:MM required if all_day is false",
								},
								"end_time": schema.StringAttribute{
									Optional:    true,
									Computed:    true,
									Description: "The end time to end the scheduled exclusion in 24 hour format. Format: HH:MM required if all_day is false",
								},
								"frequency": schema.StringAttribute{
									Required:    true,
									Description: "The frequency of the exclusion. Options: daily, weekly, monthly",
									Validators: []validator.String{
										stringvalidator.OneOf("daily", "weekly", "monthly"),
									},
								},
								"monthly_occurrence": schema.StringAttribute{
									Optional:    true,
									Computed:    true,
									Description: "The monthly occurrence of the exclusion. Either specify a week (first, second, third, fourth) or set to days to specify days of the month. Options: first, second, third, fourth, days. Required if frequency is set to monthly",
									Validators: []validator.String{
										stringvalidator.OneOf(
											"1st",
											"2nd",
											"3rd",
											"4th",
											"Last",
											"Days",
										),
									},
								},
								"days_of_week": schema.SetAttribute{
									Optional:    true,
									Computed:    true,
									Description: "The days of the week to allow the exclusion. Required if frequency is set to weekly or set to monthly and monthly_occurrence is set to a week. Options: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday",
									ElementType: types.StringType,
									Validators: []validator.Set{
										setvalidator.ValueStringsAre(
											stringvalidator.OneOf(
												"Sunday",
												"Monday",
												"Tuesday",
												"Wednesday",
												"Thursday",
												"Friday",
												"Saturday",
											),
										),
									},
								},
								"days_of_month": schema.SetAttribute{
									Optional:    true,
									Computed:    true,
									Description: "The days of the month to allow the exclusion. Required if frequency is set to monthly and monthly_occurrence is set to days. Options: 1-31",
									ElementType: types.Int64Type,
									Validators: []validator.Set{
										setvalidator.ValueInt64sAre(int64validator.All(
											int64validator.AtLeast(1),
											int64validator.AtMost(31),
										)),
									},
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
func (r *fimPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {

	var plan fimPolicyResourceModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.createFIMPolicy(ctx, plan)

	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	plan.Description = types.StringValue(policy.Description)
	plan.Name = types.StringValue(policy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Update state before continuing because we already created the Policy, but
	// other operations may fail resulting in created, but not tracked resources.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Enabled.ValueBool() {
		policy, diags = r.updatePolicy(
			ctx,
			plan,
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	plan.Enabled = types.BoolValue(*policy.Enabled)

	emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncHostGroups(ctx, plan.HostGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncRuleGroups(ctx, plan.RuleGroups, emptySet, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncScheduledExclusions(
			ctx,
			plan.ScheduledExclusions,
			[]*scheduledExclusion{},
			plan.ID.ValueString(),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusions, diags := r.getScheduledExclusions(ctx, plan.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(r.assignScheduledExclusions(ctx, &plan, exclusions)...)
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
func (r *fimPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state fimPolicyResourceModel
	var oldState fimPolicyResourceModel
	diags := req.State.Get(ctx, &oldState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if oldState.ID.ValueString() == "" {
		return
	}

	policy, diags := r.getFIMPolicy(ctx, oldState.ID.ValueString())

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostGroups := []*models.PoliciesAssignedHostGroup{}
	ruleGroups := []*models.PoliciesAssignedRuleGroup{}

	if policy != nil {
		state.ID = types.StringValue(*policy.ID)
		state.Name = types.StringValue(policy.Name)
		state.Description = types.StringValue(policy.Description)
		state.Enabled = types.BoolValue(*policy.Enabled)
		state.PlatformName = types.StringValue(policy.Platform)
		hostGroups = policy.HostGroups
		ruleGroups = policy.RuleGroups
	}

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &state, hostGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &state, ruleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusions, diags := r.getScheduledExclusions(ctx, oldState.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignScheduledExclusions(ctx, &state, exclusions)...)
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
func (r *fimPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan fimPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state fimPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncHostGroups(ctx, plan.HostGroups, state.HostGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncRuleGroups(ctx, plan.RuleGroups, state.RuleGroups, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncScheduledExclusions(
			ctx,
			plan.ScheduledExclusions,
			state.ScheduledExclusions,
			plan.ID.ValueString(),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.updatePolicy(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	plan.Description = types.StringValue(policy.Description)
	plan.Name = types.StringValue(policy.Name)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	plan.Enabled = types.BoolValue(*policy.Enabled)

	resp.Diagnostics.Append(r.assignHostGroups(ctx, &plan, policy.HostGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.assignRuleGroups(ctx, &plan, policy.RuleGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	exclusions, diags := r.getScheduledExclusions(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.assignScheduledExclusions(ctx, &plan, exclusions)...)
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
func (r *fimPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state fimPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteFIMPolicy(ctx, state)...)
}

// ImportState implements the logic to support resource imports.
func (r *fimPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *fimPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config fimPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for i, exclusion := range config.ScheduledExclusions {
		repeated := exclusion.Repeated
		attrPath := path.Root("scheduled_exclusions").AtListIndex(i)

		_, err := time.LoadLocation(exclusion.Timezone.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				attrPath,
				"Invalid timezone in scheduled exclusion",
				"Invalid timezone see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for valid timezones.",
			)
		}

		resp.Diagnostics.Append(
			valideDate(attrPath, exclusion.StartDate.ValueString())...)
		resp.Diagnostics.Append(
			valideDate(attrPath, exclusion.EndDate.ValueString())...)
		resp.Diagnostics.Append(
			valideTime(attrPath, exclusion.StartTime.ValueString())...)
		resp.Diagnostics.Append(
			valideTime(attrPath, exclusion.EndTime.ValueString())...)

		// validate repeated
		if repeated == nil {
			continue
		}

		resp.Diagnostics.Append(
			valideTime(attrPath, repeated.StartTime.ValueString())...)
		resp.Diagnostics.Append(
			valideTime(attrPath, repeated.EndTime.ValueString())...)

		summaryMsg := "Invalid repeated attribute on scheduled exclusion"

		if !repeated.AllDay.ValueBool() && repeated.StartTime.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(
				attrPath,
				summaryMsg,
				"start_time is required if all_day is false",
			)
		}
		if !repeated.AllDay.ValueBool() && repeated.EndTime.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(
				attrPath,
				summaryMsg,
				"end_time is required in repeated if all_day is false",
			)
		}

		// required attributes for when frequency is weekly
		if repeated.Frequency.ValueString() == "weekly" &&
			len(repeated.DaysOfWeek.Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				attrPath,
				summaryMsg,
				"days_of_week is required in repeated if frequency is weekly",
			)
		}

		// required attributes for when frequency is monthly
		if repeated.Frequency.ValueString() == "monthly" {
			switch repeated.MonthlyOccurrence.ValueString() {
			case "":
				resp.Diagnostics.AddAttributeError(
					attrPath,
					summaryMsg,
					"monthly_occurrence is required in repeated if frequency is monthly",
				)
			case "Days":
				if len(repeated.DaysOfMonth.Elements()) == 0 {
					resp.Diagnostics.AddAttributeError(
						attrPath,
						summaryMsg,
						"days_of_month is required in repeated if frequency is monthly and monthly_occurrence is days",
					)
				}
			case "1st", "2nd", "3rd", "4th", "Last":
				if len(repeated.DaysOfWeek.Elements()) == 0 {
					resp.Diagnostics.AddAttributeError(
						attrPath,
						summaryMsg,
						"days_of_week is required in repeated if frequency is monthly and monthly_occurrence is set to a week",
					)
				}
			}
		}
	}
}

// deleteFIMPolicy deletes a filevantage policy by id.
func (r *fimPolicyResource) deleteFIMPolicy(
	ctx context.Context,
	config fimPolicyResourceModel,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// deleting a resource that does not exist.
	if config.ID.ValueString() == "" {
		return diags
	}

	config.Enabled = types.BoolValue(false)

	_, diags = r.updatePolicy(ctx, config)

	if diags.HasError() {
		return diags
	}

	_, err := r.client.Filevantage.DeletePolicies(
		&filevantage.DeletePoliciesParams{
			Context: ctx,
			Ids:     []string{config.ID.ValueString()},
		},
	)

	if err != nil {
		diags.AddError(
			"Error deleting filevantage policy",
			fmt.Sprintf(
				"Could not delete filevantage policy (%s): \n\n %s",
				config.ID.ValueString(),
				err.Error(),
			),
		)
	}

	return diags
}

// updatePolicy updates basic information about the filevantage policy.
func (r *fimPolicyResource) updatePolicy(
	ctx context.Context,
	config fimPolicyResourceModel,
) (*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.Filevantage.UpdatePolicies(
		&filevantage.UpdatePoliciesParams{
			Context: ctx,
			Body: &models.PoliciesUpdateRequest{
				ID:          config.ID.ValueStringPointer(),
				Enabled:     config.Enabled.ValueBool(),
				Name:        config.Name.ValueString(),
				Description: config.Description.ValueString(),
			},
		},
	)

	if err != nil {
		diags.AddError(
			"Error updating filevantage policy",
			fmt.Sprintf(
				"Could not update filevantage policy (%s), unexpected error: \n\n %s",
				config.ID.ValueString(),
				err.Error(),
			),
		)
	}

	return res.Payload.Resources[0], diags
}

// getFIMPolicy gets a FileVantge policy.
func (r *fimPolicyResource) getFIMPolicy(
	ctx context.Context,
	id string,
) (*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.Filevantage.GetPolicies(&filevantage.GetPoliciesParams{
		Context: ctx,
		Ids:     []string{id},
	})

	if err != nil {
		diags.AddError(
			"Failed to get FileVantage policy",
			fmt.Sprintf("Failed to get FileVantage policy (%s): %s", id, err),
		)

		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// createFIMPolicy create a new FileVantge policy from the resource model.
func (r *fimPolicyResource) createFIMPolicy(
	ctx context.Context,
	config fimPolicyResourceModel,
) (*models.PoliciesPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := r.client.Filevantage.CreatePolicies(&filevantage.CreatePoliciesParams{
		Context: ctx,
		Body: &models.PoliciesCreateRequest{
			Name:        config.Name.ValueStringPointer(),
			Description: config.Description.ValueString(),
			Platform:    config.PlatformName.ValueString(),
		},
	})

	if err != nil {
		diags.AddError(
			"Failed to create FileVantage policy",
			fmt.Sprintf("Failed to create FileVantage policy: %s", err),
		)

		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Failed to create FileVantage policy",
			"No error returned from api but no policy was created. Please report this issue to the provider developers.",
		)

		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// syncHostGroups will sync the host groups from the resource model to the api.
func (r *fimPolicyResource) syncHostGroups(
	ctx context.Context,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.IDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(r.updateHostGroups(ctx, addHostGroup, groupsToAdd, id)...)
	diags.Append(r.updateHostGroups(ctx, removeHostGroup, groupsToRemove, id)...)

	return diags
}

// updateHostGroups will remove or add a slice of host groups
// to a slice of filevantage policies.
func (r *fimPolicyResource) updateHostGroups(
	ctx context.Context,
	action hostGroupAction,
	hostGroupIDs []string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(hostGroupIDs) == 0 {
		return diags
	}

	res, err := r.client.Filevantage.UpdatePolicyHostGroups(
		&filevantage.UpdatePolicyHostGroupsParams{
			Context:  ctx,
			Action:   action.String(),
			Ids:      hostGroupIDs,
			PolicyID: id,
		},
	)

	if err != nil {
		diags.AddError(
			"Error updating filevantage policy host groups",
			fmt.Sprintf(
				"Could not %s filevantage policy (%s) host groups (%s), unexpected error: %s",
				action.String(),
				id,
				strings.Join(hostGroupIDs, ","),
				err.Error(),
			),
		)
	}

	if res != nil && res.Payload == nil {
		return diags
	}

	for _, err := range res.Payload.Errors {
		diags.AddError(
			"Error updating filevantage policy host groups",
			fmt.Sprintf(
				"Could not %s filevantage policy (%s) host group (%s): %s",
				action.String(),
				id,
				err.ID,
				err.String(),
			),
		)
	}

	return diags
}

// assignHostGroups assigns the host groups returned from the api into the resource model.
func (r *fimPolicyResource) assignHostGroups(
	ctx context.Context,
	config *fimPolicyResourceModel,
	groups []*models.PoliciesAssignedHostGroup,
) diag.Diagnostics {

	var hostGroups []string
	for _, hostGroup := range groups {
		hostGroups = append(hostGroups, *hostGroup.ID)
	}

	hostGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, hostGroups)
	config.HostGroups = hostGroupIDs

	return diags
}

// syncRuleGroups sync the rule groups from the resource model to the api.
func (r *fimPolicyResource) syncRuleGroups(
	ctx context.Context,
	planGroups, stateGroups types.Set,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	groupsToAdd, groupsToRemove, diags := utils.IDsToModify(
		ctx,
		planGroups,
		stateGroups,
	)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	diags.Append(r.updateRuleGroups(ctx, addRuleGroup, groupsToAdd, id)...)
	diags.Append(r.updateRuleGroups(ctx, removeRuleGroup, groupsToRemove, id)...)

	return diags
}

// updateRuleGroups remove or add a slice of rule groups
// to a slice of filevantage policies.
func (r *fimPolicyResource) updateRuleGroups(
	ctx context.Context,
	action ruleGroupAction,
	ruleGroupIDs []string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	if len(ruleGroupIDs) == 0 {
		return diags
	}

	res, err := r.client.Filevantage.UpdatePolicyRuleGroups(
		&filevantage.UpdatePolicyRuleGroupsParams{
			Context:  ctx,
			Action:   action.String(),
			Ids:      ruleGroupIDs,
			PolicyID: id,
		},
	)

	if err != nil {
		diags.AddError(
			"Error updating filevantage policy rule groups",
			fmt.Sprintf(
				"Could not %s filevantage policy (%s) rule groups (%s), unexpected error: %s",
				action.String(),
				id,
				strings.Join(ruleGroupIDs, ","),
				err.Error(),
			),
		)
	}

	if res != nil && res.Payload == nil {
		return diags
	}

	for _, err := range res.Payload.Errors {
		errStr := err.String()

		if strings.Contains(errStr, "resources not allowed") {
			errStr = "Rule group type does not match policy type"
		}

		diags.AddError(
			"Error updating filevantage policy rule groups",
			fmt.Sprintf(
				"Could not %s filevantage policy (%s) rule group (%s): %s",
				action.String(),
				id,
				err.ID,
				errStr,
			),
		)
	}

	return diags
}

// assignRuleGroups assigns the rule groups returned from the api into the resource model.
func (r *fimPolicyResource) assignRuleGroups(
	ctx context.Context,
	config *fimPolicyResourceModel,
	groups []*models.PoliciesAssignedRuleGroup,
) diag.Diagnostics {
	var ruleGroups []string
	for _, ruleGroup := range groups {
		ruleGroups = append(ruleGroups, *ruleGroup.ID)
	}

	ruleGroupIDs, diags := types.SetValueFrom(ctx, types.StringType, ruleGroups)
	config.RuleGroups = ruleGroupIDs

	return diags
}

// syncScheduledExclusions syncs the scheduled exclusions from the resource model to the api.
func (r *fimPolicyResource) syncScheduledExclusions(
	ctx context.Context,
	planExclusions, stateExclusions []*scheduledExclusion,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	var exclusionsToCreate []scheduledExclusion
	var exclusionsToDelete []string
	var exclusionsToUpdate []scheduledExclusion

	var stateMap = make(map[string]scheduledExclusion)
	var planMap = make(map[string]scheduledExclusion)

	for _, exclusion := range stateExclusions {
		exclusion := *exclusion
		stateMap[exclusion.ID.ValueString()] = exclusion
	}

	for _, exclusion := range planExclusions {
		exclusion := *exclusion

		// null id means it is a new exclusion
		if exclusion.ID.IsNull() || exclusion.ID.IsUnknown() {
			exclusionsToCreate = append(exclusionsToCreate, exclusion)
			continue
		}

		planMap[exclusion.ID.ValueString()] = exclusion
		if _, ok := stateMap[exclusion.ID.ValueString()]; ok {
			if !reflect.DeepEqual(exclusion, stateMap[exclusion.ID.ValueString()]) {
				exclusionsToUpdate = append(exclusionsToUpdate, exclusion)
			}
		}
	}

	for _, exclusion := range stateExclusions {
		exclusion := *exclusion
		if _, ok := planMap[exclusion.ID.ValueString()]; !ok {
			exclusionsToDelete = append(exclusionsToDelete, exclusion.ID.ValueString())
		}
	}

	diags.Append(r.createScheduledExclusions(ctx, exclusionsToCreate, id)...)
	diags.Append(r.updateScheduledExclusion(ctx, exclusionsToUpdate, id)...)
	diags.Append(r.deleteScheduledExclusions(ctx, exclusionsToDelete, id)...)

	return diags
}

// assignScheduledExclusions assigns the scheduled exclusions returned from the api into the resource model.
func (r *fimPolicyResource) assignScheduledExclusions(
	ctx context.Context,
	config *fimPolicyResourceModel,
	exclusions []*models.ScheduledexclusionsScheduledExclusion,
) diag.Diagnostics {
	var diags diag.Diagnostics
	var scheduledExclusions []*scheduledExclusion

	for _, e := range exclusions {
		var exclusion scheduledExclusion
		var repeated repeatedExclusion
		if e.Repeated != nil {
			repeated.AllDay = types.BoolValue(e.Repeated.AllDay)
			repeated.StartTime = types.StringValue(e.Repeated.StartTime)
			repeated.EndTime = types.StringValue(e.Repeated.EndTime)
			repeated.Frequency = types.StringValue(e.Repeated.Frequency)
			repeated.MonthlyOccurrence = types.StringValue(e.Repeated.Occurrence)

			daysOfWeekSet, diags := types.SetValueFrom(
				ctx,
				types.StringType,
				e.Repeated.WeeklyDays,
			)

			if diags.HasError() {
				return diags
			}

			repeated.DaysOfWeek = daysOfWeekSet
			daysOfMonthSet, diags := types.SetValueFrom(
				ctx,
				types.Int64Type,
				e.Repeated.MonthlyDays,
			)

			if diags.HasError() {
				return diags
			}

			repeated.DaysOfMonth = daysOfMonthSet
		}

		tStart, err := time.Parse(time.RFC3339, e.ScheduleStart)
		if err == nil {
			exclusion.StartDate = types.StringValue(tStart.Format("2006-01-02"))
			exclusion.StartTime = types.StringValue(tStart.Format("15:04"))
		}

		tEnd, err := time.Parse(time.RFC3339, e.ScheduleEnd)
		if err == nil {
			exclusion.EndDate = types.StringValue(tEnd.Format("2006-01-02"))
			exclusion.EndTime = types.StringValue(tEnd.Format("15:04"))
		}

		exclusion.ID = types.StringValue(*e.ID)
		exclusion.Name = types.StringValue(*e.Name)
		exclusion.Description = types.StringValue(e.Description)
		exclusion.Processes = types.StringValue(e.Processes)
		exclusion.Users = types.StringValue(e.Users)
		exclusion.Timezone = types.StringValue(*e.Timezone)
		exclusion.Repeated = &repeated

		scheduledExclusions = append(scheduledExclusions, &exclusion)
	}

	config.ScheduledExclusions = scheduledExclusions

	return diags
}

// getScheduledExclusions gets the scheduled exclusions for a filevantage policy.
func (r *fimPolicyResource) getScheduledExclusions(
	ctx context.Context,
	id string,
) ([]*models.ScheduledexclusionsScheduledExclusion, diag.Diagnostics) {
	var diags diag.Diagnostics
	var exclusions []*models.ScheduledexclusionsScheduledExclusion

	queryParams := filevantage.QueryScheduledExclusionsParams{
		Context:  ctx,
		PolicyID: id,
	}

	queryRes, err := r.client.Filevantage.QueryScheduledExclusions(&queryParams)

	if err != nil {
		diags.AddError(
			"Error getting scheduled exclusions",
			fmt.Sprintf("Could not get scheduled exclusions: %s", err.Error()),
		)

		return exclusions, diags
	}

	if queryRes == nil || queryRes.Payload == nil {
		return exclusions, diags
	}

	if len(queryRes.Payload.Resources) == 0 {
		return exclusions, diags
	}

	getParams := filevantage.GetScheduledExclusionsParams{
		Context:  ctx,
		PolicyID: id,
		Ids:      queryRes.Payload.Resources,
	}

	res, err := r.client.Filevantage.GetScheduledExclusions(&getParams)

	if err != nil {
		diags.AddError(
			"Error getting scheduled exclusions",
			fmt.Sprintf("Could not get scheduled exclusions: %s", err.Error()),
		)

		return exclusions, diags
	}

	if res != nil && res.Payload != nil {
		return res.Payload.Resources, diags
	}

	return exclusions, diags
}

// updateScheduledExclusion update a scheduled exclusion attached to a filevantage policy.
func (r *fimPolicyResource) updateScheduledExclusion(
	ctx context.Context,
	exclusions []scheduledExclusion,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(exclusions) == 0 {
		return diags
	}

	for _, exclusion := range exclusions {
		scheduledStart, diags := r.createRFC3339DateTime(
			exclusion.StartDate.ValueString(),
			exclusion.StartTime.ValueString(),
			exclusion.Timezone.ValueString(),
		)
		diags.Append(diags...)
		if diags.HasError() {
			return diags
		}

		scheduledEnd, diags := r.createRFC3339DateTime(
			exclusion.EndDate.ValueString(),
			exclusion.EndTime.ValueString(),
			exclusion.Timezone.ValueString(),
		)
		diags.Append(diags...)
		if diags.HasError() {
			return diags
		}

		params := filevantage.UpdateScheduledExclusionsParams{
			Context: ctx,
			Body: &models.ScheduledexclusionsUpdateRequest{
				PolicyID:      policyID,
				ID:            exclusion.ID.ValueStringPointer(),
				Name:          exclusion.Name.ValueStringPointer(),
				Description:   exclusion.Description.ValueString(),
				Timezone:      exclusion.Timezone.ValueStringPointer(),
				Processes:     exclusion.Processes.ValueString(),
				Users:         exclusion.Users.ValueString(),
				ScheduleStart: scheduledStart,
			},
		}

		params.Body.ScheduleEnd = scheduledEnd

		if exclusion.Repeated != nil {
			monthlyDaysTf := []types.Int64{}
			monthlyDays := []int64{}
			weeklyDays := []string{}

			diags.Append(exclusion.Repeated.DaysOfMonth.ElementsAs(ctx, &monthlyDaysTf, true)...)
			if diags.HasError() {
				return diags
			}

			for _, d := range monthlyDaysTf {
				if d.IsNull() || d.IsUnknown() {
					continue
				}

				monthlyDays = append(monthlyDays, d.ValueInt64())
			}

			for _, d := range exclusion.Repeated.DaysOfWeek.Elements() {
				var day string
				if d.IsNull() || d.IsUnknown() {
					continue
				}

				v, err := d.ToTerraformValue(ctx)
				if err != nil {
					continue
				}
				err = v.Copy().As(&day)
				if err != nil {
					continue
				}
				weeklyDays = append(weeklyDays, day)
			}

			params.Body.Repeated = &models.ScheduledexclusionsRepeated{
				AllDay:      exclusion.Repeated.AllDay.ValueBool(),
				StartTime:   exclusion.Repeated.StartTime.ValueString(),
				EndTime:     exclusion.Repeated.EndTime.ValueString(),
				Frequency:   exclusion.Repeated.Frequency.ValueString(),
				Occurrence:  exclusion.Repeated.MonthlyOccurrence.ValueString(),
				MonthlyDays: monthlyDays,
				WeeklyDays:  weeklyDays,
			}
		}

		res, err := r.client.Filevantage.UpdateScheduledExclusions(&params)

		if err != nil {
			errMsg := fmt.Sprintf(
				"Could not update scheduled exclusion (%s): %s",
				exclusion.ID.ValueString(),
				err.Error(),
			)
			if strings.Contains(err.Error(), "500") {
				errMsg = fmt.Sprintf(
					"Could not update scheduled exclusion (%s): Returned error code 500, this could be caused by inproperly formmated users or processes strings. \n\n %s",
					exclusion.ID.ValueString(),
					err.Error(),
				)
			}

			diags.AddError("Error updating scheduled exclusion", errMsg)

			return diags
		}

		if res != nil && res.Payload != nil {
			for _, err := range res.Payload.Errors {
				diags.AddError(
					"Error updating scheduled exclusion",
					fmt.Sprintf(
						"Could not update scheduled exclusion (%s): %s",
						exclusion.ID.ValueString(),
						err.String(),
					),
				)
			}

			if diags.HasError() {
				return diags
			}
		}
	}

	return diags
}

// deleteScheduledExclusions delete scheduled exclusions from a filevantage policy.
func (r *fimPolicyResource) deleteScheduledExclusions(
	ctx context.Context,
	exclusionIDs []string,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(exclusionIDs) == 0 {
		return diags
	}

	params := filevantage.DeleteScheduledExclusionsParams{
		Context:  ctx,
		Ids:      exclusionIDs,
		PolicyID: policyID,
	}

	res, err := r.client.Filevantage.DeleteScheduledExclusions(&params)

	if err != nil {
		diags.AddError(
			"Error deleting scheduled exclusion",
			fmt.Sprintf(
				"Could not delete scheduled exclusions (%s): %s",
				strings.Join(exclusionIDs, ","),
				err.Error(),
			),
		)

		return diags
	}

	if res != nil && res.Payload != nil {
		for _, err := range res.Payload.Errors {
			diags.AddError(
				"Error deleting scheduled exclusion",
				fmt.Sprintf(
					"Could not delete scheduled exclusion (%s): %s",
					strings.Join(exclusionIDs, ","),
					err.String(),
				),
			)
		}
	}

	return diags
}

// createScheduledExclusions creates scheduled exclusions for a filevantage policy.
func (r *fimPolicyResource) createScheduledExclusions(
	ctx context.Context,
	exclusions []scheduledExclusion,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(exclusions) == 0 {
		return diags
	}

	for _, exclusion := range exclusions {
		scheduledStart, diags := r.createRFC3339DateTime(
			exclusion.StartDate.ValueString(),
			exclusion.StartTime.ValueString(),
			exclusion.Timezone.ValueString(),
		)
		diags.Append(diags...)
		if diags.HasError() {
			return diags
		}

		scheduledEnd, diags := r.createRFC3339DateTime(
			exclusion.EndDate.ValueString(),
			exclusion.EndTime.ValueString(),
			exclusion.Timezone.ValueString(),
		)
		diags.Append(diags...)
		if diags.HasError() {
			return diags
		}

		params := filevantage.CreateScheduledExclusionsParams{
			Context: ctx,
			Body: &models.ScheduledexclusionsCreateRequest{
				PolicyID:      policyID,
				Name:          exclusion.Name.ValueStringPointer(),
				Description:   exclusion.Description.ValueString(),
				Timezone:      exclusion.Timezone.ValueStringPointer(),
				Processes:     exclusion.Processes.ValueString(),
				Users:         exclusion.Users.ValueString(),
				ScheduleStart: scheduledStart,
			},
		}

		params.Body.ScheduleEnd = scheduledEnd

		if exclusion.Repeated != nil {
			monthlyDaysTf := []types.Int64{}
			monthlyDays := []int64{}
			weeklyDays := []string{}

			diags.Append(exclusion.Repeated.DaysOfMonth.ElementsAs(ctx, &monthlyDaysTf, true)...)
			if diags.HasError() {
				return diags
			}

			for _, d := range monthlyDaysTf {
				if d.IsNull() || d.IsUnknown() {
					continue
				}

				monthlyDays = append(monthlyDays, d.ValueInt64())
			}

			for _, d := range exclusion.Repeated.DaysOfWeek.Elements() {
				var day string
				if d.IsNull() || d.IsUnknown() {
					continue
				}

				v, err := d.ToTerraformValue(ctx)
				if err != nil {
					continue
				}
				err = v.Copy().As(&day)
				if err != nil {
					continue
				}
				weeklyDays = append(weeklyDays, day)
			}

			params.Body.Repeated = &models.ScheduledexclusionsRepeated{
				AllDay:      exclusion.Repeated.AllDay.ValueBool(),
				StartTime:   exclusion.Repeated.StartTime.ValueString(),
				EndTime:     exclusion.Repeated.EndTime.ValueString(),
				Frequency:   exclusion.Repeated.Frequency.ValueString(),
				Occurrence:  exclusion.Repeated.MonthlyOccurrence.ValueString(),
				MonthlyDays: monthlyDays,
				WeeklyDays:  weeklyDays,
			}

			tflog.Warn(ctx, fmt.Sprintf("monthlydays %#v", monthlyDays))
			tflog.Warn(ctx, fmt.Sprintf("monthlydays %#v", params.Body.Repeated.MonthlyDays))
		}

		res, err := r.client.Filevantage.CreateScheduledExclusions(&params)

		if err != nil {
			errMsg := fmt.Sprintf(
				"Could not create scheduled exclusion: %s",
				err.Error(),
			)
			if strings.Contains(err.Error(), "500") {
				errMsg = fmt.Sprintf(
					"Could not create scheduled exclusion (%s): Returned error code 500, this could be caused by inproperly formmated users or processes strings. \n\n %s",
					exclusion.Name.ValueString(),
					err.Error(),
				)
			}

			diags.AddError("Error creating scheduled exclusion", errMsg)

			return diags
		}

		if res != nil && res.Payload != nil {
			for _, err := range res.Payload.Errors {
				diags.AddError(
					"Error creating scheduled exclusion",
					fmt.Sprintf(
						"Could not create scheduled exclusion (%s): %s",
						exclusion.Name.ValueString(),
						err.String(),
					),
				)
			}
		}
	}

	return diags
}

func (r *fimPolicyResource) createRFC3339DateTime(
	d, t, timezone string,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if d == "" || t == "" {
		return "", diags
	}

	loc, _ := time.LoadLocation(timezone)
	dateTimeStr := fmt.Sprintf("%s %s:00", d, t)
	dt, err := time.ParseInLocation("2006-01-02 15:04:05", dateTimeStr, loc)
	if err != nil {
		diags.AddError(
			"Invalid date time",
			fmt.Sprintf("Date time is not in the format YYYY-MM-DDTHH:MM:00Z: %s", err.Error()),
		)
	}

	return dt.Format(time.RFC3339), diags
}

// verifies a date is in the format YYYY-MM-DD.
func valideDate(attrPath path.Path, d string) diag.Diagnostics {
	var diags diag.Diagnostics
	if d == "" {
		return diags
	}
	_, err := time.Parse("2006-01-02", d)
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Invalid date",
			fmt.Sprintf("Date is not in the format YYYY-MM-DD: %s", err.Error()),
		)
	}

	return diags
}

// verifies a time is in the format HH:MM.
func valideTime(attrPath path.Path, t string) diag.Diagnostics {
	var diags diag.Diagnostics
	if t == "" {
		return diags
	}
	_, err := time.Parse("15:04", t)
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Invalid time",
			fmt.Sprintf("Time is not in the format HH:MM: %s", err.Error()),
		)
	}
	return diags
}
