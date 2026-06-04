package itautomation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
)

var (
	_ resource.Resource                   = &itAutomationScheduledTaskResource{}
	_ resource.ResourceWithConfigure      = &itAutomationScheduledTaskResource{}
	_ resource.ResourceWithImportState    = &itAutomationScheduledTaskResource{}
	_ resource.ResourceWithValidateConfig = &itAutomationScheduledTaskResource{}
)

var scheduledTasksRequiredScopes []scopes.Scope = itAutomationScopes

const (
	itAutomationScheduledTask = "IT Automation Scheduled Task"
)

const (
	frequencyOneTime = "One-Time"
	frequencyMinutes = "Minutes"
	frequencyHourly  = "Hourly"
	frequencyDaily   = "Daily"
	frequencyWeekly  = "Weekly"
	frequencyMonthly = "Monthly"
)

func NewItAutomationScheduledTaskResource() resource.Resource {
	return &itAutomationScheduledTaskResource{}
}

type itAutomationScheduledTaskResource struct {
	client *client.CrowdStrikeAPISpecification
}

type triggerStatementModel struct {
	TaskID         types.String `tfsdk:"task_id"`
	Key            types.String `tfsdk:"key"`
	DataType       types.String `tfsdk:"data_type"`
	DataComparator types.String `tfsdk:"data_comparator"`
	Value          types.String `tfsdk:"value"`
}

type triggerConditionModel struct {
	Operator   types.String `tfsdk:"operator"`
	Statements types.List   `tfsdk:"statements"`
}

type scheduleModel struct {
	Frequency  types.String    `tfsdk:"frequency"`
	StartTime  fwtypes.RFC3339 `tfsdk:"start_time"`
	EndTime    fwtypes.RFC3339 `tfsdk:"end_time"`
	DayOfWeek  types.String    `tfsdk:"day_of_week"`
	DayOfMonth types.Int64     `tfsdk:"day_of_month"`
	Interval   types.Int64     `tfsdk:"interval"`
}

type scheduledTaskGroupModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
}

type itAutomationScheduledTaskResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	TaskID              types.String `tfsdk:"task_id"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Target              types.String `tfsdk:"target"`
	ScheduleName        types.String `tfsdk:"schedule_name"`
	DiscoverNewHosts    types.Bool   `tfsdk:"discover_new_hosts"`
	QueueOfflineHosts   types.Bool   `tfsdk:"queue_offline_hosts"`
	DistributeExecution types.Bool   `tfsdk:"distribute_execution"`
	ExpirationPeriod    types.String `tfsdk:"expiration_period"`
	RunTimeLimitMinutes types.Int64  `tfsdk:"run_time_limit_minutes"`
	ExecutionArgs       types.Map    `tfsdk:"execution_args"`
	Schedule            types.Object `tfsdk:"schedule"`
	TriggerCondition    types.List   `tfsdk:"trigger_condition"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedTime         types.String `tfsdk:"created_time"`
	ModifiedBy          types.String `tfsdk:"modified_by"`
	ModifiedTime        types.String `tfsdk:"modified_time"`
	LastRun             types.String `tfsdk:"last_run"`
	NextRunTime         types.String `tfsdk:"next_run_time"`
	TaskName            types.String `tfsdk:"task_name"`
	TaskType            types.String `tfsdk:"task_type"`
	Groups              types.List   `tfsdk:"groups"`
}

func scheduledTaskScheduleAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"frequency":    types.StringType,
		"start_time":   fwtypes.RFC3339Type{},
		"end_time":     fwtypes.RFC3339Type{},
		"day_of_week":  types.StringType,
		"day_of_month": types.Int64Type,
		"interval":     types.Int64Type,
	}
}

func scheduledTaskTriggerStatementAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"task_id":         types.StringType,
		"key":             types.StringType,
		"data_type":       types.StringType,
		"data_comparator": types.StringType,
		"value":           types.StringType,
	}
}

func scheduledTaskTriggerConditionAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator":   types.StringType,
		"statements": types.ListType{ElemType: types.ObjectType{AttrTypes: scheduledTaskTriggerStatementAttrTypes()}},
	}
}

func scheduledTaskGroupAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":   types.StringType,
		"name": types.StringType,
	}
}

func (r *itAutomationScheduledTaskResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_it_automation_scheduled_task"
}

func (r *itAutomationScheduledTaskResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	cfg, ok := req.ProviderData.(config.ProviderConfig)
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

	r.client = cfg.Client
}

func (r *itAutomationScheduledTaskResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"IT Automation",
			"This resource allows management of IT Automation scheduled tasks in the CrowdStrike Falcon platform. A scheduled task ties an existing IT Automation task to a recurring or one-time schedule with host targeting and optional query-result-based filtering.",
			scheduledTasksRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the scheduled task.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"task_id": schema.StringAttribute{
				Required:    true,
				Description: "Unique identifier of the IT Automation task being scheduled.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Required:    true,
				Description: "Whether the schedule is active.",
			},
			"target": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Target of the scheduled task in FQL string syntax filtering hosts by attributes " +
					"(e.g. `platform_name:'Linux'+tags:'production'`). " +
					"See https://falconpy.io/Usage/Falcon-Query-Language.html.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(8),
				},
			},
			"schedule_name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Display name for the scheduled task. Note: clearing this value forces " +
					"resource replacement because the API does not support removing a schedule name via update.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
							if !req.StateValue.IsNull() && req.PlanValue.IsNull() {
								resp.RequiresReplace = true
							}
						},
						"Clearing schedule_name forces replacement because the API does not support clearing it via update.",
						"Clearing `schedule_name` forces replacement because the API does not support clearing it via update.",
					),
				},
			},
			"discover_new_hosts": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Run on newly discovered hosts that match `target` while the schedule is active.",
			},
			"queue_offline_hosts": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Run on offline hosts when they come back online before the expiration period ends.",
			},
			"distribute_execution": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Stagger execution across the expiration window to reduce concurrent load.",
			},
			"expiration_period": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Duration the task remains active for new/offline hosts (e.g. `30m`, `1h`, `2d`). " +
					"Minimum `1m`. Must be in canonical form: the API normalizes `60m` to `1h`, `24h` to `1d`, etc., " +
					"so use the largest unit that divides evenly. Setting this requires at least one of " +
					"`discover_new_hosts`, `queue_offline_hosts`, or `distribute_execution` to be `true`. " +
					"Note: clearing this value forces resource replacement because the API does not support " +
					"removing an expiration period via update.",
				Validators: []validator.String{
					DurationCanonicalValidator(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(
						func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
							if !req.StateValue.IsNull() && req.PlanValue.IsNull() {
								resp.RequiresReplace = true
							}
						},
						"Clearing expiration_period forces replacement because the API does not support clearing it via update.",
						"Clearing `expiration_period` forces replacement because the API does not support clearing it via update.",
					),
				},
			},
			"run_time_limit_minutes": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum runtime per host execution, in minutes. Maximum 120 (2 hours).",
				Validators: []validator.Int64{
					int64validator.Between(1, 120),
				},
			},
			"execution_args": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Additional arguments passed to the underlying task at execution time.",
			},
			"schedule": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Schedule details for task execution.",
				Attributes: map[string]schema.Attribute{
					"frequency": schema.StringAttribute{
						Required: true,
						MarkdownDescription: "Frequency of runs. One of: `One-Time`, `Minutes`, `Hourly`, " +
							"`Daily`, `Weekly`, `Monthly`.",
						Validators: []validator.String{
							stringvalidator.OneOf(
								frequencyOneTime, frequencyMinutes, frequencyHourly,
								frequencyDaily, frequencyWeekly, frequencyMonthly,
							),
						},
					},
					"start_time": schema.StringAttribute{
						CustomType: fwtypes.RFC3339Type{},
						Required:   true,
						Description: "RFC3339 timestamp for when the schedule first runs. The timezone offset " +
							"embedded in this value determines the local timezone for recurring runs.",
					},
					"end_time": schema.StringAttribute{
						CustomType:  fwtypes.RFC3339Type{},
						Optional:    true,
						Description: "RFC3339 timestamp when the schedule stops running.",
					},
					"day_of_week": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: "Day of week for `Weekly` frequency. One of `Monday`, `Tuesday`, " +
							"`Wednesday`, `Thursday`, `Friday`, `Saturday`, `Sunday`. Required when " +
							"`frequency = \"Weekly\"`. Not allowed for other frequencies.",
						Validators: []validator.String{
							stringvalidator.OneOf(
								"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
							),
						},
					},
					"day_of_month": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "Day of month (1-28) for `Monthly` frequency. Required when " +
							"`frequency = \"Monthly\"`. Not allowed for other frequencies. Note: API limits " +
							"this to 1-28 to handle February.",
						Validators: []validator.Int64{
							int64validator.Between(1, 28),
						},
					},
					"interval": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "Run interval. Required when `frequency = \"Minutes\"` (range 60-10080, " +
							"in minutes) or `frequency = \"Hourly\"` (range 1-168, in hours). Not allowed for " +
							"other frequencies. Meaning depends on `frequency`.",
						Validators: []validator.Int64{
							int64validator.Between(1, 10080),
						},
					},
				},
			},
			"trigger_condition": schema.ListNestedAttribute{
				Optional: true,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				MarkdownDescription: "Query task result conditions that further filter hosts selected by `target`. " +
					"Each element is one conditional group; groups are joined with an implicit `AND`. " +
					"Statements within a group reference an existing query task by `task_id` and compare one " +
					"of its result columns to a value. Maps to the **Query tasks results** sections in the " +
					"Falcon console's *Advanced target definition*. The console only exposes this feature for " +
					"schedules whose underlying task is `action` or `remediation` type, but the API itself accepts " +
					"it on `query` task schedules as well.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"operator": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Logical operator joining the group's `statements`. One of: `AND`, `OR`.",
							Validators: []validator.String{
								stringvalidator.OneOf("AND", "OR"),
							},
						},
						"statements": schema.ListNestedAttribute{
							Required:    true,
							Description: "Conditions evaluated against the results of a query task.",
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
							},
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"task_id": schema.StringAttribute{
										Required:    true,
										Description: "ID of the query task whose results are evaluated.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"key": schema.StringAttribute{
										Required:    true,
										Description: "Result column from the query task to evaluate.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"data_type": schema.StringAttribute{
										Required: true,
										MarkdownDescription: "How to interpret `value` during comparison. One of: " +
											"`StringType`, `NumericType`, `SemverType`.",
										Validators: []validator.String{
											stringvalidator.OneOf("StringType", "NumericType", "SemverType"),
										},
									},
									"data_comparator": schema.StringAttribute{
										Required: true,
										MarkdownDescription: "Comparison operator. One of: `Equals`, `NotEquals`, " +
											"`Contains`, `NotContains`, `Matches`, `NotMatches`, `LessThan`, " +
											"`LessThanEquals`, `GreaterThan`, `GreaterThanEquals`.",
										Validators: []validator.String{
											stringvalidator.OneOf(
												"Equals", "NotEquals",
												"Contains", "NotContains",
												"Matches", "NotMatches",
												"LessThan", "LessThanEquals",
												"GreaterThan", "GreaterThanEquals",
											),
										},
									},
									"value": schema.StringAttribute{
										Required: true,
										MarkdownDescription: "Value to compare against. Numeric comparisons require " +
											"numeric strings (e.g. `\"100\"`).",
									},
								},
							},
						},
					},
				},
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "Username of the user who created the scheduled task.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_time": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp when the scheduled task was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "Username of the user who last modified the scheduled task.",
			},
			"modified_time": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp when the scheduled task was last modified.",
			},
			"last_run": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the last execution.",
			},
			"next_run_time": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the next scheduled execution.",
			},
			"task_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the underlying scheduled task.",
			},
			"task_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Type of the underlying scheduled task (`query` or `action`).",
			},
			"groups": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Task group memberships of the underlying task.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":   schema.StringAttribute{Computed: true, Description: "Group ID."},
						"name": schema.StringAttribute{Computed: true, Description: "Group name."},
					},
				},
			},
		},
	}
}

func (r *itAutomationScheduledTaskResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg itAutomationScheduledTaskResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if utils.IsKnown(cfg.Schedule) {
		var sched scheduleModel
		resp.Diagnostics.Append(cfg.Schedule.As(ctx, &sched, basetypes.ObjectAsOptions{
			UnhandledNullAsEmpty:    false,
			UnhandledUnknownAsEmpty: false,
		})...)
		if !resp.Diagnostics.HasError() {
			validateSchedule(&sched, &resp.Diagnostics)
		}
	}

	if utils.IsKnown(cfg.ExpirationPeriod) {
		dn := cfg.DiscoverNewHosts
		qo := cfg.QueueOfflineHosts
		de := cfg.DistributeExecution
		hasOne := (utils.IsKnown(dn) && dn.ValueBool()) ||
			(utils.IsKnown(qo) && qo.ValueBool()) ||
			(utils.IsKnown(de) && de.ValueBool())
		anyUnknown := dn.IsUnknown() || qo.IsUnknown() || de.IsUnknown()
		if !hasOne && !anyUnknown {
			resp.Diagnostics.AddAttributeError(
				path.Root("expiration_period"),
				"Invalid expiration_period configuration",
				"When `expiration_period` is set, at least one of `discover_new_hosts`, "+
					"`queue_offline_hosts`, or `distribute_execution` must be `true`.",
			)
		}
	}

	if utils.IsKnown(cfg.TriggerCondition) {
		validateTriggerConditions(ctx, cfg.TriggerCondition, &resp.Diagnostics)
	}
}

func validateSchedule(sched *scheduleModel, diags *diag.Diagnostics) {
	if !utils.IsKnown(sched.Frequency) {
		return
	}
	frequency := sched.Frequency.ValueString()

	dowSet := utils.IsKnown(sched.DayOfWeek)
	domSet := utils.IsKnown(sched.DayOfMonth)
	intervalSet := utils.IsKnown(sched.Interval)

	if dowSet && frequency != frequencyWeekly {
		diags.AddAttributeError(
			path.Root("schedule").AtName("day_of_week"),
			"Invalid day_of_week",
			"`day_of_week` is only allowed when `schedule.frequency` is `Weekly`.",
		)
	}
	if !dowSet && frequency == frequencyWeekly && !sched.DayOfWeek.IsUnknown() {
		diags.AddAttributeError(
			path.Root("schedule").AtName("day_of_week"),
			"Missing day_of_week",
			"`day_of_week` is required when `schedule.frequency` is `Weekly`.",
		)
	}

	if domSet && frequency != frequencyMonthly {
		diags.AddAttributeError(
			path.Root("schedule").AtName("day_of_month"),
			"Invalid day_of_month",
			"`day_of_month` is only allowed when `schedule.frequency` is `Monthly`.",
		)
	}
	if !domSet && frequency == frequencyMonthly && !sched.DayOfMonth.IsUnknown() {
		diags.AddAttributeError(
			path.Root("schedule").AtName("day_of_month"),
			"Missing day_of_month",
			"`day_of_month` is required when `schedule.frequency` is `Monthly`.",
		)
	}

	intervalAllowed := frequency == frequencyMinutes || frequency == frequencyHourly
	if intervalSet && !intervalAllowed {
		diags.AddAttributeError(
			path.Root("schedule").AtName("interval"),
			"Invalid interval",
			"`interval` is only allowed when `schedule.frequency` is `Minutes` or `Hourly`.",
		)
	}
	if !intervalSet && intervalAllowed && !sched.Interval.IsUnknown() {
		diags.AddAttributeError(
			path.Root("schedule").AtName("interval"),
			"Missing interval",
			fmt.Sprintf("`interval` is required when `schedule.frequency` is `%s`.", frequency),
		)
	}

	if intervalSet && intervalAllowed {
		v := sched.Interval.ValueInt64()
		switch frequency {
		case frequencyMinutes:
			if v < 60 || v > 10080 {
				diags.AddAttributeError(
					path.Root("schedule").AtName("interval"),
					"Invalid interval",
					fmt.Sprintf("`interval` must be between 60 and 10080 when `schedule.frequency` is `Minutes`. Got: %d.", v),
				)
			}
		case frequencyHourly:
			if v < 1 || v > 168 {
				diags.AddAttributeError(
					path.Root("schedule").AtName("interval"),
					"Invalid interval",
					fmt.Sprintf("`interval` must be between 1 and 168 when `schedule.frequency` is `Hourly`. Got: %d.", v),
				)
			}
		}
	}
}

func validateTriggerConditions(ctx context.Context, list types.List, diags *diag.Diagnostics) {
	if !utils.IsKnown(list) {
		return
	}

	var conditions []triggerConditionModel
	d := list.ElementsAs(ctx, &conditions, false)
	diags.Append(d...)
	if d.HasError() {
		return
	}

	stringComparators := map[string]bool{
		"Contains": true, "NotContains": true, "Matches": true, "NotMatches": true,
	}
	numericComparators := map[string]bool{
		"LessThan": true, "LessThanEquals": true, "GreaterThan": true, "GreaterThanEquals": true,
	}

	for i, cond := range conditions {
		if !utils.IsKnown(cond.Statements) {
			continue
		}
		var stmts []triggerStatementModel
		sd := cond.Statements.ElementsAs(ctx, &stmts, false)
		diags.Append(sd...)
		if sd.HasError() {
			continue
		}
		for j, s := range stmts {
			if !utils.IsKnown(s.DataType) || !utils.IsKnown(s.DataComparator) {
				continue
			}
			dt := s.DataType.ValueString()
			dc := s.DataComparator.ValueString()
			stmtPath := path.Root("trigger_condition").AtListIndex(i).
				AtName("statements").AtListIndex(j).AtName("data_comparator")
			if stringComparators[dc] && dt != "StringType" {
				diags.AddAttributeError(
					stmtPath,
					"Incompatible data_comparator and data_type",
					fmt.Sprintf("`%s` requires `data_type` `StringType`. Got: %q.", dc, dt),
				)
			}
			if numericComparators[dc] && dt != "NumericType" && dt != "SemverType" {
				diags.AddAttributeError(
					stmtPath,
					"Incompatible data_comparator and data_type",
					fmt.Sprintf("`%s` requires `data_type` `NumericType` or `SemverType`. Got: %q.", dc, dt),
				)
			}
		}
	}
}

// timezoneFromStartTime returns the API-formatted timezone string ("+0000",
// "-0500", etc.) derived from the offset embedded in an RFC3339 start_time.
// Returns "+0000" when start_time is null/unknown.
func timezoneFromStartTime(startTime fwtypes.RFC3339) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if !utils.IsKnown(startTime) {
		return "+0000", diags
	}
	t, parseErr := time.Parse(time.RFC3339, startTime.ValueString())
	if parseErr != nil {
		diags.AddError(
			"Invalid start_time",
			fmt.Sprintf("Could not parse `schedule.start_time` as RFC3339: %s", parseErr.Error()),
		)
		return "", diags
	}
	return t.Format("-0700"), diags
}

// reconstructStartTimeWithTimezone takes the API's UTC start_time and timezone
// offset and produces an RFC3339 string with the offset preserved.
func reconstructStartTimeWithTimezone(startTime strfmt.DateTime, timezone string) (string, error) {
	t := time.Time(startTime)
	if t.IsZero() {
		return "", nil
	}

	loc, err := parseTimezoneOffset(timezone)
	if err != nil {
		return "", err
	}
	return t.In(loc).Format(time.RFC3339), nil
}

// parseTimezoneOffset converts an API timezone offset string ("-0500",
// "+0000") into a *time.Location suitable for time.Time.In. Empty / "+0000" /
// "-0000" all return time.UTC so the formatted output uses `Z`.
func parseTimezoneOffset(tz string) (*time.Location, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" || tz == "+0000" || tz == "-0000" || tz == "Z" {
		return time.UTC, nil
	}
	parsed, err := time.Parse("-0700", tz)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone offset %q: %w", tz, err)
	}
	_, offset := parsed.Zone()
	return time.FixedZone(tz, offset), nil
}

func buildScheduleFromPlan(
	ctx context.Context,
	scheduleObj types.Object,
) (*models.FalconforitapiSchedule, diag.Diagnostics) {
	var diags diag.Diagnostics

	var sched scheduleModel
	d := scheduleObj.As(ctx, &sched, basetypes.ObjectAsOptions{})
	diags.Append(d...)
	if d.HasError() {
		return nil, diags
	}

	frequency := sched.Frequency.ValueString()
	apiSched := &models.FalconforitapiSchedule{
		Frequency: &frequency,
	}

	if startTimeT, parseDiags := sched.StartTime.ValueRFC3339Time(); !parseDiags.HasError() {
		apiSched.StartTime = strfmt.DateTime(startTimeT)
	} else {
		diags.Append(parseDiags...)
		return nil, diags
	}

	if utils.IsKnown(sched.EndTime) {
		endTimeT, parseDiags := sched.EndTime.ValueRFC3339Time()
		if parseDiags.HasError() {
			diags.Append(parseDiags...)
			return nil, diags
		}
		apiSched.EndTime = strfmt.DateTime(endTimeT)
	}

	tz, tzDiags := timezoneFromStartTime(sched.StartTime)
	diags.Append(tzDiags...)
	if tzDiags.HasError() {
		return nil, diags
	}
	apiSched.Timezone = tz

	if frequency == frequencyMinutes || frequency == frequencyHourly {
		if utils.IsKnown(sched.Interval) {
			v := int32(sched.Interval.ValueInt64())
			apiSched.Interval = &v
		}
	}

	if frequency == frequencyWeekly {
		if utils.IsKnown(sched.DayOfWeek) {
			apiSched.DaysOfWeek = []string{sched.DayOfWeek.ValueString()}
		}
	}

	if frequency == frequencyMonthly {
		if utils.IsKnown(sched.DayOfMonth) {
			apiSched.DayOfMonth = int32(sched.DayOfMonth.ValueInt64())
		}
	}

	return apiSched, diags
}

func buildTriggerConditionFromPlan(
	ctx context.Context,
	list types.List,
) ([]*models.FalconforitapiConditionGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !utils.IsKnown(list) {
		return []*models.FalconforitapiConditionGroup{}, diags
	}

	var conditions []triggerConditionModel
	diags.Append(list.ElementsAs(ctx, &conditions, false)...)
	if diags.HasError() {
		return nil, diags
	}

	result := make([]*models.FalconforitapiConditionGroup, 0, len(conditions))
	for _, cond := range conditions {
		var stmts []triggerStatementModel
		diags.Append(cond.Statements.ElementsAs(ctx, &stmts, false)...)
		if diags.HasError() {
			return nil, diags
		}

		apiStmts := make([]*models.FalconforitapiConditionalExpr, 0, len(stmts))
		for _, s := range stmts {
			apiStmts = append(apiStmts, &models.FalconforitapiConditionalExpr{
				DataComparator: s.DataComparator.ValueStringPointer(),
				DataType:       s.DataType.ValueStringPointer(),
				Key:            s.Key.ValueStringPointer(),
				TaskID:         s.TaskID.ValueStringPointer(),
				Value:          s.Value.ValueStringPointer(),
			})
		}

		result = append(result, &models.FalconforitapiConditionGroup{
			Operator:   cond.Operator.ValueString(),
			Statements: apiStmts,
		})
	}

	return result, diags
}

func (m *itAutomationScheduledTaskResourceModel) wrap(
	ctx context.Context,
	st models.ItautomationScheduledTask,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(st.ID)
	m.TaskID = flex.StringPointerToFramework(st.TaskID)
	m.Target = flex.StringPointerToFramework(st.Target)

	if st.IsActive != nil {
		m.Enabled = types.BoolValue(*st.IsActive)
	} else {
		m.Enabled = types.BoolValue(false)
	}

	m.ScheduleName = flex.StringValueToFramework(st.ScheduleName)

	m.DiscoverNewHosts = types.BoolValue(st.DiscoverNewHosts)
	m.QueueOfflineHosts = types.BoolValue(st.DiscoverOfflineHosts)
	m.DistributeExecution = types.BoolValue(st.Distribute)

	m.ExpirationPeriod = flex.StringValueToFramework(st.ExpirationInterval)

	if st.Guardrails != nil && st.Guardrails.RunTimeLimitMillis > 0 {
		// Round up so a sub-minute API value never truncates to 0, which
		// would violate the int64validator.Between(1, 120) on the next plan.
		m.RunTimeLimitMinutes = types.Int64Value((st.Guardrails.RunTimeLimitMillis + 59999) / 60000)
	} else {
		m.RunTimeLimitMinutes = types.Int64Null()
	}

	if len(st.ExecutionArgs) > 0 {
		execArgs, mapDiags := types.MapValueFrom(ctx, types.StringType, st.ExecutionArgs)
		diags.Append(mapDiags...)
		if !mapDiags.HasError() {
			m.ExecutionArgs = execArgs
		}
	} else {
		m.ExecutionArgs = types.MapNull(types.StringType)
	}

	scheduleObj, schedDiags := flattenSchedule(ctx, st.Schedule)
	diags.Append(schedDiags...)
	m.Schedule = scheduleObj

	triggerList, tcDiags := flattenTriggerCondition(ctx, st.TriggerCondition)
	diags.Append(tcDiags...)
	m.TriggerCondition = triggerList

	m.CreatedBy = flex.StringPointerToFramework(st.CreatedBy)
	if st.CreatedTime != nil {
		m.CreatedTime = types.StringValue(time.Time(*st.CreatedTime).Format(time.RFC3339))
	} else {
		m.CreatedTime = types.StringNull()
	}
	m.ModifiedBy = flex.StringValueToFramework(st.ModifiedBy)
	if t := time.Time(st.ModifiedTime); !t.IsZero() {
		m.ModifiedTime = types.StringValue(t.Format(time.RFC3339))
	} else {
		m.ModifiedTime = types.StringNull()
	}
	if t := time.Time(st.LastRun); !t.IsZero() {
		m.LastRun = types.StringValue(t.Format(time.RFC3339))
	} else {
		m.LastRun = types.StringNull()
	}
	if t := time.Time(st.NextRunTime); !t.IsZero() {
		m.NextRunTime = types.StringValue(t.Format(time.RFC3339))
	} else {
		m.NextRunTime = types.StringNull()
	}

	m.TaskName = flex.StringPointerToFramework(st.TaskName)
	if st.TaskType != nil {
		m.TaskType = types.StringValue(convertType(*st.TaskType, "terraform"))
	} else {
		m.TaskType = types.StringNull()
	}

	groupsList, gDiags := flattenGroups(ctx, st.Groups)
	diags.Append(gDiags...)
	m.Groups = groupsList

	return diags
}

func flattenSchedule(ctx context.Context, sched *models.FalconforitapiSchedule) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics
	attrTypes := scheduledTaskScheduleAttrTypes()

	if sched == nil {
		return types.ObjectNull(attrTypes), diags
	}

	m := scheduleModel{
		StartTime:  fwtypes.NewRFC3339Null(),
		EndTime:    fwtypes.NewRFC3339Null(),
		DayOfWeek:  types.StringNull(),
		DayOfMonth: types.Int64Null(),
		Interval:   types.Int64Null(),
	}

	if sched.Frequency != nil {
		m.Frequency = types.StringValue(*sched.Frequency)
	} else {
		m.Frequency = types.StringNull()
	}

	frequency := ""
	if sched.Frequency != nil {
		frequency = *sched.Frequency
	}

	startTimeT := time.Time(sched.StartTime)
	if !startTimeT.IsZero() {
		formatted, err := reconstructStartTimeWithTimezone(sched.StartTime, sched.Timezone)
		if err != nil {
			diags.AddError("Invalid start_time", err.Error())
			return types.ObjectNull(attrTypes), diags
		}
		v, vDiags := fwtypes.NewRFC3339Value(formatted)
		diags.Append(vDiags...)
		if diags.HasError() {
			return types.ObjectNull(attrTypes), diags
		}
		m.StartTime = v
	}

	endTimeT := time.Time(sched.EndTime)
	if !endTimeT.IsZero() {
		loc, err := parseTimezoneOffset(sched.Timezone)
		if err != nil {
			diags.AddError("Invalid timezone", err.Error())
			return types.ObjectNull(attrTypes), diags
		}
		formatted := endTimeT.In(loc).Format(time.RFC3339)
		v, vDiags := fwtypes.NewRFC3339Value(formatted)
		diags.Append(vDiags...)
		if diags.HasError() {
			return types.ObjectNull(attrTypes), diags
		}
		m.EndTime = v
	}

	if frequency == frequencyWeekly && len(sched.DaysOfWeek) > 0 {
		m.DayOfWeek = types.StringValue(sched.DaysOfWeek[0])
	}

	if frequency == frequencyMonthly && sched.DayOfMonth > 0 {
		m.DayOfMonth = types.Int64Value(int64(sched.DayOfMonth))
	}

	if (frequency == frequencyMinutes || frequency == frequencyHourly) &&
		sched.Interval != nil && *sched.Interval > 0 {
		m.Interval = types.Int64Value(int64(*sched.Interval))
	}

	obj, oDiags := types.ObjectValueFrom(ctx, attrTypes, m)
	diags.Append(oDiags...)
	if diags.HasError() {
		return types.ObjectNull(attrTypes), diags
	}
	return obj, diags
}

func flattenTriggerCondition(
	ctx context.Context,
	conditions []*models.FalconforitapiConditionGroup,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	condObjType := types.ObjectType{AttrTypes: scheduledTaskTriggerConditionAttrTypes()}

	if len(conditions) == 0 {
		return types.ListNull(condObjType), diags
	}

	stmtObjType := types.ObjectType{AttrTypes: scheduledTaskTriggerStatementAttrTypes()}
	out := make([]triggerConditionModel, 0, len(conditions))

	for _, c := range conditions {
		if c == nil {
			continue
		}
		stmts := make([]triggerStatementModel, 0, len(c.Statements))
		for _, s := range c.Statements {
			stmts = append(stmts, triggerStatementModel{
				TaskID:         types.StringPointerValue(s.TaskID),
				Key:            types.StringPointerValue(s.Key),
				DataType:       types.StringPointerValue(s.DataType),
				DataComparator: types.StringPointerValue(s.DataComparator),
				Value:          types.StringPointerValue(s.Value),
			})
		}
		stmtList, sd := types.ListValueFrom(ctx, stmtObjType, stmts)
		diags.Append(sd...)
		if diags.HasError() {
			return types.ListNull(condObjType), diags
		}
		out = append(out, triggerConditionModel{
			Operator:   types.StringValue(c.Operator),
			Statements: stmtList,
		})
	}

	list, ld := types.ListValueFrom(ctx, condObjType, out)
	diags.Append(ld...)
	if diags.HasError() {
		return types.ListNull(condObjType), diags
	}
	return list, diags
}

func flattenGroups(
	ctx context.Context,
	groups []*models.FalconforitapiGroupMembership,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	groupObjType := types.ObjectType{AttrTypes: scheduledTaskGroupAttrTypes()}

	if len(groups) == 0 {
		return types.ListValueFrom(ctx, groupObjType, []scheduledTaskGroupModel{})
	}

	out := make([]scheduledTaskGroupModel, 0, len(groups))
	for _, g := range groups {
		if g == nil {
			continue
		}
		out = append(out, scheduledTaskGroupModel{
			ID:   types.StringPointerValue(g.ID),
			Name: types.StringPointerValue(g.Name),
		})
	}

	list, ld := types.ListValueFrom(ctx, groupObjType, out)
	diags.Append(ld...)
	return list, diags
}

func (r *itAutomationScheduledTaskResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan itAutomationScheduledTaskResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiSched, schedDiags := buildScheduleFromPlan(ctx, plan.Schedule)
	resp.Diagnostics.Append(schedDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	target := plan.Target.ValueString()
	taskID := plan.TaskID.ValueString()
	isActive := plan.Enabled.ValueBool()

	overrideBody := &createScheduledTaskRequest{
		IsActive:             &isActive,
		TaskID:               &taskID,
		Target:               &target,
		DiscoverNewHosts:     plan.DiscoverNewHosts.ValueBool(),
		DiscoverOfflineHosts: plan.QueueOfflineHosts.ValueBool(),
		Distribute:           plan.DistributeExecution.ValueBool(),
		Schedule:             newScheduleRequest(apiSched),
		ScheduleName:         plan.ScheduleName.ValueString(),
		ExpirationInterval:   plan.ExpirationPeriod.ValueString(),
	}

	if utils.IsKnown(plan.RunTimeLimitMinutes) {
		overrideBody.Guardrails = &models.FalconforitapiGuardrails{
			RunTimeLimitMillis: plan.RunTimeLimitMinutes.ValueInt64() * 60000,
		}
	}

	if utils.IsKnown(plan.ExecutionArgs) {
		execArgs := make(map[string]string)
		resp.Diagnostics.Append(plan.ExecutionArgs.ElementsAs(ctx, &execArgs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		overrideBody.ExecutionArgs = execArgs
	}

	triggers, tcDiags := buildTriggerConditionFromPlan(ctx, plan.TriggerCondition)
	resp.Diagnostics.Append(tcDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	overrideBody.TriggerCondition = triggers

	createParams := it_automation.NewITAutomationCreateScheduledTaskParams()
	createParams.WithContext(ctx)

	apiResp, err := r.client.ItAutomation.ITAutomationCreateScheduledTask(
		createParams,
		func(op *runtime.ClientOperation) {
			op.Params = &createScheduledTaskParams{Body: overrideBody}
		},
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create, err, scheduledTasksRequiredScopes,
		))
		return
	}

	if apiResp == nil || apiResp.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, apiResp.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}
	if len(apiResp.Payload.Resources) == 0 || apiResp.Payload.Resources[0] == nil ||
		apiResp.Payload.Resources[0].ID == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	// Persist the ID immediately so Terraform can track (and clean up) the
	// resource even if the follow-up read or wrap fails.
	plan.ID = flex.StringPointerToFramework(apiResp.Payload.Resources[0].ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, readDiags := r.getScheduledTask(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, created)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *itAutomationScheduledTaskResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state itAutomationScheduledTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	st, diags := r.getScheduledTask(ctx, id)
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			tflog.Warn(ctx, fmt.Sprintf(notFoundRemoving,
				fmt.Sprintf("%s %s", itAutomationScheduledTask, id)))
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, st)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *itAutomationScheduledTaskResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan itAutomationScheduledTaskResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()

	apiSched, schedDiags := buildScheduleFromPlan(ctx, plan.Schedule)
	resp.Diagnostics.Append(schedDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	overrideBody := &updateScheduledTaskRequest{
		TaskID:               plan.TaskID.ValueString(),
		Target:               plan.Target.ValueString(),
		IsActive:             plan.Enabled.ValueBool(),
		DiscoverNewHosts:     plan.DiscoverNewHosts.ValueBool(),
		DiscoverOfflineHosts: plan.QueueOfflineHosts.ValueBool(),
		Distribute:           plan.DistributeExecution.ValueBool(),
		Schedule:             newScheduleRequest(apiSched),
		ScheduleName:         plan.ScheduleName.ValueStringPointer(),
		ExpirationInterval:   plan.ExpirationPeriod.ValueStringPointer(),
		// Default to the cleared representation; the blocks below replace these
		// with real values when the plan still has them. The API treats null as
		// "keep", so an empty map/object is required to actually clear.
		ExecutionArgs:    map[string]string{},
		Guardrails:       &models.FalconforitapiGuardrails{},
		TriggerCondition: []*models.FalconforitapiConditionGroup{},
	}

	if utils.IsKnown(plan.RunTimeLimitMinutes) {
		overrideBody.Guardrails = &models.FalconforitapiGuardrails{
			RunTimeLimitMillis: plan.RunTimeLimitMinutes.ValueInt64() * 60000,
		}
	}

	if utils.IsKnown(plan.ExecutionArgs) {
		execArgs := make(map[string]string)
		resp.Diagnostics.Append(plan.ExecutionArgs.ElementsAs(ctx, &execArgs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		overrideBody.ExecutionArgs = execArgs
	}

	triggers, tcDiags := buildTriggerConditionFromPlan(ctx, plan.TriggerCondition)
	resp.Diagnostics.Append(tcDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if triggers != nil {
		overrideBody.TriggerCondition = triggers
	}

	updateParams := it_automation.NewITAutomationUpdateScheduledTaskParams()
	updateParams.WithContext(ctx)

	updateResp, err := r.client.ItAutomation.ITAutomationUpdateScheduledTask(
		updateParams,
		func(op *runtime.ClientOperation) {
			op.Params = &updateScheduledTaskParams{Body: overrideBody, ID: id}
		},
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update, err, scheduledTasksRequiredScopes,
		))
		return
	}
	if updateResp != nil && updateResp.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateResp.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	updated, readDiags := r.getScheduledTask(ctx, id)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, updated)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *itAutomationScheduledTaskResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state itAutomationScheduledTaskResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	if id == "" {
		return
	}

	if state.Enabled.ValueBool() {
		if err := r.deactivateScheduledTask(ctx, id); err != nil {
			diag := tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, scheduledTasksRequiredScopes)
			if diag.Summary() == tferrors.NotFoundErrorSummary {
				return
			}
			resp.Diagnostics.Append(diag)
			return
		}
	}

	params := it_automation.NewITAutomationDeleteScheduledTasksParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	delResp, err := r.client.ItAutomation.ITAutomationDeleteScheduledTasks(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, scheduledTasksRequiredScopes)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
	if delResp != nil && delResp.Payload != nil {
		if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Delete, delResp.Payload.Errors); diag != nil {
			resp.Diagnostics.Append(diag)
		}
	}
}

func (r *itAutomationScheduledTaskResource) deactivateScheduledTask(ctx context.Context, id string) error {
	current, diags := r.getScheduledTask(ctx, id)
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			return nil
		}
		return fmt.Errorf("%s", diags.Errors()[0].Detail())
	}

	deactivateBody := &deactivateScheduledTaskRequest{
		IsActive:         false,
		TriggerCondition: current.TriggerCondition,
	}
	if deactivateBody.TriggerCondition == nil {
		deactivateBody.TriggerCondition = []*models.FalconforitapiConditionGroup{}
	}

	updateParams := it_automation.NewITAutomationUpdateScheduledTaskParams()
	updateParams.WithContext(ctx)

	_, err := r.client.ItAutomation.ITAutomationUpdateScheduledTask(
		updateParams,
		func(op *runtime.ClientOperation) {
			op.Params = &deactivateScheduledTaskParams{Body: deactivateBody, ID: id}
		},
	)
	return err
}

func (r *itAutomationScheduledTaskResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *itAutomationScheduledTaskResource) getScheduledTask(
	ctx context.Context,
	id string,
) (models.ItautomationScheduledTask, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := it_automation.NewITAutomationGetScheduledTasksParams()
	params.WithContext(ctx)
	params.Ids = []string{id}

	resp, err := r.client.ItAutomation.ITAutomationGetScheduledTasks(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, scheduledTasksRequiredScopes))
		return models.ItautomationScheduledTask{}, diags
	}

	if resp == nil || resp.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return models.ItautomationScheduledTask{}, diags
	}
	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, resp.Payload.Errors); diag != nil {
		diags.Append(diag)
		return models.ItautomationScheduledTask{}, diags
	}

	if len(resp.Payload.Resources) == 0 ||
		resp.Payload.Resources[0] == nil || resp.Payload.Resources[0].ID == nil {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("No IT automation scheduled task with id: %s found.", id)))
		return models.ItautomationScheduledTask{}, diags
	}

	return *resp.Payload.Resources[0], diags
}

// scheduleRequest mirrors models.FalconforitapiSchedule but uses pointer types
// for fields whose Go zero values would otherwise be serialized into the
// request body. encoding/json's `omitempty` never applies to struct types, so
// the generated model's `omitempty` tag on `end_time` (a strfmt.DateTime, which
// is a struct over time.Time) has no effect: an unset value serializes as
// `"end_time":"0001-01-01T00:00:00.000Z"` instead of being omitted. Using a
// *strfmt.DateTime makes omitempty drop the nil pointer as intended.
type scheduleRequest struct {
	DayOfMonth int32            `json:"day_of_month,omitempty"`
	DaysOfWeek []string         `json:"days_of_week"`
	EndTime    *strfmt.DateTime `json:"end_time,omitempty"`
	Frequency  *string          `json:"frequency"`
	Interval   *int32           `json:"interval"`
	StartTime  *strfmt.DateTime `json:"start_time,omitempty"`
	Time       string           `json:"time,omitempty"`
	Timezone   string           `json:"timezone,omitempty"`
}

// newScheduleRequest converts a generated schedule into the serialization form
// above. Returns nil when the input is nil so the JSON encoder emits null.
func newScheduleRequest(s *models.FalconforitapiSchedule) *scheduleRequest {
	if s == nil {
		return nil
	}
	out := &scheduleRequest{
		DayOfMonth: s.DayOfMonth,
		DaysOfWeek: s.DaysOfWeek,
		Frequency:  s.Frequency,
		Interval:   s.Interval,
		Time:       s.Time,
		Timezone:   s.Timezone,
	}
	if !time.Time(s.StartTime).IsZero() {
		st := s.StartTime
		out.StartTime = &st
	}
	if !time.Time(s.EndTime).IsZero() {
		et := s.EndTime
		out.EndTime = &et
	}
	return out
}

// createScheduledTaskRequest is the POST body for a create. Like the update
// variant it declares the bool flags and schedule without `omitempty` so a
// `false` flag is serialized rather than stripped by the generated model. The
// remaining optional fields keep `omitempty` because on create there is no
// prior server state to clear: a null plan value should simply be omitted.
type createScheduledTaskRequest struct {
	IsActive             *bool                                  `json:"is_active"`
	TaskID               *string                                `json:"task_id"`
	Target               *string                                `json:"target"`
	DiscoverNewHosts     bool                                   `json:"discover_new_hosts"`
	DiscoverOfflineHosts bool                                   `json:"discover_offline_hosts"`
	Distribute           bool                                   `json:"distribute"`
	Schedule             *scheduleRequest                       `json:"schedule"`
	ScheduleName         string                                 `json:"schedule_name,omitempty"`
	ExpirationInterval   string                                 `json:"expiration_interval,omitempty"`
	ExecutionArgs        map[string]string                      `json:"execution_args,omitempty"`
	Guardrails           *models.FalconforitapiGuardrails       `json:"guardrails,omitempty"`
	TriggerCondition     []*models.FalconforitapiConditionGroup `json:"trigger_condition"`
}

// createScheduledTaskParams replaces the generated params object so the
// override request body is what gets serialized.
type createScheduledTaskParams struct {
	Body *createScheduledTaskRequest
}

func (p *createScheduledTaskParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if err := r.SetTimeout(cr.DefaultTimeout); err != nil {
		return err
	}
	if p.Body != nil {
		return r.SetBodyParam(p.Body)
	}
	return nil
}

// updateScheduledTaskRequest is the PATCH body for an update. Every field is
// declared without `omitempty` (unlike the generated
// models.ItautomationUpdateScheduledTaskRequest, which strips zero values) so
// that clearing an optional field actually sends the cleared value to the
// server instead of being silently dropped. The API treats an omitted/null
// field as "keep current", so:
//   - bools are sent explicitly so a flip to false sticks.
//   - execution_args sends an empty map to clear (null keeps).
//   - guardrails sends an empty object to clear the run-time limit (null keeps).
//   - trigger_condition sends an empty slice to clear (the API replaces, not
//     merges, on every update).
//
// schedule_name and expiration_interval cannot be cleared via update at all
// (the API rejects an empty string and ignores null), so the schema forces
// replacement when they are removed; here they are sent as a non-nil pointer
// only when the plan still has a value.
type updateScheduledTaskRequest struct {
	TaskID               string                                 `json:"task_id"`
	Target               string                                 `json:"target"`
	IsActive             bool                                   `json:"is_active"`
	DiscoverNewHosts     bool                                   `json:"discover_new_hosts"`
	DiscoverOfflineHosts bool                                   `json:"discover_offline_hosts"`
	Distribute           bool                                   `json:"distribute"`
	Schedule             *scheduleRequest                       `json:"schedule"`
	ScheduleName         *string                                `json:"schedule_name"`
	ExpirationInterval   *string                                `json:"expiration_interval"`
	ExecutionArgs        map[string]string                      `json:"execution_args"`
	Guardrails           *models.FalconforitapiGuardrails       `json:"guardrails"`
	TriggerCondition     []*models.FalconforitapiConditionGroup `json:"trigger_condition"`
}

// deactivateScheduledTaskRequest is a minimal PATCH body that flips
// `is_active` to false without resending the full desired configuration.
// Delete uses this to disable a task before removing it, where the full plan
// shape is not readily available. trigger_condition is echoed back because the
// API replaces (rather than merges) it on every update.
type deactivateScheduledTaskRequest struct {
	IsActive         bool                                   `json:"is_active"`
	TriggerCondition []*models.FalconforitapiConditionGroup `json:"trigger_condition"`
}

// updateScheduledTaskParams replaces the generated update params. The `id`
// query parameter must be re-set since we're replacing the request writer
// entirely.
type updateScheduledTaskParams struct {
	Body *updateScheduledTaskRequest
	ID   string
}

func (p *updateScheduledTaskParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if err := r.SetTimeout(cr.DefaultTimeout); err != nil {
		return err
	}
	if err := r.SetQueryParam("id", p.ID); err != nil {
		return err
	}
	if p.Body != nil {
		return r.SetBodyParam(p.Body)
	}
	return nil
}

// deactivateScheduledTaskParams replaces the generated update params for the
// deactivation call.
type deactivateScheduledTaskParams struct {
	Body *deactivateScheduledTaskRequest
	ID   string
}

func (p *deactivateScheduledTaskParams) WriteToRequest(r runtime.ClientRequest, _ strfmt.Registry) error {
	if err := r.SetTimeout(cr.DefaultTimeout); err != nil {
		return err
	}
	if err := r.SetQueryParam("id", p.ID); err != nil {
		return err
	}
	if p.Body != nil {
		return r.SetBodyParam(p.Body)
	}
	return nil
}
