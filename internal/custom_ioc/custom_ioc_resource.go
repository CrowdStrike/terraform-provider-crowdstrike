package customioc

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &customIOCResource{}
	_ resource.ResourceWithConfigure      = &customIOCResource{}
	_ resource.ResourceWithImportState    = &customIOCResource{}
	_ resource.ResourceWithValidateConfig = &customIOCResource{}
	_ resource.ResourceWithModifyPlan     = &customIOCResource{}
)

const (
	typeSHA256        = "sha256"
	typeMD5           = "md5"
	typeDomain        = "domain"
	typeIPv4          = "ipv4"
	typeIPv6          = "ipv6"
	typeAllSubdomains = "all_subdomains"

	platformWindows = "windows"
	platformMac     = "mac"
	platformLinux   = "linux"
	platformIOS     = "ios"
	platformAndroid = "android"

	actionAllow       = "allow"
	actionDetect      = "detect"
	actionPrevent     = "prevent"
	actionPreventNoUI = "prevent_no_ui"
	actionNoAction    = "no_action"

	severityInformational = "informational"
	severityLow           = "low"
	severityMedium        = "medium"
	severityHigh          = "high"
	severityCritical      = "critical"

	hostGroupAll = "all"
)

var (
	allTypes = []string{
		typeSHA256,
		typeMD5,
		typeDomain,
		typeIPv4,
		typeIPv6,
		typeAllSubdomains,
	}

	allPlatforms = []string{
		platformWindows,
		platformMac,
		platformLinux,
		platformIOS,
		platformAndroid,
	}

	allActions = []string{
		actionAllow,
		actionDetect,
		actionPrevent,
		actionPreventNoUI,
		actionNoAction,
	}

	allSeverities = []string{
		severityInformational,
		severityLow,
		severityMedium,
		severityHigh,
		severityCritical,
	}
)

// NewCustomIOCResource creates a new custom IOC resource.
func NewCustomIOCResource() resource.Resource {
	return &customIOCResource{}
}

// customIOCResource defines the resource implementation.
type customIOCResource struct {
	client *client.CrowdStrikeAPISpecification
}

// customIOCResourceModel describes the resource data model.
type customIOCResourceModel struct {
	ID              types.String      `tfsdk:"id"`
	Type            types.String      `tfsdk:"type"`
	Value           types.String      `tfsdk:"value"`
	Action          types.String      `tfsdk:"action"`
	MobileAction    types.String      `tfsdk:"mobile_action"`
	Severity        types.String      `tfsdk:"severity"`
	Description     types.String      `tfsdk:"description"`
	Platforms       types.Set         `tfsdk:"platforms"`
	HostGroups      types.Set         `tfsdk:"host_groups"`
	AppliedGlobally types.Bool        `tfsdk:"applied_globally"`
	Expiration      timetypes.RFC3339 `tfsdk:"expiration"`
	Source          types.String      `tfsdk:"source"`
	Tags            types.Set         `tfsdk:"tags"`
	CreatedBy       types.String      `tfsdk:"created_by"`
	CreatedOn       types.String      `tfsdk:"created_on"`
	ModifiedBy      types.String      `tfsdk:"modified_by"`
	ModifiedOn      types.String      `tfsdk:"modified_on"`
}

// wrap maps an API response model to the Terraform resource model.
func (m *customIOCResourceModel) wrap(
	ctx context.Context,
	indicator *models.APIIndicatorV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(indicator.ID)
	m.Type = types.StringValue(indicator.Type)
	m.Value = types.StringValue(indicator.Value)
	m.Severity = flex.StringValueToFramework(indicator.Severity)
	m.Description = flex.StringValueToFramework(indicator.Description)
	m.AppliedGlobally = types.BoolValue(indicator.AppliedGlobally)
	m.Source = flex.StringValueToFramework(indicator.Source)
	m.CreatedBy = types.StringValue(indicator.CreatedBy)
	m.CreatedOn = types.StringValue(indicator.CreatedOn.String())
	m.ModifiedBy = types.StringValue(indicator.ModifiedBy)
	m.ModifiedOn = types.StringValue(indicator.ModifiedOn.String())
	m.Expiration = flex.DateTimeValueToFramework(indicator.Expiration)

	// action/mobile_action: the API silently fills the field that does not apply
	// to the configured platforms with "no_action". Null the field the user was
	// not allowed to set so state matches plan. sha256/md5 are non-mobile-only,
	// all_subdomains is mobile-only; other types depend on platforms.
	switch indicator.Type {
	case typeSHA256, typeMD5:
		m.Action = flex.StringValueToFramework(indicator.Action)
		m.MobileAction = types.StringNull()
	case typeAllSubdomains:
		m.Action = types.StringNull()
		m.MobileAction = flex.StringValueToFramework(indicator.MobileAction)
	default:
		if slices.ContainsFunc(indicator.Platforms, isNonMobilePlatform) {
			m.Action = flex.StringValueToFramework(indicator.Action)
		} else {
			m.Action = types.StringNull()
		}
		if slices.ContainsFunc(indicator.Platforms, isMobilePlatform) {
			m.MobileAction = flex.StringValueToFramework(indicator.MobileAction)
		} else {
			m.MobileAction = types.StringNull()
		}
	}

	platforms, d := types.SetValueFrom(ctx, types.StringType, indicator.Platforms)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	m.Platforms = platforms

	if indicator.AppliedGlobally {
		hostGroups, d := types.SetValueFrom(ctx, types.StringType, []string{hostGroupAll})
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.HostGroups = hostGroups
	} else {
		hostGroups, d := types.SetValueFrom(ctx, types.StringType, indicator.HostGroups)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.HostGroups = hostGroups
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

func (r *customIOCResource) Configure(
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

func (r *customIOCResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_custom_ioc"
}

func (r *customIOCResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Endpoint Security",
			"Manages IOC (Indicator of Compromise) indicators in CrowdStrike Falcon. IOC indicators allow you to create custom indicators based on SHA256 hashes, MD5 hashes, domains, IPv4 addresses, or IPv6 addresses with actions such as allow, detect, or prevent.",
			apiScopes,
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
				MarkdownDescription: "The type of the IOC indicator. Valid values are: `sha256`, `md5`, `domain`, `ipv4`, `ipv6`, `all_subdomains`. `sha256` and `md5` are only valid with non-mobile platforms (`windows`, `mac`, `linux`); `all_subdomains` is only valid with mobile platforms (`ios`, `android`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(allTypes...),
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
				Optional:            true,
				MarkdownDescription: "The action to take on non-mobile platforms (`windows`, `mac`, `linux`). Required when `platforms` contains a non-mobile platform. Valid values are: `allow`, `detect`, `prevent`, `prevent_no_ui`, `no_action`. For `domain`, `ipv4`, and `ipv6` types only `detect` and `no_action` are permitted.",
				Validators: []validator.String{
					stringvalidator.OneOf(allActions...),
				},
			},
			"mobile_action": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The action to take on mobile platforms (`ios`, `android`). Required when `platforms` contains a mobile platform. Valid values are: `allow`, `detect`, `prevent`, `prevent_no_ui`, `no_action`.",
				Validators: []validator.String{
					stringvalidator.OneOf(allActions...),
				},
			},
			"severity": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The severity level of the IOC indicator. Required when `action` or `mobile_action` is `detect` or `prevent`; must not be set for other actions. Valid values are: `informational`, `low`, `medium`, `high`, `critical`.",
				Validators: []validator.String{
					stringvalidator.OneOf(allSeverities...),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A description of the IOC indicator.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platforms": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "The platforms this IOC indicator applies to. Valid values are: `windows`, `mac`, `linux`, `ios`, `android`. Hash types (`sha256`, `md5`) only support non-mobile platforms (`windows`, `mac`, `linux`); `all_subdomains` only supports mobile platforms (`ios`, `android`).",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf(allPlatforms...),
					),
					setvalidator.SizeAtLeast(1),
				},
			},
			"host_groups": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs that receive this indicator. Use `[\"all\"]` to apply globally.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
					),
				},
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the indicator is applied globally to all hosts.",
			},
			"expiration": schema.StringAttribute{
				CustomType:          timetypes.RFC3339Type{},
				Optional:            true,
				MarkdownDescription: "The expiration date of the IOC indicator in RFC 3339 format (e.g. `2025-12-31T23:59:59Z`). Must be a future date. Once this date passes, the API auto-resets `action` or `mobile_action` to `no_action` server-side. Terraform will show permanent drift on `action` after that point until `expiration` is bumped/removed or `action` is set to `no_action`.",
			},
			"source": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The source of the IOC indicator.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"tags": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A set of tags to apply to the IOC indicator.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
					),
				},
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
		},
	}
}

// ValidateConfig runs during validate, plan, and apply to check configuration validity.
func (r *customIOCResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var cfg customIOCResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.validateHostGroups(ctx, cfg, resp)
	r.validatePlatformsForType(ctx, cfg, resp)
	r.validateActionForType(ctx, cfg, resp)
	r.validateSeverityRequirement(cfg, resp)
	r.validateActionPresence(ctx, cfg, resp)
}

// ModifyPlan enforces that expiration is always a future date when it changes.
// State-aware: lets users edit other fields on an IOC whose stored expiration has
// already passed, as long as they don't touch the expiration itself.
func (r *customIOCResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var planExp timetypes.RFC3339
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("expiration"), &planExp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planExp.IsNull() || planExp.IsUnknown() {
		return
	}

	if !req.State.Raw.IsNull() {
		var stateExp timetypes.RFC3339
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("expiration"), &stateExp)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !stateExp.IsNull() {
			equal, d := planExp.StringSemanticEquals(ctx, stateExp)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			if equal {
				return
			}
		}
	}

	t, d := planExp.ValueRFC3339Time()
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !t.After(time.Now()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("expiration"),
			"expiration must be a future date",
			"Set expiration to a date later than now, or remove it.",
		)
	}
}

func (r *customIOCResource) validateHostGroups(
	ctx context.Context,
	cfg customIOCResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if cfg.HostGroups.IsNull() || cfg.HostGroups.IsUnknown() {
		return
	}

	for _, elem := range cfg.HostGroups.Elements() {
		if elem.IsUnknown() {
			return
		}
	}

	groups := flex.ExpandSetAs[string](ctx, cfg.HostGroups, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if containsAll(groups) && len(groups) > 1 {
		resp.Diagnostics.AddAttributeError(
			path.Root("host_groups"),
			"Conflicting host_groups values",
			`host_groups cannot mix "all" with specific host group IDs. `+
				`Either use ["all"] to apply this indicator globally, `+
				`or provide a list of specific host group IDs without "all".`,
		)
	}
}

func (r *customIOCResource) validatePlatformsForType(
	ctx context.Context,
	cfg customIOCResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if cfg.Type.IsNull() || cfg.Type.IsUnknown() {
		return
	}
	if cfg.Platforms.IsNull() || cfg.Platforms.IsUnknown() {
		return
	}

	for _, elem := range cfg.Platforms.Elements() {
		if elem.IsUnknown() {
			return
		}
	}

	iocType := cfg.Type.ValueString()
	platforms := flex.ExpandSetAs[string](ctx, cfg.Platforms, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	switch iocType {
	case typeSHA256, typeMD5:
		for _, p := range platforms {
			if isMobilePlatform(p) {
				resp.Diagnostics.AddAttributeError(
					path.Root("platforms"),
					"Unsupported platform for hash type",
					fmt.Sprintf(
						`platform %q is not supported for %q indicators. `+
							`Hash types (sha256, md5) only support "windows", "mac", and "linux".`,
						p, iocType,
					),
				)
			}
		}
	case typeAllSubdomains:
		for _, p := range platforms {
			if isNonMobilePlatform(p) {
				resp.Diagnostics.AddAttributeError(
					path.Root("platforms"),
					"Unsupported platform for all_subdomains type",
					fmt.Sprintf(
						`platform %q is not supported for "all_subdomains" indicators. `+
							`The "all_subdomains" type only supports mobile platforms ("ios", "android").`,
						p,
					),
				)
			}
		}
	}
}

func (r *customIOCResource) validateActionForType(
	ctx context.Context,
	cfg customIOCResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if cfg.Type.IsNull() || cfg.Type.IsUnknown() {
		return
	}
	if cfg.Action.IsNull() || cfg.Action.IsUnknown() {
		return
	}
	if cfg.Platforms.IsNull() || cfg.Platforms.IsUnknown() {
		return
	}

	for _, elem := range cfg.Platforms.Elements() {
		if elem.IsUnknown() {
			return
		}
	}

	platforms := flex.ExpandSetAs[string](ctx, cfg.Platforms, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	hasNonMobile := slices.ContainsFunc(platforms, isNonMobilePlatform)
	if !hasNonMobile {
		return
	}

	iocType := cfg.Type.ValueString()
	action := cfg.Action.ValueString()

	switch iocType {
	case typeDomain, typeIPv4, typeIPv6:
		if action != actionDetect && action != actionNoAction {
			resp.Diagnostics.AddAttributeError(
				path.Root("action"),
				"Invalid action for type",
				fmt.Sprintf(
					`action %q is not permitted for %q indicators on non-mobile platforms. `+
						`Valid actions for %q are "detect" and "no_action".`,
					action, iocType, iocType,
				),
			)
		}
	}
}

func (r *customIOCResource) validateSeverityRequirement(
	cfg customIOCResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if cfg.Action.IsUnknown() || cfg.MobileAction.IsUnknown() || cfg.Severity.IsUnknown() {
		return
	}

	action := cfg.Action.ValueString()
	mobileAction := cfg.MobileAction.ValueString()
	severitySet := cfg.Severity.ValueString() != ""
	severityRequired := isDetectionAction(action) || isDetectionAction(mobileAction)

	switch {
	case severitySet && !severityRequired:
		resp.Diagnostics.AddAttributeError(
			path.Root("severity"),
			"Invalid severity",
			fmt.Sprintf(
				`severity is only allowed when action or mobile_action is "detect" or "prevent" `+
					`(got action=%q, mobile_action=%q). `+
					`Remove severity, or change action or mobile_action to "detect" or "prevent".`,
				action, mobileAction,
			),
		)
	case !severitySet && severityRequired:
		resp.Diagnostics.AddAttributeError(
			path.Root("severity"),
			"Missing required severity",
			fmt.Sprintf(
				`severity is required when action or mobile_action is "detect" or "prevent" `+
					`(got action=%q, mobile_action=%q). `+
					`Set severity to one of "informational", "low", "medium", "high", or "critical".`,
				action, mobileAction,
			),
		)
	}
}

func (r *customIOCResource) validateActionPresence(
	ctx context.Context,
	cfg customIOCResourceModel,
	resp *resource.ValidateConfigResponse,
) {
	if cfg.Platforms.IsNull() || cfg.Platforms.IsUnknown() {
		return
	}

	for _, elem := range cfg.Platforms.Elements() {
		if elem.IsUnknown() {
			return
		}
	}

	if cfg.Action.IsUnknown() || cfg.MobileAction.IsUnknown() {
		return
	}

	platforms := flex.ExpandSetAs[string](ctx, cfg.Platforms, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	hasNonMobile := slices.ContainsFunc(platforms, isNonMobilePlatform)
	hasMobile := slices.ContainsFunc(platforms, isMobilePlatform)
	actionSet := cfg.Action.ValueString() != ""
	mobileActionSet := cfg.MobileAction.ValueString() != ""

	if hasNonMobile && !actionSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("action"),
			"Missing required action",
			`action is required when platforms contains a non-mobile platform ("windows", "mac", "linux").`,
		)
	}

	if !hasNonMobile && actionSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("action"),
			"action has no effect without a non-mobile platform",
			`action applies only to non-mobile platforms ("windows", "mac", "linux"). `+
				`The API silently discards it when platforms contains only mobile entries. `+
				`Either remove action or add a non-mobile platform.`,
		)
	}

	if hasMobile && !mobileActionSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("mobile_action"),
			"Missing required mobile_action",
			`mobile_action is required when platforms contains a mobile platform ("ios", "android").`,
		)
	}

	if !hasMobile && mobileActionSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("mobile_action"),
			"mobile_action has no effect without a mobile platform",
			`mobile_action applies only to mobile platforms ("ios", "android"). `+
				`The API silently discards it when platforms contains only non-mobile entries. `+
				`Either remove mobile_action or add a mobile platform.`,
		)
	}
}

func isMobilePlatform(p string) bool {
	return p == platformIOS || p == platformAndroid
}

func isNonMobilePlatform(p string) bool {
	return p == platformWindows || p == platformMac || p == platformLinux
}

func isDetectionAction(action string) bool {
	return action == actionDetect || action == actionPrevent
}

func (r *customIOCResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan customIOCResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating IOC indicator", map[string]any{
		"type":  plan.Type.ValueString(),
		"value": plan.Value.ValueString(),
	})

	var platforms []string
	resp.Diagnostics.Append(plan.Platforms.ElementsAs(ctx, &platforms, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var hostGroups []string
	resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tags := []string{}
	if !plan.Tags.IsNull() {
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	appliedGlobally := containsAll(hostGroups)
	if appliedGlobally {
		hostGroups = nil
	}

	indicator := &models.APIIndicatorCreateReqV1{
		Type:            plan.Type.ValueString(),
		Value:           plan.Value.ValueString(),
		Action:          plan.Action.ValueString(),
		MobileAction:    plan.MobileAction.ValueString(),
		Severity:        plan.Severity.ValueString(),
		Description:     plan.Description.ValueString(),
		Platforms:       platforms,
		HostGroups:      hostGroups,
		AppliedGlobally: &appliedGlobally,
		Source:          plan.Source.ValueString(),
		Tags:            tags,
	}

	if !plan.Expiration.IsNull() {
		t, tDiags := plan.Expiration.ValueRFC3339Time()
		resp.Diagnostics.Append(tDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		dt := strfmt.DateTime(t)
		indicator.Expiration = &dt
	}

	body := &models.APIIndicatorCreateReqsV1{
		Indicators: []*models.APIIndicatorCreateReqV1{indicator},
	}

	params := ioc.NewIndicatorCreateV1ParamsWithContext(ctx).WithBody(body)
	ignoreWarnings := true
	params.SetIgnoreWarnings(&ignoreWarnings)

	res, err := r.client.Ioc.IndicatorCreateV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopes))
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

	plan.ID = types.StringValue(createdIndicator.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Created IOC indicator", map[string]any{
		"id": createdIndicator.ID,
	})

	resp.Diagnostics.Append(plan.wrap(ctx, createdIndicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *customIOCResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state customIOCResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Debug(ctx, "Reading IOC indicator", map[string]any{
		"id": id,
	})

	indicator, readDiags := getCustomIOC(ctx, r.client, id)
	if tferrors.HasNotFoundError(readDiags) {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, indicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *customIOCResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan customIOCResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state customIOCResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Debug(ctx, "Updating IOC indicator", map[string]any{
		"id": id,
	})

	var platforms []string
	resp.Diagnostics.Append(plan.Platforms.ElementsAs(ctx, &platforms, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var hostGroups []string
	resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tags := []string{}
	if !plan.Tags.IsNull() {
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	appliedGlobally := containsAll(hostGroups)
	if appliedGlobally {
		hostGroups = nil
	}

	expiration, expDiags := buildUpdateExpiration(plan.Expiration)
	resp.Diagnostics.Append(expDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := &models.APIIndicatorUpdateReqV1{
		ID:              id,
		Action:          plan.Action.ValueString(),
		MobileAction:    plan.MobileAction.ValueString(),
		Severity:        flex.FrameworkToStringPointer(plan.Severity),
		Expiration:      expiration,
		Description:     flex.FrameworkToStringPointer(plan.Description),
		Platforms:       platforms,
		HostGroups:      hostGroups,
		AppliedGlobally: appliedGlobally,
		Source:          flex.FrameworkToStringPointer(plan.Source),
		Tags:            tags,
	}

	body := &models.APIIndicatorUpdateReqsV1{
		Indicators: []*models.APIIndicatorUpdateReqV1{updateReq},
	}

	params := ioc.NewIndicatorUpdateV1ParamsWithContext(ctx).WithBody(body)
	ignoreWarnings := true
	params.SetIgnoreWarnings(&ignoreWarnings)

	res, err := r.client.Ioc.IndicatorUpdateV1(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopes))
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

	updatedIndicator := payload.Resources[0]

	tflog.Debug(ctx, "Updated IOC indicator", map[string]any{
		"id": id,
	})

	plannedAction := plan.Action
	plannedMobileAction := plan.MobileAction

	resp.Diagnostics.Append(plan.wrap(ctx, updatedIndicator)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.suppressExpiredActionDrift(plan.Expiration, plannedAction, plannedMobileAction, &plan, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *customIOCResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state customIOCResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	tflog.Debug(ctx, "Deleting IOC indicator", map[string]any{
		"id": id,
	})

	params := ioc.NewIndicatorDeleteV1ParamsWithContext(ctx).WithIds([]string{id})
	_, err := r.client.Ioc.IndicatorDeleteV1(params)
	if err != nil {
		diagErr := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopes)
		if diagErr != nil && diagErr.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diagErr)
		return
	}

	tflog.Debug(ctx, "Deleted IOC indicator", map[string]any{
		"id": id,
	})
}

func (r *customIOCResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func containsAll(groups []string) bool {
	return slices.Contains(groups, hostGroupAll)
}

// buildUpdateExpiration returns the expiration to include in the update request:
//   - null/unknown plan: zero DateTime, which clears the expiration server-side.
//   - expired plan: nil, so the field is omitted. The API rejects updates that
//     resend an already-expired expiration.
//   - otherwise: the plan value.
//
// Relies on ModifyPlan's invariant: by the time an update reaches here, an
// expired plan value implies plan == state (ModifyPlan blocks every other
// expired case). If ModifyPlan's state-aware carve-out changes, reconsider
// whether this function still has enough context to decide safely.
func buildUpdateExpiration(plan timetypes.RFC3339) (*strfmt.DateTime, diag.Diagnostics) {
	var diags diag.Diagnostics

	if plan.IsNull() {
		zero := strfmt.DateTime{}
		return &zero, diags
	}

	planTime, d := plan.ValueRFC3339Time()
	diags.Append(d...)
	if diags.HasError() {
		return nil, diags
	}

	if !planTime.After(time.Now()) {
		return nil, diags
	}

	exp := strfmt.DateTime(planTime)
	return &exp, diags
}

// Once expiration passes, the API auto-resets action/mobile_action to "no_action". If the
// caller applied with a non-no_action value, keep the planned value in state and warn; this
// prevents the apply from landing in a state that immediately disagrees with itself.
func (r *customIOCResource) suppressExpiredActionDrift(
	expiration timetypes.RFC3339,
	plannedAction types.String,
	plannedMobileAction types.String,
	model *customIOCResourceModel,
	diags *diag.Diagnostics,
) {
	if expiration.IsNull() {
		return
	}

	t, d := expiration.ValueRFC3339Time()
	diags.Append(d...)
	if d.HasError() {
		return
	}

	if !t.Before(time.Now()) {
		return
	}

	warned := false
	if actionSuppressed(plannedAction, model.Action) {
		model.Action = plannedAction
		warned = true
	}
	if actionSuppressed(plannedMobileAction, model.MobileAction) {
		model.MobileAction = plannedMobileAction
		warned = true
	}

	if warned {
		diags.AddAttributeWarning(
			path.Root("expiration"),
			"expiration is in the past",
			`The expiration date has already passed. The CrowdStrike API auto-reset action to `+
				`"no_action" during this apply. Terraform requires the post-apply state to match the plan, `+
				`so the planned value was retained in state to avoid an apply failure. `+
				`The next refresh will read "no_action" from the API and show drift until expiration is `+
				`bumped/removed or action is set to "no_action".`,
		)
	}
}

func actionSuppressed(planned, actual types.String) bool {
	if planned.IsNull() || planned.IsUnknown() {
		return false
	}
	p := planned.ValueString()
	if p == "" || p == actionNoAction {
		return false
	}
	return actual.ValueString() == actionNoAction
}

func getCustomIOC(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) (*models.APIIndicatorV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := ioc.NewIndicatorGetV1ParamsWithContext(ctx).WithIds([]string{id})
	res, err := client.Ioc.IndicatorGetV1(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopes))
		return nil, diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewNotFoundError(
			fmt.Sprintf("IOC indicator with ID %s was not found.", id),
		))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}
