package dataprotection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/float64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &dataProtectionPolicyResource{}
	_ resource.ResourceWithConfigure      = &dataProtectionPolicyResource{}
	_ resource.ResourceWithImportState    = &dataProtectionPolicyResource{}
	_ resource.ResourceWithModifyPlan     = &dataProtectionPolicyResource{}
	_ resource.ResourceWithValidateConfig = &dataProtectionPolicyResource{}
)

const (
	// Practitioner-facing platform values. These are the console's own platform
	// selector labels and they match every other platform-scoped resource in the
	// provider.
	platformWindows = "Windows"
	platformMac     = "Mac"

	// Wire values required by the platform_name query parameter on the create,
	// update, and delete operations. Never exposed in the schema.
	apiPlatformWin = "win"
	apiPlatformMac = "mac"

	// Maximum inspection file size. Falcon checks the raw number against
	// [512, 524288000] whatever the unit is, then checks the byte total against
	// 524288000 after applying the unit, so both bounds are needed: the first as a
	// schema validator, the second as a cross-field check in ValidateConfig.
	// 524288000 bytes is exactly 500 MiB. The default, 104857600 bytes, is exactly
	// 100 MiB and is the same size as the Falcon default of 104.8576 MB, which
	// cannot itself be sent because 104.8576 fails the raw-number check.
	maxFileSizeMinBytes     = 512
	maxFileSizeMaxBytes     = 524288000
	maxFileSizeDefaultBytes = 104857600

	// max_file_size_unit values. KB and MB are decimal, verified on the wire:
	// 512 + MB converts to 512000000 and 524288 + KB converts to 524288000.
	maxFileSizeUnitBytes = "Bytes"
	maxFileSizeUnitKB    = "KB"
	maxFileSizeUnitMB    = "MB"

	// The two values every message-source enum accepts. The provider selects
	// between them from whether the matching custom-message attribute is
	// configured, so the practitioner never writes either one. Applies to
	// allow_notifications, block_notifications, and be_splash_message_source.
	messageSourceDefault = "default"
	messageSourceCustom  = "custom"

	// excludeDomainsSeparator joins be_exclude_domains for the wire. The API
	// stores the whole tag list as one string and bounds the joined value, not any
	// single element.
	excludeDomainsSeparator = ","
	excludeDomainsMaxLength = 2048

	// eujBuiltinHeaderKey caches Falcon's built-in justification header in private
	// state. Every write that carries euj_header_text must reproduce that sentence
	// verbatim in headers[0], and the provider reads it from the API rather than
	// hardcoding it, so it has to survive between applies. Private state rather than
	// a schema attribute because the sentence is a product constant, not a property
	// of the policy the practitioner manages.
	eujBuiltinHeaderKey = "euj_builtin_header_text"

	// The two built-in justification options. The API requires
	// euj_dropdown_options.justifications[0] and [1] to carry exactly this text, in
	// this order, each with default:true and with id equal to its own
	// justification. Omitting id, sending "", sending any other string, or
	// swapping the two values all return 400. Neither the text nor the id is
	// practitioner-configurable.
	eujMandatoryBusinessPurposes = "Business purposes"
	eujMandatoryPersonalUse      = "Personal use"

	// eujMinimumEnabledOptions is the smallest number of justification options the
	// API accepts, counting the two built-ins and every custom option.
	eujMinimumEnabledOptions = 2
)

// Defaults for the settings that control another attribute. ValidateConfig has to
// resolve a null controller to the value the plan will actually carry, so each of
// these is named once here and referenced from both the schema Default and the
// dependency rule rather than written twice.
const (
	defaultContextInspection       = true
	defaultContentInspection       = true
	defaultSimilarityDetection     = false
	defaultEujBuiltinOptionEnabled = true

	// Platform-scoped controllers. These are also the values
	// platformScopedSettings plans on Windows.
	defaultEvidenceStorage                = false
	defaultScreenCapture                  = false
	defaultNetworkInspection              = false
	defaultBrowsersWithoutActiveExtension = "allow"
)

// maxFileSizeUnitFactors converts a max_file_size_unit to bytes. Used by the
// stage-2 cross-field check in ValidateConfig.
var maxFileSizeUnitFactors = map[string]float64{
	maxFileSizeUnitBytes: 1,
	maxFileSizeUnitKB:    1000,
	maxFileSizeUnitMB:    1000000,
}

// platformScopedSetting is a setting that exists on exactly one platform. Most of
// them the API rejects on the other platform with HTTP 400; the two
// unsupported-browser settings it accepts on Mac and ignores, because the Mac sensor
// has no unsupported-browser enforcement. Either way the setting is only meaningful
// on one platform, and because a schema Default is unconditional, the default has to
// be applied by ModifyPlan under a platform guard instead.
type platformScopedSetting struct {
	name     string     // attribute name
	platform string     // platformWindows or platformMac
	value    attr.Value // the default on its own platform
	null     attr.Value // the typed null for the other platform

	// get reads the setting out of a model. ModifyPlan and ValidateConfig both
	// iterate the table and need the matching value without knowing its concrete
	// type, and the framework cannot read an attribute into an attr.Value target,
	// so each row states its own accessor. Declaring it here rather than in a
	// name-keyed switch elsewhere makes a missing accessor a compile error.
	get func(dataProtectionPolicyResourceModel) attr.Value
}

// platformScopedSettings declares the platform partition and its defaults once.
// ValidateConfig reads it for the platform rejection rules, and ModifyPlan reads
// it to apply the defaults. The API also rejects
// evidence_duplication_enabled_default and
// enable_end_user_notifications_unsupported_browser on Mac, but neither is exposed
// as an attribute, so neither has anything to validate or default.
//
// Values are the observed fresh-create defaults. `null` is explicit rather than
// derived because resp.Plan.SetAttribute takes an interface{} and requires a typed
// null such as types.BoolNull() rather than an untyped nil.
var platformScopedSettings = []platformScopedSetting{
	{
		name: "browsers_without_active_extension", platform: platformWindows,
		value: types.StringValue(defaultBrowsersWithoutActiveExtension), null: types.StringNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.BrowsersWithoutActiveExtension },
	},
	{
		name: "block_all_data_access", platform: platformWindows,
		value: types.BoolValue(false), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.BlockAllDataAccess },
	},
	{
		name: "screen_capture", platform: platformWindows,
		value: types.BoolValue(defaultScreenCapture), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.ScreenCapture },
	},
	{
		name: "screen_capture_pre_event_seconds", platform: platformWindows,
		value: types.StringValue("3"), null: types.StringNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.ScreenCapturePreEventSeconds },
	},
	{
		name: "screen_capture_post_event_seconds", platform: platformWindows,
		value: types.StringValue("3"), null: types.StringNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.ScreenCapturePostEventSeconds },
	},
	{
		name: "evidence_storage", platform: platformWindows,
		value: types.BoolValue(defaultEvidenceStorage), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.EvidenceStorage },
	},
	{
		name: "end_user_encryption_activity", platform: platformWindows,
		value: types.BoolValue(false), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.EndUserEncryptionActivity },
	},
	{
		name: "evidence_storage_max_free_space_percent", platform: platformWindows,
		value: types.Float64Value(2), null: types.Float64Null(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.EvidenceStorageMaxFreeSpacePercent },
	},
	{
		name: "evidence_storage_max_size_gib", platform: platformWindows,
		value: types.Float64Value(1), null: types.Float64Null(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.EvidenceStorageMaxSizeGiB },
	},
	{
		name: "network_inspection", platform: platformWindows,
		value: types.BoolValue(defaultNetworkInspection), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.NetworkInspection },
	},
	{
		name: "network_inspection_files_exceeding_size_limit", platform: platformWindows,
		value: types.StringValue("allow"), null: types.StringNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value {
			return m.NetworkInspectionFilesExceedingSizeLimit
		},
	},
	{
		name: "enable_ocr", platform: platformMac,
		value: types.BoolValue(true), null: types.BoolNull(),
		get: func(m dataProtectionPolicyResourceModel) attr.Value { return m.EnableOCR },
	},
}

var policyResourceRequiredScopes = []scopes.Scope{
	{Name: "Data Protection", Read: true, Write: true},
}

// policyIDPattern is the shape of a policy ID. Import validates against it
// locally so a typo produces a clear provider error instead of the API's
// "has length 13, at least 32 expected".
var policyIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// eujCompanyLogoPattern is the prefix a base64 PNG data URI carries. Compiled
// once here rather than in Schema, matching policyIDPattern above.
var eujCompanyLogoPattern = regexp.MustCompile(`^data:image/png(?:;charset=utf-8)?;base64,`)

// platformNameToAPI translates the practitioner-facing platform_name into the
// wire value the platform_name query parameter requires.
var platformNameToAPI = map[string]string{
	platformWindows: apiPlatformWin,
	platformMac:     apiPlatformMac,
}

// platformNameFromAPI translates the platform_name the API returns back into the
// practitioner-facing value.
var platformNameFromAPI = map[string]string{
	apiPlatformWin: platformWindows,
	apiPlatformMac: platformMac,
}

func NewDataProtectionPolicyResource() resource.Resource {
	return &dataProtectionPolicyResource{}
}

type dataProtectionPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataProtectionPolicyResourceModel struct {
	// Identity and structure
	ID           types.String `tfsdk:"id"`
	PlatformName types.String `tfsdk:"platform_name"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	Enabled      types.Bool   `tfsdk:"enabled"`

	// Assignment
	HostGroups      types.Set `tfsdk:"host_groups"`
	Classifications types.Set `tfsdk:"classifications"`

	// Server-owned metadata
	CID       types.String `tfsdk:"cid"`
	CreatedAt types.String `tfsdk:"created_at"`
	CreatedBy types.String `tfsdk:"created_by"`

	// Inspection
	ContextInspection          types.Bool    `tfsdk:"context_inspection"`
	ContentInspection          types.Bool    `tfsdk:"content_inspection"`
	ClipboardInspection        types.Bool    `tfsdk:"clipboard_inspection"`
	ClipboardWebOrigin         types.Bool    `tfsdk:"clipboard_web_origin"`
	SimilarityDetection        types.Bool    `tfsdk:"similarity_detection"`
	MinimumSimilarityThreshold types.String  `tfsdk:"minimum_similarity_threshold"`
	InspectionDepth            types.String  `tfsdk:"inspection_depth"`
	InspectionConfidence       types.String  `tfsdk:"inspection_confidence"`
	MaxFileSize                types.Float64 `tfsdk:"max_file_size"`
	MaxFileSizeUnit            types.String  `tfsdk:"max_file_size_unit"`

	// Browser extension
	BeExcludeDomains                 types.Set     `tfsdk:"be_exclude_domains"`
	BeSplashScreen                   types.Bool    `tfsdk:"be_splash_screen"`
	BeCustomSplashMessage            types.String  `tfsdk:"be_custom_splash_message"`
	BeUploadTimeoutSeconds           types.Int32   `tfsdk:"be_upload_timeout_seconds"`
	BeUploadTimeoutResponse          types.String  `tfsdk:"be_upload_timeout_response"`
	BePasteTimeoutMilliseconds       types.Int32   `tfsdk:"be_paste_timeout_milliseconds"`
	BePasteTimeoutResponse           types.String  `tfsdk:"be_paste_timeout_response"`
	BePasteClipboardMinSize          types.Float64 `tfsdk:"be_paste_clipboard_min_size"`
	BePasteClipboardMinSizeUnit      types.String  `tfsdk:"be_paste_clipboard_min_size_unit"`
	BePasteClipboardMaxSize          types.Float64 `tfsdk:"be_paste_clipboard_max_size"`
	BePasteClipboardMaxSizeUnit      types.String  `tfsdk:"be_paste_clipboard_max_size_unit"`
	BePasteClipboardBlockOverMaxSize types.Bool    `tfsdk:"be_paste_clipboard_block_over_max_size"`

	// Unsupported browsers
	BrowsersWithoutActiveExtension types.String `tfsdk:"browsers_without_active_extension"`
	BlockAllDataAccess             types.Bool   `tfsdk:"block_all_data_access"`

	// End user notifications
	CustomAllowedActionNotification types.String `tfsdk:"custom_allowed_action_notification"`
	CustomBlockedActionNotification types.String `tfsdk:"custom_blocked_action_notification"`

	// End user justification
	EujRequireAdditionalDetails types.Bool   `tfsdk:"euj_require_additional_details"`
	EujDialogTimeout            types.Int32  `tfsdk:"euj_dialog_timeout"`
	EujCompanyLogo              types.String `tfsdk:"euj_company_logo"`
	EujCustomHeaderText         types.String `tfsdk:"euj_custom_header_text"`
	EujBusinessPurposesEnabled  types.Bool   `tfsdk:"euj_business_purposes_enabled"`
	EujPersonalUseEnabled       types.Bool   `tfsdk:"euj_personal_use_enabled"`
	EujCustomDropdownOptions    types.List   `tfsdk:"euj_custom_dropdown_options"`

	// Windows only
	ScreenCapture                            types.Bool    `tfsdk:"screen_capture"`
	ScreenCapturePreEventSeconds             types.String  `tfsdk:"screen_capture_pre_event_seconds"`
	ScreenCapturePostEventSeconds            types.String  `tfsdk:"screen_capture_post_event_seconds"`
	EvidenceStorage                          types.Bool    `tfsdk:"evidence_storage"`
	EndUserEncryptionActivity                types.Bool    `tfsdk:"end_user_encryption_activity"`
	EvidenceStorageMaxFreeSpacePercent       types.Float64 `tfsdk:"evidence_storage_max_free_space_percent"`
	EvidenceStorageMaxSizeGiB                types.Float64 `tfsdk:"evidence_storage_max_size_gib"`
	NetworkInspection                        types.Bool    `tfsdk:"network_inspection"`
	NetworkInspectionFilesExceedingSizeLimit types.String  `tfsdk:"network_inspection_files_exceeding_size_limit"`

	// Mac only
	EnableOCR types.Bool `tfsdk:"enable_ocr"`
}

func (r *dataProtectionPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_data_protection_policy"
}

func (r *dataProtectionPolicyResource) Configure(
	_ context.Context,
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
			fmt.Sprintf("Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = providerConfig.Client
}

func (r *dataProtectionPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Data Protection",
			"Manages a Falcon Data Protection policy for a single platform, including its settings, assigned host groups, and assigned classifications.",
			policyResourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			// ---------- identity and structure ----------
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Platform the policy applies to. Accepts `Windows` or `Mac`. Changing this causes a replace.",
				Validators: []validator.String{
					stringvalidator.OneOf(platformWindows, platformMac),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Description of the policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the policy is enabled. Defaults to `false`.",
			},

			// ---------- assignment ----------
			"host_groups": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs assigned to this policy. Omit the attribute to assign no host groups; an explicitly empty set is rejected.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
					),
				},
			},
			"classifications": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Classification IDs assigned to this policy. Omit the attribute to assign no classifications; an explicitly empty set is rejected.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
					),
				},
			},

			// ---------- server-owned metadata ----------
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "Customer ID that owns the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the policy was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "Identity that created the policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// ---------- inspection ----------
			"context_inspection": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(defaultContextInspection),
				MarkdownDescription: "Gives insight into data sources, assigned sensitivity labels, and file types, for data in motion and at rest. Defaults to `true`.",
			},
			"content_inspection": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(defaultContentInspection),
				MarkdownDescription: "Inspects egressing data against the content patterns used by this policy's classifications. Defaults to `true`.",
			},
			"clipboard_inspection": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Detects egress when classified data is pasted from the clipboard in supported browsers. Defaults to `false`.",
			},
			"clipboard_web_origin": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Tracks and attributes web sources for clipboard content copied from web applications. Requires `context_inspection` to be `true`. Defaults to `false`.",
			},
			"similarity_detection": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(defaultSimilarityDetection),
				MarkdownDescription: "Detects egress of files containing content copied from other classified files on the same endpoint. Requires `context_inspection` to be `true`. Defaults to `false`.",
			},
			"minimum_similarity_threshold": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("80"),
				MarkdownDescription: "Minimum percentage of similar content required for an egress event to be monitored. Requires `similarity_detection` to be `true`. Defaults to `80`.",
				Validators: []validator.String{
					stringvalidator.OneOf("10", "20", "30", "40", "50", "60", "70", "80", "90", "100"),
				},
			},
			"inspection_depth": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("balanced"),
				MarkdownDescription: "Inspection depth for data in motion. Requires `content_inspection` to be `true`. Defaults to `balanced`.",
				Validators: []validator.String{
					stringvalidator.OneOf("balanced", "high_performance", "deep_scan"),
				},
			},
			"inspection_confidence": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("medium"),
				MarkdownDescription: "Minimum confidence level for reporting content matches. `low` reports more matches, `high` reports only high-confidence matches. Requires `content_inspection` to be `true`. Defaults to `medium`.",
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high"),
				},
			},
			"max_file_size": schema.Float64Attribute{
				Optional: true, Computed: true,
				Default:             float64default.StaticFloat64(maxFileSizeDefaultBytes),
				MarkdownDescription: "Largest file the sensor inspects for classified content, expressed in `max_file_size_unit`. Files above this size are not assessed against classification definitions. Defaults to `104857600` bytes (`100 MiB`).\n\nThe accepted range depends on the unit, because the value must be between `512` and `524288000` as written **and** at most `524288000` bytes (`500 MiB`) once converted: `512` to `524288000` for `Bytes`, `512` to `524288` for `KB`, and `512` to `524.288` for `MB`. `Bytes` is the only unit that can express the whole range.\n\nThe console shows this control in `MiB`, so a console value of `100 MiB` is `104857600` here.",
				Validators: []validator.Float64{
					float64validator.Between(maxFileSizeMinBytes, maxFileSizeMaxBytes),
				},
			},
			"max_file_size_unit": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString(maxFileSizeUnitBytes),
				MarkdownDescription: "Unit for `max_file_size`. Accepts `Bytes`, `KB`, or `MB`, where `KB` and `MB` are decimal multiples of `1000` and `1000000`. Defaults to `Bytes`.",
				Validators: []validator.String{
					stringvalidator.OneOf(maxFileSizeUnitBytes, maxFileSizeUnitKB, maxFileSizeUnitMB),
				},
			},

			// ---------- browser extension ----------
			"be_exclude_domains": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Domain patterns excluded from visibility and enforcement by the Falcon browser extension, for example `*://*.example.com/*`. No events are generated from excluded domains. These are the tags in the console's **Exclude domains** control.\n\nThe patterns are stored as a single comma-separated value that must be at most 2048 characters. Omit the attribute to exclude no domains; an explicitly empty set is rejected.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
					),
					fwvalidators.SetJoinedLengthAtMost(excludeDomainsSeparator, excludeDomainsMaxLength),
				},
			},
			"be_splash_screen": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the browser extension shows a splash screen while a file is being evaluated. Defaults to `true`.",
			},
			"be_custom_splash_message": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Custom text for the browser extension splash dialog. Omit the attribute to use the Falcon default text, `Processing. Please wait.`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthAtMost(256),
				},
			},
			"be_upload_timeout_seconds": schema.Int32Attribute{
				Optional: true, Computed: true,
				Default:             int32default.StaticInt32(40),
				MarkdownDescription: "How long the browser extension waits for a response when uploading data before timing out, in seconds. Must be between `1` and `300`. Defaults to `40`.",
				Validators: []validator.Int32{
					int32validator.Between(1, 300),
				},
			},
			"be_upload_timeout_response": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("allow"),
				MarkdownDescription: "Extension behavior when an upload evaluation times out. `allow` fails open, `block` fails closed. Defaults to `allow`.",
				Validators: []validator.String{
					stringvalidator.OneOf("allow", "block"),
				},
			},
			"be_paste_timeout_milliseconds": schema.Int32Attribute{
				Optional: true, Computed: true,
				Default:             int32default.StaticInt32(800),
				MarkdownDescription: "How long the browser extension waits for a response when pasting data before timing out, in milliseconds. Must be between `1` and `10000`. Defaults to `800`.",
				Validators: []validator.Int32{
					int32validator.Between(1, 10000),
				},
			},
			"be_paste_timeout_response": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("allow"),
				MarkdownDescription: "Extension behavior when a paste evaluation times out. `allow` fails open, `block` fails closed. Defaults to `allow`.",
				Validators: []validator.String{
					stringvalidator.OneOf("allow", "block"),
				},
			},
			"be_paste_clipboard_min_size": schema.Float64Attribute{
				Optional: true, Computed: true,
				Default:             float64default.StaticFloat64(32),
				MarkdownDescription: "Minimum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_min_size_unit`. Must be greater than `0` and at most `65536` regardless of the unit. Defaults to `32`, which with the default unit of `Bytes` is 32 bytes.",
				Validators: []validator.Float64{
					float64validator.Between(0, 65536),
					float64validator.NoneOf(0),
				},
			},
			"be_paste_clipboard_min_size_unit": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("Bytes"),
				MarkdownDescription: "Unit for `be_paste_clipboard_min_size`. Accepts `Bytes` or `KiB`. Defaults to `Bytes`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Bytes", "KiB"),
				},
			},
			"be_paste_clipboard_max_size": schema.Float64Attribute{
				Optional: true, Computed: true,
				Default:             float64default.StaticFloat64(0.0625),
				MarkdownDescription: "Maximum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_max_size_unit`. Must be greater than `0` and at most `65536` regardless of the unit. Defaults to `0.0625`, which with the default unit of `KiB` is 64 bytes.",
				Validators: []validator.Float64{
					float64validator.Between(0, 65536),
					float64validator.NoneOf(0),
				},
			},
			"be_paste_clipboard_max_size_unit": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:             stringdefault.StaticString("KiB"),
				MarkdownDescription: "Unit for `be_paste_clipboard_max_size`. Accepts `Bytes` or `KiB`. Defaults to `KiB`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Bytes", "KiB"),
				},
			},
			"be_paste_clipboard_block_over_max_size": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When `true`, pastes exceeding `be_paste_clipboard_max_size` are blocked regardless of content. Defaults to `false`.",
			},

			// ---------- unsupported browsers ----------
			//
			// Both of these are platform-scoped, so neither carries a `Default`. See
			// the Windows only section below for why, and platformScopedSettings for
			// the whole set.
			"browsers_without_active_extension": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** How browsers without an active Falcon extension handle data uploads, including Firefox, Internet Explorer, and incognito sessions. `allow` permits all uploads; `block_policy` blocks uploads matching a classification. Defaults to `allow`.\n\n~> **Note** On Mac, uploads from browsers without the extension active are neither monitored nor blocked, so Mac policies have no equivalent setting.",
				Validators: []validator.String{
					stringvalidator.OneOf("allow", "block_policy"),
				},
			},
			"block_all_data_access": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Blocks all data access via Firefox and Internet Explorer. Requires `browsers_without_active_extension` to be `block_policy`. Defaults to `false`.",
			},

			// ---------- end user notifications ----------
			"custom_allowed_action_notification": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Custom text shown to end users when a rule allows an action. Omit the attribute to use the Falcon default text, `An action has been allowed and logged by your organization's data protection policy.`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthBetween(2, 256),
				},
			},
			"custom_blocked_action_notification": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Custom text shown to end users when a rule blocks an action. Omit the attribute to use the Falcon default text, `An action has been blocked by your organization's data protection policy.`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.LengthBetween(2, 256),
				},
			},

			// ---------- end user justification ----------
			"euj_require_additional_details": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "When `true`, the end user must fill in the additional details box to proceed with a justification. Defaults to `true`.",
			},
			"euj_dialog_timeout": schema.Int32Attribute{
				Optional: true, Computed: true,
				Default:             int32default.StaticInt32(120),
				MarkdownDescription: "Timeout for the end user justification dialog, in seconds. Must be between `60` and `420`. If the user provides no justification the egress is blocked. Defaults to `120`.",
				Validators: []validator.Int32{
					int32validator.Between(60, 420),
				},
			},
			"euj_company_logo": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Company logo shown in the end user justification dialog, as a base64 PNG data URI. The image must be 100px by 100px with a transparent background.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(150000),
					stringvalidator.RegexMatches(
						eujCompanyLogoPattern,
						"must be a base64-encoded PNG data URI, for example \"data:image/png;base64,iVBORw0...\"",
					),
				},
			},
			"euj_custom_header_text": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Custom header text for the end user justification dialog. Omit the attribute to use the built-in Falcon message.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"euj_business_purposes_enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(defaultEujBuiltinOptionEnabled),
				MarkdownDescription: "Whether the built-in `Business purposes` option is offered in the end user justification dialog. Its text is fixed by Falcon. At least two options in total must be enabled. Defaults to `true`.",
			},
			"euj_personal_use_enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:             booldefault.StaticBool(defaultEujBuiltinOptionEnabled),
				MarkdownDescription: "Whether the built-in `Personal use` option is offered in the end user justification dialog. Its text is fixed by Falcon. At least two options in total must be enabled. Defaults to `true`.",
			},
			"euj_custom_dropdown_options": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Custom justification options offered in the end user justification dialog, shown after the two built-in options in the order defined here. At most two may be defined. In the Falcon console these are the rows added with **Add custom justification** under **EUJ dialog box > Dropdown options**.\n\nAt least two options in total, built-in or custom, must be enabled.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.SizeAtMost(2),
					listvalidator.UniqueValues(),
					listvalidator.ValueStringsAre(
						fwvalidators.StringNotWhitespace(),
						stringvalidator.NoneOf(
							eujMandatoryBusinessPurposes,
							eujMandatoryPersonalUse,
						),
					),
				},
			},

			// ---------- Windows only ----------
			//
			// No platform-scoped attribute carries a `Default`, because a `Default` is
			// unconditional and the API returns 400 for any of them on the wrong
			// platform. Their defaults are applied by ModifyPlan instead, guarded on
			// platform_name. platformScopedSettings is the full set, which also covers
			// the two unsupported-browser settings above and enable_ocr below.
			"screen_capture": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Captures the screen before and after an egress event. Requires `evidence_storage` to be `true`. Defaults to `false`.\n\n~> **Important** Enabling screen capture may carry legal obligations to notify or obtain consent from end users. Review the notice in the Falcon console before use.",
			},
			"screen_capture_pre_event_seconds": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Seconds of screen recording retained before a trigger event. Requires `screen_capture` to be `true`. Defaults to `3`.",
				Validators: []validator.String{
					stringvalidator.OneOf("3", "5", "10"),
				},
			},
			"screen_capture_post_event_seconds": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Seconds of screen recording retained after a trigger event. Requires `screen_capture` to be `true`. Defaults to `3`.",
				Validators: []validator.String{
					stringvalidator.OneOf("3", "5", "10"),
				},
			},
			"evidence_storage": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Allows users with the Data Protection Forensics Manager role to request and download files for egress events. Files larger than `max_file_size` cannot be retrieved. Defaults to `false`.",
			},
			"end_user_encryption_activity": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** When data encryption occurs, stores a copy of the original data in a protected folder on the host so it remains retrievable for 30 days. Requires `evidence_storage` to be `true`. Defaults to `false`.",
			},
			"evidence_storage_max_free_space_percent": schema.Float64Attribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Maximum percentage of free disk space evidence storage may consume. Must be between `1` and `90`. The smaller of this and `evidence_storage_max_size_gib` takes priority. Requires `evidence_storage` to be `true`. Defaults to `2`.",
				Validators: []validator.Float64{
					float64validator.Between(1, 90),
				},
			},
			"evidence_storage_max_size_gib": schema.Float64Attribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Maximum disk space in GiB that evidence storage may use on a host. Must be between `1` and `100`. When full, files are deleted first-in first-out. Requires `evidence_storage` to be `true`. Defaults to `1`.",
				Validators: []validator.Float64{
					float64validator.Between(1, 100),
				},
			},
			"network_inspection": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** Detects egress of classified data via network traffic. Network inspection only supports the web destinations listed in the Falcon documentation. Defaults to `false`.",
			},
			"network_inspection_files_exceeding_size_limit": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Windows only.** How network inspection handles file uploads larger than its 1 MiB ceiling. `allow` permits them, `block` blocks them. Requires `network_inspection` to be `true`. Defaults to `allow`.",
				Validators: []validator.String{
					stringvalidator.OneOf("allow", "block"),
				},
			},

			// ---------- Mac only ----------
			"enable_ocr": schema.BoolAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "**Mac only.** Extracts and classifies sensitive text from image files such as screenshots and photos during data egress. Requires `content_inspection` to be `true`. Defaults to `true`.",
			},
		},
	}
}

func (r *dataProtectionPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wirePlatform, diagnostic := wirePlatformName(plan.PlatformName.ValueString())
	if diagnostic != nil {
		resp.Diagnostics.Append(diagnostic)
		return
	}

	// The POST model requires a description key, so a null description is sent as
	// the empty string. flex canonicalizes it back to null when the API echoes it.
	//
	// The settings are accepted at create, so apart from euj_header_text they need
	// no follow-up update. They are carried by the override body rather than the
	// generated one, because gofalcon does not model enable_clipboard_web_origin.
	//
	// builtinHeader is deliberately empty, which omits euj_header_text: the API
	// validates headers[0] against its built-in sentence and nothing has told the
	// provider what that sentence is yet. The POST answers with it, and the
	// follow-up update below is what applies a custom header.
	properties := expandPolicyProperties(ctx, policyWrite{plan: plan}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	createResource := &policyPostOverride{
		PolicymanagerExternalPolicyPost: models.PolicymanagerExternalPolicyPost{
			Name:             plan.Name.ValueStringPointer(),
			Description:      flex.FrameworkToStringPointer(plan.Description),
			PolicyProperties: &properties.PolicymanagerPolicyProperties,
		},
		PolicyProperties: properties,
	}

	createBody := &models.PolicymanagerCreatePoliciesRequest{
		Resources: []*models.PolicymanagerExternalPolicyPost{
			&createResource.PolicymanagerExternalPolicyPost,
		},
	}

	params := data_protection_configuration.NewEntitiesPolicyPostV2Params().
		WithContext(ctx).
		WithPlatformName(wirePlatform).
		WithBody(createBody)

	tflog.Debug(ctx, "Creating data protection policy", map[string]any{
		"name":          plan.Name.ValueString(),
		"platform_name": plan.PlatformName.ValueString(),
	})

	res, err := r.client.DataProtectionConfiguration.EntitiesPolicyPostV2(
		params,
		withPolicyPostOverride(&policyCreateRequestOverride{
			Resources: []*policyPostOverride{createResource},
		}),
	)
	if err != nil {
		// Create is not safe to retry: there is no idempotency key and names are
		// not unique, so a policy may exist even though the call reported failure.
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			policyResourceRequiredScopes,
			tferrors.WithDetail(fmt.Sprintf(
				"The policy may or may not have been created. Check %s in the Falcon console before re-applying: "+
					"a retry would create a second policy with the same name.\n\n%s",
				plan.Name.ValueString(), err.Error(),
			)),
		))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diagnostic := policyPayloadDiagnostic(tferrors.Create, res.Payload.Errors); diagnostic != nil {
		resp.Diagnostics.Append(diagnostic)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	created := res.Payload.Resources[0]

	// createdState is the best state the failure paths below can write. The
	// generated response model drops enable_clipboard_web_origin, so the value the
	// provider just sent is carried across; the API acknowledged it. It stays nil
	// when the response carried no policy_properties, in which case there is
	// nothing better to write than the ID persisted just below, and writing zero
	// values for every setting would be worse than writing none.
	var createdState *policyOverride
	if created.PolicyProperties != nil {
		createdState = &policyOverride{
			PolicymanagerExternalPolicy: *created,
			PolicyProperties: &policyPropertiesOverride{
				PolicymanagerPolicyProperties: *created.PolicyProperties,
				EnableClipboardWebOrigin:      properties.EnableClipboardWebOrigin,
			},
		}
	}

	// Persist the ID before anything else can fail, so a failed follow-up update
	// still leaves a policy Terraform can refresh and destroy.
	plan.ID = flex.StringPointerToFramework(created.ID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// builtinHeader is Falcon's built-in justification header, which the create
	// response carries whether or not the create sent euj_header_text. It is what
	// lets the follow-up update apply a custom header without the provider
	// hardcoding the sentence.
	builtinHeader := ""
	if created.PolicyProperties != nil {
		builtinHeader = builtinHeaderText(created.PolicyProperties.EujHeaderText)
	}

	// A create response that carried no header structure leaves the sentence unknown,
	// which would make the update below omit euj_header_text and quietly leave the
	// built-in header in place. That is reported rather than attempted. The policy
	// exists and its ID is in state, so the next apply reads the sentence and
	// converges.
	if utils.IsKnown(plan.EujCustomHeaderText) && builtinHeader == "" {
		resp.Diagnostics.AddError(
			"Data protection policy created without its custom justification header",
			fmt.Sprintf(
				"Policy %s was created, but the create response did not carry euj_header_text, so the "+
					"built-in header text the API requires alongside a custom one could not be read. The "+
					"policy exists and uses Falcon's built-in justification header. Re-run terraform "+
					"apply to set the custom header.",
				plan.ID.ValueString(),
			),
		)
		return
	}

	// Three settings cannot be established by the POST alone.
	//
	// is_enabled and host_groups are absent from the POST model, so enabling a
	// policy or attaching host groups structurally requires a follow-up update.
	//
	// euj_custom_header_text could structurally be sent at create, because the POST
	// model does carry policy_properties, but the API validates
	// euj_header_text.headers[0] against a sentence the provider only learns from
	// this response. It is applied here rather than hardcoded, so a reworded
	// sentence needs no provider release. Without this the confirming read would
	// report no custom header while configuration asks for one, which Terraform
	// rejects as an inconsistent result.
	//
	// When none of the three applies, the POST alone already produced the desired
	// state and create stays a single call.
	if plan.Enabled.ValueBool() || !plan.HostGroups.IsNull() || utils.IsKnown(plan.EujCustomHeaderText) {
		patch, diags := buildPatch(ctx, policyWrite{plan: plan, builtinHeader: builtinHeader})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		if diags := r.patchPolicy(ctx, tferrors.Create, wirePlatform, patch); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			resp.Diagnostics.AddError(
				"Data protection policy created but not fully configured",
				fmt.Sprintf(
					"Policy %s was created successfully, but the follow-up update that enables it, "+
						"assigns its host groups, and applies its custom justification header failed. The "+
						"policy exists, is disabled, has no host groups, and uses Falcon's built-in "+
						"justification header. Re-run terraform apply to finish configuring it, or "+
						"terraform destroy to remove it.",
					plan.ID.ValueString(),
				),
			)
			if createdState != nil {
				resp.Diagnostics.Append(setState(ctx, &resp.State, &plan, *createdState)...)
			}
			return
		}
	}

	// State is written from a confirming read rather than from the write response,
	// which is not reliable for host_groups.
	policy, notFound, diags := r.readPolicy(ctx, tferrors.Create, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if notFound {
		resp.Diagnostics.AddError(
			"Data protection policy not found after creation",
			fmt.Sprintf(
				"Policy %s was created but could not be read back. Re-run terraform apply to reconcile.",
				plan.ID.ValueString(),
			),
		)
	}
	if resp.Diagnostics.HasError() {
		// The created policy is the best state available when the confirming read
		// fails, and it keeps the ID recoverable for a destroy.
		if createdState != nil {
			resp.Diagnostics.Append(setState(ctx, &resp.State, &plan, *createdState)...)
		}
		return
	}

	resp.Diagnostics.Append(setState(ctx, &resp.State, &plan, *policy)...)

	// The confirming read is the freshest sighting of the built-in justification
	// header, so it refreshes the cache the next update reads.
	resp.Diagnostics.Append(cacheBuiltinHeader(ctx, resp.Private, *policy)...)
}

func (r *dataProtectionPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, notFound, diags := r.readPolicy(ctx, tferrors.Read, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if notFound {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(setState(ctx, &resp.State, &state, *policy)...)

	// Refresh runs before every plan, so this is normally what keeps the built-in
	// justification header current for the next update. It is also what populates the
	// cache after an import, where private state starts empty.
	resp.Diagnostics.Append(cacheBuiltinHeader(ctx, resp.Private, *policy)...)
}

func (r *dataProtectionPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	wirePlatform, diagnostic := wirePlatformName(plan.PlatformName.ValueString())
	if diagnostic != nil {
		resp.Diagnostics.Append(diagnostic)
		return
	}

	tflog.Debug(ctx, "Updating data protection policy", map[string]any{
		"id": plan.ID.ValueString(),
	})

	// The update body has to reproduce Falcon's built-in justification header in
	// euj_header_text.headers[0] verbatim, whether the practitioner is setting,
	// changing, or removing a custom header. The refresh that precedes every plan
	// normally leaves it cached, so no read is needed here. An empty cache is
	// recovered with one, because omitting the field would preserve the remote value
	// instead of converging it.
	builtinHeader, diags := cachedBuiltinHeader(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if builtinHeader == "" {
		current, notFound, readDiags := r.readPolicy(ctx, tferrors.Update, plan.ID.ValueString())
		resp.Diagnostics.Append(readDiags...)
		if notFound {
			resp.Diagnostics.AddError(
				"Data protection policy not found before update",
				fmt.Sprintf(
					"Policy %s could not be read to recover the built-in justification header text the "+
						"API requires on every update. Re-run terraform apply to reconcile.",
					plan.ID.ValueString(),
				),
			)
		}
		if resp.Diagnostics.HasError() {
			return
		}

		if current.PolicyProperties != nil {
			builtinHeader = builtinHeaderText(current.PolicyProperties.EujHeaderText)
		}
	}

	// Proceeding without the sentence would omit euj_header_text, which the API reads
	// as "preserve", so a changed or removed custom header would silently not apply.
	// Terraform would then reject the result as inconsistent with the plan, which
	// reports the symptom rather than the cause. This says the cause.
	if builtinHeader == "" {
		resp.Diagnostics.AddError(
			"Unable to determine the built-in justification header text",
			fmt.Sprintf(
				"Updating policy %s requires the built-in header text the API demands in "+
					"euj_header_text.headers[0], and neither private state nor a fresh read of the policy "+
					"supplied it. Re-run terraform apply to reconcile.",
				plan.ID.ValueString(),
			),
		)
		return
	}

	patch, diags := buildPatch(ctx, policyWrite{plan: plan, builtinHeader: builtinHeader})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.patchPolicy(ctx, tferrors.Update, wirePlatform, patch)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// State is written from a confirming read rather than from the write response,
	// which is not reliable for host_groups.
	policy, notFound, diags := r.readPolicy(ctx, tferrors.Update, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if notFound {
		resp.Diagnostics.AddError(
			"Data protection policy not found after update",
			fmt.Sprintf(
				"Policy %s was updated but could not be read back. Re-run terraform apply to reconcile.",
				plan.ID.ValueString(),
			),
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(setState(ctx, &resp.State, &plan, *policy)...)

	// The confirming read is the freshest sighting of the built-in justification
	// header, so it refreshes the cache the next update reads.
	resp.Diagnostics.Append(cacheBuiltinHeader(ctx, resp.Private, *policy)...)
}

func (r *dataProtectionPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	policy, notFound, diags := r.readPolicy(ctx, tferrors.Delete, id)
	resp.Diagnostics.Append(diags...)
	if notFound {
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if policy.IsDefault != nil && *policy.IsDefault {
		resp.Diagnostics.AddWarning(
			"Tenant default Data Protection policy cannot be destroyed",
			fmt.Sprintf(
				"Falcon's tenant default Data Protection policy %s cannot be destroyed. Terraform will "+
					"remove it from state without deleting or modifying the policy in Falcon.",
				id,
			),
		)
		return
	}

	wirePlatform, diagnostic := wirePlatformName(state.PlatformName.ValueString())
	if diagnostic != nil {
		resp.Diagnostics.Append(diagnostic)
		return
	}

	disabledByDelete := false
	if policy.IsEnabled != nil && *policy.IsEnabled {
		stillPresent, diags := r.disablePolicy(ctx, wirePlatform, id)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		if !stillPresent {
			// The disable reported the policy as already gone.
			return
		}
		disabledByDelete = true
	}

	diags = r.deletePolicy(ctx, wirePlatform, id)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() && disabledByDelete {
		resp.Diagnostics.AddWarning(
			"Data protection policy disabled but not deleted",
			fmt.Sprintf(
				"Policy %s was disabled to satisfy the API's delete precondition, but the delete "+
					"itself failed, so the policy remains and is now inert. Re-run terraform destroy "+
					"to remove it.",
				id,
			),
		)
	}
}

func (r *dataProtectionPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	if !policyIDPattern.MatchString(req.ID) {
		resp.Diagnostics.AddError(
			"Invalid data protection policy import identifier",
			fmt.Sprintf(
				"Expected a 32-character hexadecimal policy ID, got %q. The ID is shown as the policy's "+
					"identifier in the Falcon console URL.",
				req.ID,
			),
		)
		return
	}

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ModifyPlan applies the defaults for the platform-scoped settings, which cannot use
// a schema Default. A Default is unconditional: it fires whenever configuration is
// null, with no access to platform_name, so on a Mac policy it would plan
// screen_capture = false and the provider would send it. Most of these fields answer
// `400 "<field> is not a field of Data Protection <platform> policy"` on the wrong
// platform, and Read reports every one of them as null there, so a defaulted value
// could never be confirmed either.
//
// The resource hook runs after TransformDefaults, MarkComputedNilsAsUnknown, and
// the attribute plan modifiers, so it sees the finished proposed plan and can
// replace whatever is there.
//
// The rule keys off configuration, never the plan value. On update an attribute
// that was never configured carries the prior state forward, which is a known value
// indistinguishable from a configured one; reading req.Config removes the ambiguity
// and makes this behave exactly like a schema Default would.
func (r *dataProtectionPolicyResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	// A destroy has no plan to modify.
	if req.Plan.Raw.IsNull() {
		return
	}

	var config dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// platform_name is unknown only when it comes from an unknown expression. The
	// attributes stay unknown and are resolved by the second ModifyPlan call during
	// apply, which the framework makes with the unknown values filled in.
	if config.PlatformName.IsUnknown() {
		return
	}

	platformName := config.PlatformName.ValueString()

	for _, setting := range platformScopedSettings {
		configValue := setting.get(config)

		// A configured value is left exactly as written, and an unknown one is left
		// for the apply-phase call.
		if !configValue.IsNull() {
			continue
		}

		value := setting.null
		if setting.platform == platformName {
			value = setting.value
		}

		resp.Diagnostics.Append(
			resp.Plan.SetAttribute(ctx, path.Root(setting.name), value)...,
		)
	}
}

func (r *dataProtectionPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config dataProtectionPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Value-dependency rules between settings both platforms carry. A null controller
	// is resolved to its schema default rather than skipped: every controller here has
	// a static default, so "the practitioner did not configure it" is a specific known
	// planned value, and skipping would let a real misconfiguration through. Unknown
	// values are passed through untouched so the shared validators skip them.
	contextInspection := boolOrDefault(config.ContextInspection, defaultContextInspection)
	contentInspection := boolOrDefault(config.ContentInspection, defaultContentInspection)
	similarityDetection := boolOrDefault(config.SimilarityDetection, defaultSimilarityDetection)

	resp.Diagnostics.Append(fwvalidators.BoolRequiresBool(
		config.SimilarityDetection, contextInspection,
		"similarity_detection", "context_inspection",
	)...)
	resp.Diagnostics.Append(fwvalidators.BoolRequiresBool(
		config.ClipboardWebOrigin, contextInspection,
		"clipboard_web_origin", "context_inspection",
	)...)
	resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
		config.MinimumSimilarityThreshold, similarityDetection,
		"minimum_similarity_threshold", "similarity_detection",
	)...)
	resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
		config.InspectionDepth, contentInspection,
		"inspection_depth", "content_inspection",
	)...)
	resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
		config.InspectionConfidence, contentInspection,
		"inspection_confidence", "content_inspection",
	)...)

	// The Windows-only dependency rules. Their controllers are resolved against the
	// value ModifyPlan plans on Windows, which is the resolution boolOrDefault performs
	// for an attribute with an unconditional Default.
	//
	// Every dependent in this group is Windows-only, so the whole group is skipped on
	// Mac: there validatePlatformScopedSettings already reports the real problem, and
	// a dependency diagnostic between two settings Mac cannot carry would only add
	// noise pointing at a rule that does not apply.
	if platformCarries(config.PlatformName, platformWindows) {
		browsersWithoutActiveExtension := stringOrDefault(
			config.BrowsersWithoutActiveExtension, defaultBrowsersWithoutActiveExtension,
		)
		evidenceStorage := boolOrDefault(config.EvidenceStorage, defaultEvidenceStorage)
		screenCapture := boolOrDefault(config.ScreenCapture, defaultScreenCapture)
		networkInspection := boolOrDefault(config.NetworkInspection, defaultNetworkInspection)

		// block_all_data_access only constrains the controlling enum when it is
		// actually switched on. Configuring it as false is what the default already
		// does and needs no particular controller, which is why this rule takes a
		// bool dependent rather than an any-configured-value one.
		resp.Diagnostics.Append(fwvalidators.BoolRequiresStringValue(
			config.BlockAllDataAccess, browsersWithoutActiveExtension,
			"block_all_data_access", "browsers_without_active_extension", "block_policy",
		)...)
		resp.Diagnostics.Append(fwvalidators.BoolRequiresBool(
			config.ScreenCapture, evidenceStorage,
			"screen_capture", "evidence_storage",
		)...)
		resp.Diagnostics.Append(fwvalidators.BoolRequiresBool(
			config.EndUserEncryptionActivity, evidenceStorage,
			"end_user_encryption_activity", "evidence_storage",
		)...)
		resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
			config.EvidenceStorageMaxSizeGiB, evidenceStorage,
			"evidence_storage_max_size_gib", "evidence_storage",
		)...)
		resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
			config.EvidenceStorageMaxFreeSpacePercent, evidenceStorage,
			"evidence_storage_max_free_space_percent", "evidence_storage",
		)...)
		resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
			config.ScreenCapturePreEventSeconds, screenCapture,
			"screen_capture_pre_event_seconds", "screen_capture",
		)...)
		resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
			config.ScreenCapturePostEventSeconds, screenCapture,
			"screen_capture_post_event_seconds", "screen_capture",
		)...)
		resp.Diagnostics.Append(fwvalidators.AttributeRequiresBool(
			config.NetworkInspectionFilesExceedingSizeLimit, networkInspection,
			"network_inspection_files_exceeding_size_limit", "network_inspection",
		)...)
	}

	// The one Mac-only dependency rule, skipped on Windows for the same reason. Its
	// controller is a setting both platforms carry, so only the dependent is gated.
	if platformCarries(config.PlatformName, platformMac) {
		resp.Diagnostics.Append(fwvalidators.BoolRequiresBool(
			config.EnableOCR, contentInspection,
			"enable_ocr", "content_inspection",
		)...)
	}

	resp.Diagnostics.Append(validatePlatformScopedSettings(config)...)
	resp.Diagnostics.Append(validateEujEnabledOptions(config)...)
	resp.Diagnostics.Append(validateMaxFileSizeBytes(config.MaxFileSize, config.MaxFileSizeUnit)...)
}

// platformCarries reports whether the platform selected in configuration can carry
// the settings scoped to platform. An unknown platform_name carries everything:
// validatePlatformScopedSettings skips on an unknown platform too, so a dependency
// rule cannot contradict a platform diagnostic there, and skipping the rule would
// drop a real violation instead.
func platformCarries(platformName types.String, platform string) bool {
	return !utils.IsKnown(platformName) || platformName.ValueString() == platform
}

// validatePlatformScopedSettings rejects a setting configured on a platform that does
// not have it. Most of them the API refuses outright, and without this the
// practitioner sees its
// `400 "<field> is not a field of Data Protection <platform> policy"` at apply time,
// naming the wire field rather than the attribute. browsers_without_active_extension
// and block_all_data_access are the two the API accepts on Mac and then ignores,
// because the Mac sensor has no unsupported-browser enforcement at all; letting them
// be configured there would write a setting that silently does nothing.
func validatePlatformScopedSettings(config dataProtectionPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	if !utils.IsKnown(config.PlatformName) {
		return diags
	}

	platformName := config.PlatformName.ValueString()

	for _, setting := range platformScopedSettings {
		if setting.platform == platformName {
			continue
		}

		configValue := setting.get(config)
		if !utils.IsKnown(configValue) {
			continue
		}

		diags.AddAttributeError(
			path.Root(setting.name),
			fmt.Sprintf("%s is not supported on %s policies", setting.name, platformName),
			fmt.Sprintf(
				"%s only applies to %s policies and cannot be configured on a %s policy. Remove it "+
					"from this resource, or set platform_name to %q.",
				setting.name, setting.platform, platformName, setting.platform,
			),
		)
	}

	return diags
}

// validateEujEnabledOptions enforces the API's minimum of two *selected*
// justification options, probed directly: an array with fewer returns
// `400 "euj_dropdown_options check failed: there should be at least 2 selected
// justifications"`. The array length is not what is bounded, so two built-ins with
// one of them deselected is rejected even though the array holds two entries.
//
// The schema already makes wrong built-in text, a wrong built-in order, a third
// default entry, more than four entries, and an empty array unrepresentable, so this
// is the only one of the API's justification rules a practitioner can still violate.
//
// A null bool resolves to its default, true, so it counts as enabled. The whole rule
// is skipped when any of the three inputs is unknown, because the count cannot be
// computed.
func validateEujEnabledOptions(config dataProtectionPolicyResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	if config.EujBusinessPurposesEnabled.IsUnknown() ||
		config.EujPersonalUseEnabled.IsUnknown() ||
		config.EujCustomDropdownOptions.IsUnknown() {
		return diags
	}

	enabled := len(config.EujCustomDropdownOptions.Elements())
	if boolOrDefault(config.EujBusinessPurposesEnabled, defaultEujBuiltinOptionEnabled).ValueBool() {
		enabled++
	}
	if boolOrDefault(config.EujPersonalUseEnabled, defaultEujBuiltinOptionEnabled).ValueBool() {
		enabled++
	}

	if enabled >= eujMinimumEnabledOptions {
		return diags
	}

	diags.AddAttributeError(
		path.Root("euj_custom_dropdown_options"),
		"At least two end user justification options must be enabled",
		fmt.Sprintf(
			"The end user justification dialog offers %d option(s), but Falcon requires at least %d. "+
				"Enable euj_business_purposes_enabled or euj_personal_use_enabled, or add entries to "+
				"euj_custom_dropdown_options.",
			enabled, eujMinimumEnabledOptions,
		),
	)

	return diags
}

// boolOrDefault resolves a null controlling bool to its schema default so a
// dependency rule evaluates the value the plan will actually carry. An unknown
// value is returned untouched, which makes the shared validators skip it.
func boolOrDefault(value types.Bool, defaultValue bool) types.Bool {
	if value.IsNull() {
		return types.BoolValue(defaultValue)
	}

	return value
}

// stringOrDefault is the string counterpart of boolOrDefault.
func stringOrDefault(value types.String, defaultValue string) types.String {
	if value.IsNull() {
		return types.StringValue(defaultValue)
	}

	return value
}

// validateMaxFileSizeBytes enforces Falcon's second, unit-aware bound on
// max_file_size. The schema validator covers stage 1, which bounds the raw number
// to [512, 524288000] whatever the unit is. Stage 2 multiplies the number by the
// unit factor and rejects a total above 524288000 bytes, but it reports that as an
// internal server error rather than a validation message
// ("field 'MaxFileSizeToInspect': conflicting values 5.25E+8 and bool"), so it has
// to be caught at plan time.
//
// An unknown value on either attribute skips the check; it is re-evaluated at
// apply. A null on either resolves to its static default, which passes.
func validateMaxFileSizeBytes(size types.Float64, unit types.String) diag.Diagnostics {
	var diags diag.Diagnostics

	if size.IsUnknown() || unit.IsUnknown() {
		return diags
	}

	sizeValue := float64(maxFileSizeDefaultBytes)
	if !size.IsNull() {
		sizeValue = size.ValueFloat64()
	}

	unitValue := maxFileSizeUnitBytes
	if !unit.IsNull() {
		unitValue = unit.ValueString()
	}

	factor, ok := maxFileSizeUnitFactors[unitValue]
	if !ok {
		// An unmapped unit is already rejected by the attribute's OneOf validator,
		// so there is nothing to add here.
		return diags
	}

	totalBytes := sizeValue * factor
	if totalBytes <= maxFileSizeMaxBytes {
		return diags
	}

	diags.AddAttributeError(
		path.Root("max_file_size"),
		"max_file_size is larger than Falcon can inspect",
		fmt.Sprintf(
			"max_file_size %s with max_file_size_unit %q is %s bytes, above the maximum of %d bytes "+
				"(500 MiB). Lower max_file_size or choose a smaller unit; Bytes is the only unit whose "+
				"accepted range spans every valid size.",
			formatFileSize(sizeValue), unitValue, formatFileSize(totalBytes), maxFileSizeMaxBytes,
		),
	)

	return diags
}

// formatFileSize renders a file size the way the practitioner wrote it, without
// exponent notation.
func formatFileSize(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// float64OrNull flattens a platform-scoped float. gofalcon models these as value
// types, so a field the response omits arrives as 0. Every one of them has a lower
// bound above 0, which makes 0 unambiguously "absent" rather than a real value, and
// null is what the attribute plans to on the platform that does not carry it.
func float64OrNull(value float64) types.Float64 {
	if value == 0 {
		return types.Float64Null()
	}

	return types.Float64Value(value)
}

// policyWrite is everything a write body is built from: the planned configuration,
// plus Falcon's built-in justification header, which the API demands verbatim in
// euj_header_text.headers[0] and which is read from a previous API response rather
// than hardcoded. See expandEujHeaderText for what an empty builtinHeader means.
type policyWrite struct {
	plan          dataProtectionPolicyResourceModel
	builtinHeader string
}

// expandPolicyProperties assembles every setting the resource manages. Each one
// carries a static default, so every plan value is known at write time and the
// whole set is sent on both create and update; the API's merge therefore never
// applies to a managed field and there is no conditional omission.
//
// euj_header_text is the one exception: it is omitted when the built-in sentence is
// not yet known, which happens only on the create POST.
//
// max_file_size and max_file_size_unit are sent verbatim. The API echoes both
// unchanged, so normalizing or recomputing either would create a permanent diff.
func expandPolicyProperties(
	ctx context.Context,
	write policyWrite,
	diags *diag.Diagnostics,
) *policyPropertiesOverride {
	plan := write.plan

	properties := &policyPropertiesOverride{
		PolicymanagerPolicyProperties: models.PolicymanagerPolicyProperties{
			// classifications is always sent as a non-nil slice because Terraform
			// owns the membership: the API preserves a collection sent as null and
			// only clears it when sent as an empty array, and flex.ExpandSetAs
			// yields a non-nil empty slice for a null or unknown set.
			Classifications: flex.ExpandSetAs[string](ctx, plan.Classifications, diags),

			EnableContextInspection:   plan.ContextInspection.ValueBoolPointer(),
			EnableContentInspection:   plan.ContentInspection.ValueBoolPointer(),
			EnableClipboardInspection: plan.ClipboardInspection.ValueBoolPointer(),
			SimilarityDetection:       plan.SimilarityDetection.ValueBoolPointer(),
			SimilarityThreshold:       plan.MinimumSimilarityThreshold.ValueString(),
			InspectionDepth:           plan.InspectionDepth.ValueString(),
			MinConfidenceLevel:        plan.InspectionConfidence.ValueString(),
			MaxFileSizeToInspect:      plan.MaxFileSize.ValueFloat64(),
			MaxFileSizeToInspectUnit:  plan.MaxFileSizeUnit.ValueString(),

			BeSplashEnabled:                        plan.BeSplashScreen.ValueBoolPointer(),
			BeUploadTimeoutDurationSeconds:         plan.BeUploadTimeoutSeconds.ValueInt32(),
			BeUploadTimeoutResponse:                plan.BeUploadTimeoutResponse.ValueString(),
			BePasteTimeoutDurationMilliseconds:     plan.BePasteTimeoutMilliseconds.ValueInt32(),
			BePasteTimeoutResponse:                 plan.BePasteTimeoutResponse.ValueString(),
			BePasteClipboardMinSize:                plan.BePasteClipboardMinSize.ValueFloat64(),
			BePasteClipboardMinSizeUnit:            plan.BePasteClipboardMinSizeUnit.ValueString(),
			BePasteClipboardMaxSize:                plan.BePasteClipboardMaxSize.ValueFloat64(),
			BePasteClipboardMaxSizeUnit:            plan.BePasteClipboardMaxSizeUnit.ValueString(),
			BePasteClipboardOverSizeBehaviourBlock: plan.BePasteClipboardBlockOverMaxSize.ValueBoolPointer(),

			EujRequireAdditionalDetails: plan.EujRequireAdditionalDetails.ValueBoolPointer(),
			EujDialogTimeout:            plan.EujDialogTimeout.ValueInt32(),

			// The three message-source enums and euj_header_text are derived from
			// other attributes rather than mirroring a wire field, so the provider
			// states them explicitly on every write instead of relying on a server
			// default or on the API's merge.
			BeSplashMessageSource: messageSource(plan.BeCustomSplashMessage),
			AllowNotifications:    messageSource(plan.CustomAllowedActionNotification),
			BlockNotifications:    messageSource(plan.CustomBlockedActionNotification),
			EujHeaderText:         expandEujHeaderText(plan.EujCustomHeaderText, write.builtinHeader),

			// Each message text is sent only when it is configured, which the
			// generated omitempty handles. Reverting to Falcon's built-in text is the
			// job of the source enum above, not of an empty text: the API rejects ""
			// on the two notification fields outright, with
			// `length must be at least 2 and at max 256`.
			BeSplashCustomMessage:   plan.BeCustomSplashMessage.ValueString(),
			CustomAllowNotification: plan.CustomAllowedActionNotification.ValueString(),
			CustomBlockNotification: plan.CustomBlockedActionNotification.ValueString(),
		},

		// gofalcon does not model this field, so it only reaches the wire
		// through the override.
		EnableClipboardWebOrigin: plan.ClipboardWebOrigin.ValueBoolPointer(),

		// Each is sent on every write, as "" when the attribute is null,
		// so removing the attribute from configuration actually clears the remote
		// value. Neither has a companion source enum, so the empty string is the
		// only way to clear it, and the generated omitempty would drop it.
		BeExcludeDomains: expandExcludeDomains(ctx, plan.BeExcludeDomains, diags),
		EujDialogBoxLogo: plan.EujCompanyLogo.ValueString(),

		// The whole justification array is reconstructed on every write. Three
		// Terraform attributes share this one wire field, so expanding them one at
		// a time would drop the others, and omitting the field would preserve the
		// remote value, which would make a removal silently no-op.
		EujDropdownOptions: expandEujDropdownOptions(ctx, plan, diags),
	}

	expandPlatformScopedSettings(plan, properties)

	return properties
}

// expandPlatformScopedSettings fills in the settings that exist on only one platform.
// A field belonging to the other platform is left at its zero value so `omitempty`
// drops it: most of them answer
// `400 "<field> is not a field of Data Protection <platform> policy"`, and the two
// unsupported-browser fields would be stored on a Mac policy where the sensor ignores
// them, which Read then has to hide again.
//
// The plan value is null on the platform that does not carry the field, which
// ModifyPlan guarantees, so testing the value rather than the platform would work
// too. The platform is tested instead because it states the rule directly.
func expandPlatformScopedSettings(
	plan dataProtectionPolicyResourceModel,
	properties *policyPropertiesOverride,
) {
	switch plan.PlatformName.ValueString() {
	case platformWindows:
		properties.BrowsersWithoutActiveExtension = plan.BrowsersWithoutActiveExtension.ValueString()
		properties.BlockAllDataAccess = plan.BlockAllDataAccess.ValueBoolPointer()
		properties.EnableScreenCapture = plan.ScreenCapture.ValueBoolPointer()
		properties.ScreenCaptureDurationPreEvent = plan.ScreenCapturePreEventSeconds.ValueString()
		properties.ScreenCaptureDurationPostEvent = plan.ScreenCapturePostEventSeconds.ValueString()
		properties.EvidenceDownloadEnabled = plan.EvidenceStorage.ValueBoolPointer()
		properties.EvidenceEncryptedEnabled = plan.EndUserEncryptionActivity.ValueBoolPointer()
		properties.EvidenceStorageFreeDiskPerc = plan.EvidenceStorageMaxFreeSpacePercent.ValueFloat64()
		properties.EvidenceStorageMaxSize = plan.EvidenceStorageMaxSizeGiB.ValueFloat64()
		properties.EnableNetworkInspection = plan.NetworkInspection.ValueBoolPointer()
		properties.NetworkInspectionFilesExceedingSizeLimit = plan.NetworkInspectionFilesExceedingSizeLimit.ValueString()
	case platformMac:
		properties.EnableOCR = plan.EnableOCR.ValueBoolPointer()
	}
}

// messageSource derives the wire source enum for one collapsed custom-message
// pair. Configuring the text *is* the choice of custom messaging, because the
// built-in text of each is fixed by Falcon and cannot be edited, so the radio the
// console shows adds no expressive power over the text box.
func messageSource(text types.String) string {
	if utils.IsKnown(text) {
		return messageSourceCustom
	}

	return messageSourceDefault
}

// flattenCustomMessage reduces one wire source-and-text pair back to the single
// exposed attribute. Anything other than `custom` with non-empty text reads back as
// null, which absorbs the one remote shape the schema cannot express, `custom` with
// an empty text. Reporting that as null means Read never invents a value, and the
// next apply converges the remote to `default`.
func flattenCustomMessage(source, text string) types.String {
	if source == messageSourceCustom && text != "" {
		return types.StringValue(text)
	}

	return types.StringNull()
}

// expandExcludeDomains joins the tag set into the single comma-separated string the
// API stores. A null set becomes "", which clears the remote list and needs the
// be_exclude_domains override. Elements are sorted so the wire value is a
// deterministic function of the set, which has no order of its own.
func expandExcludeDomains(
	ctx context.Context,
	domains types.Set,
	diags *diag.Diagnostics,
) string {
	elements := flex.ExpandSetAs[string](ctx, domains, diags)
	slices.Sort(elements)

	return strings.Join(elements, excludeDomainsSeparator)
}

// flattenExcludeDomains splits the wire string back into the tag set. An empty wire
// value reads back as a null set, not an empty one, because null is the canonical
// state for an unset collection here.
func flattenExcludeDomains(ctx context.Context, domains string) (types.Set, diag.Diagnostics) {
	if domains == "" {
		return flex.FlattenStringValueSet(ctx, nil)
	}

	return flex.FlattenStringValueSet(ctx, strings.Split(domains, excludeDomainsSeparator))
}

// expandEujHeaderText synthesizes the fixed two-element header structure from the
// single exposed attribute. Slot 0 always carries Falcon's built-in sentence, which
// the API demands verbatim and rejects any substitute for; slot 1 carries the custom
// text. Exactly one of the two is selected, and that selection is the attribute's
// only degree of freedom.
//
// builtinHeader comes from a previous API response, never from a constant, so that a
// reworded sentence needs no provider release. An empty builtinHeader means the
// caller has not seen the policy yet and returns nil, which omits the field: the API
// then fills in the built-in itself and selects it. That is correct only on create.
// A patch that omits the field silently preserves the remote value instead of
// converging it, so an update must supply the sentence rather than accept the
// omission.
func expandEujHeaderText(
	customHeader types.String,
	builtinHeader string,
) *models.PolicymanagerEUJHeaderText {
	if builtinHeader == "" {
		return nil
	}

	custom := utils.IsKnown(customHeader)

	return &models.PolicymanagerEUJHeaderText{
		Headers: []*models.PolicymanagerEUJHeader{
			{
				Header:   utils.Addr(builtinHeader),
				Default:  utils.Addr(true),
				Selected: utils.Addr(!custom),
			},
			{
				Header:   utils.Addr(customHeader.ValueString()),
				Default:  utils.Addr(false),
				Selected: utils.Addr(custom),
			},
		},
	}
}

// builtinHeaderText reads Falcon's built-in justification header out of a policy
// response. Every response that carries a policy carries it in headers[0], including
// the response to a create that sent no euj_header_text at all, which is what lets
// the provider source the sentence instead of hardcoding it.
//
// An empty return means the response did not carry the structure. Callers treat that
// as "not known yet" rather than as a value.
func builtinHeaderText(headerText *models.PolicymanagerEUJHeaderText) string {
	if headerText == nil || len(headerText.Headers) == 0 {
		return ""
	}

	builtin := headerText.Headers[0]
	if builtin == nil || builtin.Header == nil {
		return ""
	}

	return *builtin.Header
}

// flattenEujHeaderText reduces the wire structure back to the single attribute. The
// custom slot counts only when it is selected and non-empty; the degenerate
// selected-but-empty state reads back as null and the next apply converges it to
// the built-in header.
func flattenEujHeaderText(headerText *models.PolicymanagerEUJHeaderText) types.String {
	if headerText == nil || len(headerText.Headers) < 2 {
		return types.StringNull()
	}

	custom := headerText.Headers[1]
	if custom == nil || custom.Selected == nil || !*custom.Selected || custom.Header == nil {
		return types.StringNull()
	}

	return flex.StringPointerToFramework(custom.Header)
}

// expandEujDropdownOptions rebuilds the whole justification array from the three
// attributes that share it. The two built-in entries come first, in the order and
// with the exact text the API demands, each carrying default:true and an id equal
// to its own justification. Custom entries follow with default:false, selected:true,
// and no id key at all.
//
// `selected` is always emitted explicitly, because omitting it reads as false. The
// array is never sent empty: the API rejects that, and "no custom options" is the
// two-element built-in array.
func expandEujDropdownOptions(
	ctx context.Context,
	plan dataProtectionPolicyResourceModel,
	diags *diag.Diagnostics,
) *eujDropdownOptionsOverride {
	justifications := []*eujOptionOverride{
		{
			Justification: utils.Addr(eujMandatoryBusinessPurposes),
			ID:            utils.Addr(eujMandatoryBusinessPurposes),
			Default:       utils.Addr(true),
			Selected:      plan.EujBusinessPurposesEnabled.ValueBoolPointer(),
		},
		{
			Justification: utils.Addr(eujMandatoryPersonalUse),
			ID:            utils.Addr(eujMandatoryPersonalUse),
			Default:       utils.Addr(true),
			Selected:      plan.EujPersonalUseEnabled.ValueBoolPointer(),
		},
	}

	// flex.ExpandListAs returns an empty slice for a null or unknown list, so no
	// null guard is needed.
	for _, option := range flex.ExpandListAs[string](ctx, plan.EujCustomDropdownOptions, diags) {
		justifications = append(justifications, &eujOptionOverride{
			Justification: utils.Addr(option),
			Default:       utils.Addr(false),
			Selected:      utils.Addr(true),
		})
	}

	return &eujDropdownOptionsOverride{Justifications: justifications}
}

// flattenEujDropdownOptions splits the wire array back into the three attributes.
// Entry 0 and entry 1 contribute their `selected` flag; every later entry becomes a
// custom option, with `id` discarded.
//
// A custom entry the console wrote with selected:false is reported as present
// rather than dropped. Dropping it would make the next apply delete a
// console-configured row without that deletion ever appearing in a plan; reporting
// it means any removal is an explicit diff the practitioner approves.
func flattenEujDropdownOptions(
	ctx context.Context,
	options *eujDropdownOptionsOverride,
) (businessPurposes, personalUse types.Bool, custom types.List, diags diag.Diagnostics) {
	if options == nil {
		custom, diags = flex.FlattenStringValueList(ctx, nil)
		return types.BoolNull(), types.BoolNull(), custom, diags
	}

	selectedAt := func(index int) types.Bool {
		if index >= len(options.Justifications) {
			return types.BoolNull()
		}
		if option := options.Justifications[index]; option != nil {
			return types.BoolPointerValue(option.Selected)
		}
		return types.BoolNull()
	}

	var customOptions []string
	for _, option := range options.Justifications[min(len(options.Justifications), 2):] {
		if option == nil || option.Justification == nil {
			continue
		}
		customOptions = append(customOptions, *option.Justification)
	}

	custom, diags = flex.FlattenStringValueList(ctx, customOptions)

	return selectedAt(0), selectedAt(1), custom, diags
}

// buildPatch assembles the update body from the planned values. Everything the
// resource manages is sent on every update, so the API's merge semantics never
// come into play for a managed field.
//
// host_groups is always sent as a non-nil slice. The API preserves a collection
// sent as null and only clears it when sent as an empty array, so a null set has
// to reach the wire as [] for Terraform to own the membership.
//
// The embedded generated patch is populated in full and the outer fields shadow
// only what gofalcon gets wrong, so the corrected body and the generated one stay
// in step.
func buildPatch(
	ctx context.Context,
	write policyWrite,
) (*policyPatchOverride, diag.Diagnostics) {
	var diags diag.Diagnostics

	plan := write.plan
	properties := expandPolicyProperties(ctx, write, &diags)

	patch := &policyPatchOverride{
		PolicymanagerExternalPolicyPatch: models.PolicymanagerExternalPolicyPatch{
			ID:               plan.ID.ValueStringPointer(),
			IsEnabled:        plan.Enabled.ValueBoolPointer(),
			Name:             plan.Name.ValueString(),
			Description:      plan.Description.ValueString(),
			HostGroups:       flex.ExpandSetAs[string](ctx, plan.HostGroups, &diags),
			PolicyProperties: &properties.PolicymanagerPolicyProperties,
		},
		Description:      plan.Description.ValueString(),
		PolicyProperties: properties,
	}

	return patch, diags
}

// policyWriteAttempts bounds how many times one PATCH or DELETE call is attempted.
// Falcon can report transient write contention as a 500, so these idempotent
// writes are retried a small number of times. The create POST deliberately does
// not use this helper because retrying it can create a duplicate policy.
const policyWriteAttempts = 3

// policyWriteBackoff is the pause before the second attempt, grown linearly for
// each one after it. A var rather than a const so unit tests need not sleep.
var policyWriteBackoff = time.Second

// retryPolicyWrite retries a PATCH or DELETE only when Falcon returns a server
// error. Successful responses and non-server errors are returned immediately.
func retryPolicyWrite[T any](
	ctx context.Context,
	description string,
	write func() (T, error),
) (T, error) {
	var zero T

	for attempt := 1; attempt <= policyWriteAttempts; attempt++ {
		result, err := write()
		if err == nil || !tferrors.IsServerError(err) || attempt == policyWriteAttempts {
			return result, err
		}

		if ctx.Err() != nil {
			return zero, err
		}

		tflog.Warn(ctx, "Data protection policy write returned a server error, retrying", map[string]any{
			"write":              description,
			"attempt":            attempt,
			"attempts_permitted": policyWriteAttempts,
		})

		select {
		case <-ctx.Done():
			return zero, err
		case <-time.After(time.Duration(attempt) * policyWriteBackoff):
		}
	}

	return zero, nil
}

// patchPolicy issues an update. All policy PATCH calls retry transient server
// errors; this covers both follow-up patches during Create and normal Update.
func (r *dataProtectionPolicyResource) patchPolicy(
	ctx context.Context,
	operation tferrors.Operation,
	wirePlatform string,
	patch *policyPatchOverride,
) diag.Diagnostics {
	var diags diag.Diagnostics

	body := &models.PolicymanagerUpdatePoliciesRequest{
		Resources: []*models.PolicymanagerExternalPolicyPatch{
			&patch.PolicymanagerExternalPolicyPatch,
		},
	}

	params := data_protection_configuration.NewEntitiesPolicyPatchV2Params().
		WithContext(ctx).
		WithPlatformName(wirePlatform).
		WithBody(body)

	res, err := retryPolicyWrite(ctx, "update", func() (*data_protection_configuration.EntitiesPolicyPatchV2OK, error) {
		return r.client.DataProtectionConfiguration.EntitiesPolicyPatchV2(
			params,
			withPolicyPatchOverride(&policyUpdateRequestOverride{
				Resources: []*policyPatchOverride{patch},
			}),
		)
	})
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(operation, err, policyResourceRequiredScopes))
		return diags
	}

	if res == nil || res.Payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return diags
	}

	if diagnostic := policyPayloadDiagnostic(operation, res.Payload.Errors); diagnostic != nil {
		diags.Append(diagnostic)
		return diags
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
	}

	return diags
}

// disablePolicy satisfies the API's delete precondition. It reports whether the
// policy is still present, so a policy the API says is already gone makes destroy
// a no-op success. The disable PATCH retries transient server errors.
func (r *dataProtectionPolicyResource) disablePolicy(
	ctx context.Context,
	wirePlatform string,
	id string,
) (stillPresent bool, diags diag.Diagnostics) {
	body := &models.PolicymanagerUpdatePoliciesRequest{
		Resources: []*models.PolicymanagerExternalPolicyPatch{
			{ID: &id, IsEnabled: utils.Addr(false)},
		},
	}

	params := data_protection_configuration.NewEntitiesPolicyPatchV2Params().
		WithContext(ctx).
		WithPlatformName(wirePlatform).
		WithBody(body)

	tflog.Debug(ctx, "Disabling data protection policy before delete", map[string]any{"id": id})

	res, err := retryPolicyWrite(ctx, "disable", func() (*data_protection_configuration.EntitiesPolicyPatchV2OK, error) {
		return r.client.DataProtectionConfiguration.EntitiesPolicyPatchV2(params)
	})
	if err != nil {
		diagnostic := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			policyResourceRequiredScopes,
		)
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return false, diags
		}
		diags.Append(diagnostic)
		return false, diags
	}

	if res == nil || res.Payload == nil {
		return true, diags
	}

	if diagnostic := policyPayloadDiagnostic(tferrors.Delete, res.Payload.Errors); diagnostic != nil {
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return false, diags
		}
		diags.Append(diagnostic)
		return false, diags
	}

	return true, diags
}

// deletePolicy deletes the policy, retrying transient server errors. Not-found is
// success because the desired state has already been reached.
func (r *dataProtectionPolicyResource) deletePolicy(
	ctx context.Context,
	wirePlatform string,
	id string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	params := data_protection_configuration.NewEntitiesPolicyDeleteV2Params().
		WithContext(ctx).
		WithPlatformName(wirePlatform).
		WithIds([]string{id})

	tflog.Debug(ctx, "Deleting data protection policy", map[string]any{"id": id})

	res, err := retryPolicyWrite(ctx, "delete", func() (*data_protection_configuration.EntitiesPolicyDeleteV2OK, error) {
		return r.client.DataProtectionConfiguration.EntitiesPolicyDeleteV2(params)
	})
	if err != nil {
		diagnostic := tferrors.NewDiagnosticFromAPIError(
			tferrors.Delete,
			err,
			policyResourceRequiredScopes,
		)
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return diags
		}
		diags.Append(diagnostic)
		return diags
	}

	if res == nil || res.Payload == nil {
		return diags
	}

	if diagnostic := policyPayloadDiagnostic(tferrors.Delete, res.Payload.Errors); diagnostic != nil {
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return diags
		}
		diags.Append(diagnostic)
	}

	return diags
}

// readPolicy fetches one policy. It reports notFound for a confirmed absence,
// which Read turns into state removal and the write paths treat as an error.
//
// This is also the confirming read the write paths issue after a successful
// write. The patch response body cannot be trusted on its own: when a host group
// is deleted while still attached, the API detaches it but the patch response
// keeps echoing the deleted IDs, while this read correctly reports the policy's
// real membership.
//
// The response reader is overridden so the settings gofalcon does not model are
// decoded too. The generated response carries only the embedded model, so the
// resources are collected from the reader rather than from res.Payload.
func (r *dataProtectionPolicyResource) readPolicy(
	ctx context.Context,
	operation tferrors.Operation,
	id string,
) (policy *policyOverride, notFound bool, diags diag.Diagnostics) {
	params := data_protection_configuration.NewEntitiesPolicyGetV2Params().
		WithContext(ctx).
		WithIds([]string{id})

	reader, option := withPolicyGetOverride()

	res, err := r.client.DataProtectionConfiguration.EntitiesPolicyGetV2(params, option)
	if err != nil {
		diagnostic := tferrors.NewDiagnosticFromAPIError(operation, err, policyResourceRequiredScopes)
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return nil, true, diags
		}
		diags.Append(diagnostic)
		return nil, false, diags
	}

	if res == nil || res.Payload == nil || reader.extended == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, false, diags
	}

	// A deleted policy is reported as HTTP 200 with a payload error carrying code
	// 404, so the payload has to be classified before anything is flattened.
	if diagnostic := policyPayloadDiagnostic(operation, res.Payload.Errors); diagnostic != nil {
		if diagnostic.Summary() == tferrors.NotFoundErrorSummary {
			return nil, true, diags
		}
		diags.Append(diagnostic)
		return nil, false, diags
	}

	if len(reader.extended.Resources) == 0 || reader.extended.Resources[0] == nil {
		return nil, true, diags
	}

	return reader.extended.Resources[0], false, diags
}

// privateStateReader and privateStateWriter narrow the framework's private state to
// the two methods the resource needs. The concrete type behind resp.Private lives in
// the framework's internal tree and cannot be named here, so it is reached
// structurally.
type privateStateReader interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

type privateStateWriter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

// cacheBuiltinHeader records the built-in justification header carried by a policy
// response, so the next update can reproduce it in euj_header_text.headers[0]
// without an extra read. A response that carried no header structure caches nothing
// rather than caching an empty string, which keeps "not known" distinguishable from
// "known to be empty".
func cacheBuiltinHeader(
	ctx context.Context,
	private privateStateWriter,
	policy policyOverride,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if policy.PolicyProperties == nil {
		return diags
	}

	header := builtinHeaderText(policy.PolicyProperties.EujHeaderText)
	if header == "" {
		return diags
	}

	encoded, err := json.Marshal(header)
	if err != nil {
		diags.AddError(
			"Unable to cache the built-in justification header",
			fmt.Sprintf("Encoding %q for private state failed: %s", header, err),
		)
		return diags
	}

	diags.Append(private.SetKey(ctx, eujBuiltinHeaderKey, encoded)...)

	return diags
}

// cachedBuiltinHeader recovers the built-in justification header from private state.
// An empty return means no entry, which the caller resolves with an API read rather
// than by omitting the field: a patch that omits euj_header_text preserves the remote
// value instead of converging it.
func cachedBuiltinHeader(
	ctx context.Context,
	private privateStateReader,
) (string, diag.Diagnostics) {
	encoded, diags := private.GetKey(ctx, eujBuiltinHeaderKey)
	if diags.HasError() || len(encoded) == 0 {
		return "", diags
	}

	var header string
	if err := json.Unmarshal(encoded, &header); err != nil {
		diags.AddError(
			"Unable to read the built-in justification header from private state",
			fmt.Sprintf(
				"Decoding the cached value failed: %s. Re-run terraform apply to rebuild it.",
				err,
			),
		)
		return "", diags
	}

	return header, diags
}

// setState flattens an API response into the model and writes it to state.
func setState(
	ctx context.Context,
	state *tfsdk.State,
	model *dataProtectionPolicyResourceModel,
	policy policyOverride,
) diag.Diagnostics {
	diags := model.wrap(ctx, policy)
	if diags.HasError() {
		return diags
	}

	diags.Append(state.Set(ctx, model)...)

	return diags
}

// wrap converts the API model to the Terraform model. It returns diagnostics
// because platform_name arrives in its wire form and an unmapped value is a
// defect to report rather than a value to store.
func (m *dataProtectionPolicyResourceModel) wrap(
	ctx context.Context,
	policy policyOverride,
) diag.Diagnostics {
	var diags diag.Diagnostics

	// platform_name is resolved first because two of the platform-scoped settings can
	// only be flattened correctly once the platform is known.
	if policy.PlatformName == nil {
		diags.AddError(
			"Unexpected data protection policy response",
			"The API returned a policy with no platform_name. "+
				"Please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
		return diags
	}

	platformName, diagnostic := schemaPlatformName(*policy.PlatformName)
	if diagnostic != nil {
		diags.Append(diagnostic)
		return diags
	}
	m.PlatformName = types.StringValue(platformName)

	m.ID = flex.StringPointerToFramework(policy.ID)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.Enabled = types.BoolPointerValue(policy.IsEnabled)

	m.CID = flex.StringPointerToFramework(policy.Cid)
	m.CreatedAt = flex.StringPointerToFramework(policy.CreatedAt)
	m.CreatedBy = flex.StringPointerToFramework(policy.CreatedBy)

	// The API answers an empty host_groups with null and an empty classifications
	// with [], and flex canonicalizes both to a null set.
	hostGroups, hostGroupDiags := flex.FlattenStringValueSet(ctx, policy.HostGroups)
	diags.Append(hostGroupDiags...)
	m.HostGroups = hostGroups

	if policy.PolicyProperties == nil {
		diags.AddError(
			"Unexpected data protection policy response",
			"The API returned a policy with no policy_properties, so none of the policy's settings "+
				"could be read. "+
				"Please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
		return diags
	}
	properties := policy.PolicyProperties

	classifications, classificationDiags := flex.FlattenStringValueSet(ctx, properties.Classifications)
	diags.Append(classificationDiags...)
	m.Classifications = classifications

	// The settings map straight across. The enum strings deliberately do not go
	// through flex.StringValueToFramework, which maps "" to null: an empty value is
	// not a canonicalization for a defaulted setting, so hiding it would turn an API
	// defect into a confusing null.
	m.ContextInspection = types.BoolPointerValue(properties.EnableContextInspection)
	m.ContentInspection = types.BoolPointerValue(properties.EnableContentInspection)
	m.ClipboardInspection = types.BoolPointerValue(properties.EnableClipboardInspection)
	m.ClipboardWebOrigin = types.BoolPointerValue(properties.EnableClipboardWebOrigin)
	m.SimilarityDetection = types.BoolPointerValue(properties.SimilarityDetection)
	m.MinimumSimilarityThreshold = types.StringValue(properties.SimilarityThreshold)
	m.InspectionDepth = types.StringValue(properties.InspectionDepth)
	m.InspectionConfidence = types.StringValue(properties.MinConfidenceLevel)
	m.MaxFileSize = types.Float64Value(properties.MaxFileSizeToInspect)
	m.MaxFileSizeUnit = types.StringValue(properties.MaxFileSizeToInspectUnit)

	m.BeSplashScreen = types.BoolPointerValue(properties.BeSplashEnabled)
	m.BeUploadTimeoutSeconds = types.Int32Value(properties.BeUploadTimeoutDurationSeconds)
	m.BeUploadTimeoutResponse = types.StringValue(properties.BeUploadTimeoutResponse)
	m.BePasteTimeoutMilliseconds = types.Int32Value(properties.BePasteTimeoutDurationMilliseconds)
	m.BePasteTimeoutResponse = types.StringValue(properties.BePasteTimeoutResponse)
	m.BePasteClipboardMinSize = types.Float64Value(properties.BePasteClipboardMinSize)
	m.BePasteClipboardMinSizeUnit = types.StringValue(properties.BePasteClipboardMinSizeUnit)
	m.BePasteClipboardMaxSize = types.Float64Value(properties.BePasteClipboardMaxSize)
	m.BePasteClipboardMaxSizeUnit = types.StringValue(properties.BePasteClipboardMaxSizeUnit)
	m.BePasteClipboardBlockOverMaxSize = types.BoolPointerValue(properties.BePasteClipboardOverSizeBehaviourBlock)

	m.EujRequireAdditionalDetails = types.BoolPointerValue(properties.EujRequireAdditionalDetails)
	m.EujDialogTimeout = types.Int32Value(properties.EujDialogTimeout)

	// The C2 strings canonicalize an empty remote to null via flex, so an unset
	// field reads back as null rather than as "".
	m.EujCompanyLogo = flex.StringValueToFramework(properties.EujDialogBoxLogo)

	excludeDomains, excludeDomainDiags := flattenExcludeDomains(ctx, properties.BeExcludeDomains)
	diags.Append(excludeDomainDiags...)
	m.BeExcludeDomains = excludeDomains

	// Each collapsed pair reads back as the text only when the wire source says
	// custom and the text is non-empty.
	m.BeCustomSplashMessage = flattenCustomMessage(
		properties.BeSplashMessageSource, properties.BeSplashCustomMessage,
	)
	m.CustomAllowedActionNotification = flattenCustomMessage(
		properties.AllowNotifications, properties.CustomAllowNotification,
	)
	m.CustomBlockedActionNotification = flattenCustomMessage(
		properties.BlockNotifications, properties.CustomBlockNotification,
	)

	m.EujCustomHeaderText = flattenEujHeaderText(properties.EujHeaderText)

	businessPurposes, personalUse, customOptions, dropdownDiags := flattenEujDropdownOptions(
		ctx, properties.EujDropdownOptions,
	)
	diags.Append(dropdownDiags...)
	m.EujBusinessPurposesEnabled = businessPurposes
	m.EujPersonalUseEnabled = personalUse
	m.EujCustomDropdownOptions = customOptions

	// Most of the platform-scoped settings are absent from the wrong platform's
	// response, so each one flattens to null there, which is exactly what ModifyPlan
	// planned.
	//
	// browsers_without_active_extension and block_all_data_access are the exception: a
	// Mac policy is stored with Windows values for both and echoes them back even
	// though the write body never sent them, so reading them straight across would
	// contradict the null the plan carries on Mac. They are read on Windows only.
	if platformName == platformWindows {
		m.BrowsersWithoutActiveExtension = flex.StringValueToFramework(
			properties.BrowsersWithoutActiveExtension,
		)
		m.BlockAllDataAccess = types.BoolPointerValue(properties.BlockAllDataAccess)
	} else {
		m.BrowsersWithoutActiveExtension = types.StringNull()
		m.BlockAllDataAccess = types.BoolNull()
	}

	m.ScreenCapture = types.BoolPointerValue(properties.EnableScreenCapture)
	m.ScreenCapturePreEventSeconds = flex.StringValueToFramework(properties.ScreenCaptureDurationPreEvent)
	m.ScreenCapturePostEventSeconds = flex.StringValueToFramework(properties.ScreenCaptureDurationPostEvent)
	m.EvidenceStorage = types.BoolPointerValue(properties.EvidenceDownloadEnabled)
	m.EndUserEncryptionActivity = types.BoolPointerValue(properties.EvidenceEncryptedEnabled)
	m.EvidenceStorageMaxFreeSpacePercent = float64OrNull(properties.EvidenceStorageFreeDiskPerc)
	m.EvidenceStorageMaxSizeGiB = float64OrNull(properties.EvidenceStorageMaxSize)
	m.NetworkInspection = types.BoolPointerValue(properties.EnableNetworkInspection)
	m.NetworkInspectionFilesExceedingSizeLimit = flex.StringValueToFramework(
		properties.NetworkInspectionFilesExceedingSizeLimit,
	)
	m.EnableOCR = types.BoolPointerValue(properties.EnableOCR)

	return diags
}

// wirePlatformName converts platform_name into the wire value for the query
// parameter. An unmapped value cannot be sent, so it is reported rather than
// passed through: the API answers an unknown platform with an opaque 400.
func wirePlatformName(platformName string) (string, diag.Diagnostic) {
	wire, ok := platformNameToAPI[platformName]
	if !ok {
		return "", diag.NewAttributeErrorDiagnostic(
			path.Root("platform_name"),
			"Unsupported data protection policy platform",
			fmt.Sprintf(
				"platform_name %q is not supported. Valid values are %q and %q.",
				platformName, platformWindows, platformMac,
			),
		)
	}

	return wire, nil
}

// schemaPlatformName converts the platform_name the API returns into the
// practitioner-facing value. An unmapped value is treated as a provider or API
// defect rather than passed through, because writing a wire value into state
// would surface as Terraform's opaque produced-inconsistent-result error instead
// of a readable diagnostic.
func schemaPlatformName(apiPlatformName string) (string, diag.Diagnostic) {
	name, ok := platformNameFromAPI[apiPlatformName]
	if !ok {
		return "", diag.NewErrorDiagnostic(
			"Unexpected data protection policy platform",
			fmt.Sprintf(
				"The API returned platform_name %q, which the provider does not recognize. "+
					"Please report this issue at: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
				apiPlatformName,
			),
		)
	}

	return name, nil
}

// policyPayloadDiagnostic classifies the application-level errors the data
// protection policy endpoints return alongside a successful HTTP status.
//
// A missing policy is reported as HTTP 200 carrying a payload error with code
// 404, so read and delete have to inspect the payload rather than the status
// code. tferrors.NewDiagnosticFromPayloadErrors is typed to []*models.MsaAPIError
// and cannot accept []*models.PolicymanagerError, which is why the
// 200-with-errors classification lives here.
//
// Returns nil when the payload carries no errors.
func policyPayloadDiagnostic(
	operation tferrors.Operation,
	payloadErrors []*models.PolicymanagerError,
) diag.Diagnostic {
	if len(payloadErrors) == 0 {
		return nil
	}

	for _, payloadErr := range payloadErrors {
		if payloadErr == nil || payloadErr.Code == nil || *payloadErr.Code != 404 {
			continue
		}

		return tferrors.NewNotFoundError(policyErrorDetail(payloadErr))
	}

	return tferrors.NewOperationError(operation, errors.New(policyErrorDetails(payloadErrors)))
}

// policyErrorDetails renders every payload error as a single readable detail.
func policyErrorDetails(payloadErrors []*models.PolicymanagerError) string {
	details := make([]string, 0, len(payloadErrors))
	for _, payloadErr := range payloadErrors {
		if detail := policyErrorDetail(payloadErr); detail != "" {
			details = append(details, detail)
		}
	}

	if len(details) == 0 {
		return "the API reported an error but supplied no message"
	}

	return strings.Join(details, "; ")
}

// policyErrorDetail renders one payload error, including the field it blames when
// the API populates one.
func policyErrorDetail(payloadErr *models.PolicymanagerError) string {
	if payloadErr == nil {
		return ""
	}

	var detail strings.Builder

	if payloadErr.Code != nil {
		fmt.Fprintf(&detail, "%d: ", *payloadErr.Code)
	}

	if payloadErr.Message != nil {
		detail.WriteString(*payloadErr.Message)
	}

	if payloadErr.Field != "" {
		fmt.Fprintf(&detail, " (field: %s)", payloadErr.Field)
	}

	return strings.TrimSpace(detail.String())
}
