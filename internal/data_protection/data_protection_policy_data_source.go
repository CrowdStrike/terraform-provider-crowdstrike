package dataprotection

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	policyDataSourceDocumentationSection = "Data Protection"
	policyDataSourceMarkdownDescription  = "This data source provides information about a single Falcon Data Protection policy."
)

// policyDataSourceRequiredScopes reuses the resource's required scopes -- the
// data protection read/write scope also covers reads of a single policy.
var policyDataSourceRequiredScopes = policyResourceRequiredScopes

var (
	_ datasource.DataSource              = &dataProtectionPolicyDataSource{}
	_ datasource.DataSourceWithConfigure = &dataProtectionPolicyDataSource{}
)

func NewDataProtectionPolicyDataSource() datasource.DataSource {
	return &dataProtectionPolicyDataSource{}
}

type dataProtectionPolicyDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

// dataProtectionPolicyDataSourceModel mirrors dataProtectionPolicyResourceModel
// in policy_resource.go field for field, so a practitioner moving from the
// resource to a lookup of an existing policy sees the same attribute names.
type dataProtectionPolicyDataSourceModel struct {
	// Identity and structure
	ID           types.String `tfsdk:"id"`
	Filter       types.String `tfsdk:"filter"`
	PlatformName types.String `tfsdk:"platform_name"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	Enabled      types.Bool   `tfsdk:"enabled"`

	// Assignment
	HostGroups      types.Set `tfsdk:"host_groups"`
	Classifications types.Set `tfsdk:"classifications"`

	// Server-owned metadata
	CID        types.String `tfsdk:"cid"`
	CreatedAt  types.String `tfsdk:"created_at"`
	CreatedBy  types.String `tfsdk:"created_by"`
	IsDefault  types.Bool   `tfsdk:"is_default"`
	Precedence types.Int32  `tfsdk:"precedence"`

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

// wrap converts the API model to the Terraform data source model. It mirrors
// dataProtectionPolicyResourceModel.wrap in policy_resource.go field for field;
// see that method for the reasoning behind each conversion.
func (m *dataProtectionPolicyDataSourceModel) wrap(
	ctx context.Context,
	policy policyOverride,
) diag.Diagnostics {
	var diags diag.Diagnostics

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
	m.IsDefault = types.BoolPointerValue(policy.IsDefault)
	m.Precedence = types.Int32PointerValue(policy.Precedence)

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
	m.EujCompanyLogo = flex.StringValueToFramework(properties.EujDialogBoxLogo)

	excludeDomains, excludeDomainDiags := flattenExcludeDomains(ctx, properties.BeExcludeDomains)
	diags.Append(excludeDomainDiags...)
	m.BeExcludeDomains = excludeDomains

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

func (d *dataProtectionPolicyDataSource) Configure(
	_ context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	providerConfig, ok := req.ProviderData.(config.ProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = providerConfig.Client
}

func (d *dataProtectionPolicyDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_data_protection_policy"
}

func (d *dataProtectionPolicyDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			policyDataSourceDocumentationSection,
			policyDataSourceMarkdownDescription,
			policyDataSourceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			// ---------- lookup arguments ----------
			"id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Unique identifier of the policy. Set this to look the policy up directly by identifier, which does not require `platform_name`. Exactly one of `id` or `filter` must be provided.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(policyIDPattern, "must be a 32-character hex policy ID"),
					stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("filter")),
				},
			},
			"filter": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "An FQL filter that resolves to exactly one data protection policy: the lookup fails if it matches none or more than one. Requires `platform_name`. Exactly one of `id` or `filter` must be provided. See the [Filtering with Falcon Query Language](https://registry.terraform.io/providers/crowdstrike/crowdstrike/latest/docs/guides/falcon-query-language) guide for the syntax, and the Filtering section of this page for the properties data protection policies can be filtered on and the caveats that apply to them.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.AlsoRequires(path.MatchRoot("platform_name")),
				},
			},
			"platform_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Platform the policy applies to. Accepts `Windows` or `Mac`. Required when using `filter`, because the search API only searches one platform at a time. Must not be set when using `id`, which the API resolves without a platform.",
				Validators: []validator.String{
					stringvalidator.OneOf(platformWindows, platformMac),
					stringvalidator.ConflictsWith(path.MatchRoot("id")),
				},
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the policy.",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Description of the policy.",
			},
			"enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the policy is enabled.",
			},

			// ---------- assignment ----------
			"host_groups": schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Host group IDs assigned to this policy.",
			},
			"classifications": schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Classification IDs assigned to this policy.",
			},

			// ---------- server-owned metadata ----------
			"cid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Customer ID that owns the policy.",
			},
			"created_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the policy was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identity that created the policy.",
			},
			"is_default": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this is the platform's default policy.",
			},
			"precedence": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "Position of the policy in its platform's precedence order.",
			},

			// ---------- inspection ----------
			"context_inspection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Gives insight into data sources, assigned sensitivity labels, and file types, for data in motion and at rest.",
			},
			"content_inspection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Inspects egressing data against the content patterns used by this policy's classifications.",
			},
			"clipboard_inspection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Detects egress when classified data is pasted from the clipboard in supported browsers.",
			},
			"clipboard_web_origin": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Tracks and attributes web sources for clipboard content copied from web applications.",
			},
			"similarity_detection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Detects egress of files containing content copied from other classified files on the same endpoint.",
			},
			"minimum_similarity_threshold": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Minimum percentage of similar content required for an egress event to be monitored.",
			},
			"inspection_depth": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Inspection depth for data in motion.",
			},
			"inspection_confidence": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Minimum confidence level for reporting content matches.",
			},
			"max_file_size": schema.Float64Attribute{
				Computed:            true,
				MarkdownDescription: "Largest file the sensor inspects for classified content, expressed in `max_file_size_unit`.",
			},
			"max_file_size_unit": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unit for `max_file_size`.",
			},

			// ---------- browser extension ----------
			"be_exclude_domains": schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Domain patterns excluded from visibility and enforcement by the Falcon browser extension.",
			},
			"be_splash_screen": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the browser extension shows a splash screen while a file is being evaluated.",
			},
			"be_custom_splash_message": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Custom text for the browser extension splash dialog.",
			},
			"be_upload_timeout_seconds": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "How long the browser extension waits for a response when uploading data before timing out, in seconds.",
			},
			"be_upload_timeout_response": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Extension behavior when an upload evaluation times out.",
			},
			"be_paste_timeout_milliseconds": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "How long the browser extension waits for a response when pasting data before timing out, in milliseconds.",
			},
			"be_paste_timeout_response": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Extension behavior when a paste evaluation times out.",
			},
			"be_paste_clipboard_min_size": schema.Float64Attribute{
				Computed:            true,
				MarkdownDescription: "Minimum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_min_size_unit`.",
			},
			"be_paste_clipboard_min_size_unit": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unit for `be_paste_clipboard_min_size`.",
			},
			"be_paste_clipboard_max_size": schema.Float64Attribute{
				Computed:            true,
				MarkdownDescription: "Maximum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_max_size_unit`.",
			},
			"be_paste_clipboard_max_size_unit": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unit for `be_paste_clipboard_max_size`.",
			},
			"be_paste_clipboard_block_over_max_size": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "When `true`, pastes exceeding `be_paste_clipboard_max_size` are blocked regardless of content.",
			},

			// ---------- unsupported browsers ----------
			"browsers_without_active_extension": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** How browsers without an active Falcon extension handle data uploads.",
			},
			"block_all_data_access": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Blocks all data access via Firefox and Internet Explorer.",
			},

			// ---------- end user notifications ----------
			"custom_allowed_action_notification": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Custom text shown to end users when a rule allows an action.",
			},
			"custom_blocked_action_notification": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Custom text shown to end users when a rule blocks an action.",
			},

			// ---------- end user justification ----------
			"euj_require_additional_details": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "When `true`, the end user must fill in the additional details box to proceed with a justification.",
			},
			"euj_dialog_timeout": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "Timeout for the end user justification dialog, in seconds.",
			},
			"euj_company_logo": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Company logo shown in the end user justification dialog, as a base64 PNG data URI.",
			},
			"euj_custom_header_text": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Custom header text for the end user justification dialog.",
			},
			"euj_business_purposes_enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the built-in `Business purposes` option is offered in the end user justification dialog.",
			},
			"euj_personal_use_enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the built-in `Personal use` option is offered in the end user justification dialog.",
			},
			"euj_custom_dropdown_options": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Custom justification options offered in the end user justification dialog.",
			},

			// ---------- Windows only ----------
			"screen_capture": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Captures the screen before and after an egress event.",
			},
			"screen_capture_pre_event_seconds": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Seconds of screen recording retained before a trigger event.",
			},
			"screen_capture_post_event_seconds": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Seconds of screen recording retained after a trigger event.",
			},
			"evidence_storage": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Allows users with the Data Protection Forensics Manager role to request and download files for egress events.",
			},
			"end_user_encryption_activity": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** When data encryption occurs, stores a copy of the original data in a protected folder on the host.",
			},
			"evidence_storage_max_free_space_percent": schema.Float64Attribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Maximum percentage of free disk space evidence storage may consume.",
			},
			"evidence_storage_max_size_gib": schema.Float64Attribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Maximum disk space in GiB that evidence storage may use on a host.",
			},
			"network_inspection": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** Detects egress of classified data via network traffic.",
			},
			"network_inspection_files_exceeding_size_limit": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "**Windows only.** How network inspection handles file uploads larger than its 1 MiB ceiling.",
			},

			// ---------- Mac only ----------
			"enable_ocr": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "**Mac only.** Extracts and classifies sensitive text from image files such as screenshots and photos during data egress.",
			},
		},
	}
}

func (d *dataProtectionPolicyDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data dataProtectionPolicyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		policy *policyOverride
		diags  diag.Diagnostics
	)

	if !data.ID.IsNull() && data.ID.ValueString() != "" {
		// The API resolves an ID without a platform, and platform_name conflicts
		// with id, so there is no platform to translate on this path.
		policy, diags = d.findPolicyByID(ctx, data.ID.ValueString())
	} else {
		// platform_name is required alongside filter, so it is set here.
		wirePlatform, diagnostic := wirePlatformName(data.PlatformName.ValueString())
		if diagnostic != nil {
			resp.Diagnostics.Append(diagnostic)
			return
		}

		policy, diags = d.findPolicyByFilter(ctx, wirePlatform, data.Filter.ValueString())
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.wrap(ctx, *policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getPoliciesByIDs fetches the full policies for the given IDs using
// EntitiesPolicyGetV2 and the extended reader override.
func (d *dataProtectionPolicyDataSource) getPoliciesByIDs(
	ctx context.Context,
	ids []string,
	notFoundDetail string,
) ([]*policyOverride, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := data_protection_configuration.NewEntitiesPolicyGetV2Params().
		WithContext(ctx).
		WithIds(ids)

	reader, option := withPolicyGetOverride()

	res, err := d.client.DataProtectionConfiguration.EntitiesPolicyGetV2(params, option)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, policyDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil || reader.extended == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	if diagnostic := policyPayloadDiagnostic(tferrors.Read, res.Payload.Errors); diagnostic != nil {
		diags.Append(diagnostic)
		return nil, diags
	}

	return reader.extended.Resources, diags
}

// findPolicyByID looks up exactly one policy by its ID. The API resolves an ID
// without a platform, so no platform is involved on this path.
func (d *dataProtectionPolicyDataSource) findPolicyByID(
	ctx context.Context,
	id string,
) (*policyOverride, diag.Diagnostics) {
	tflog.Debug(ctx, "[datasource] Looking up data protection policy by ID", map[string]any{
		"id": id,
	})

	notFoundDetail := fmt.Sprintf("No data protection policy found with ID %q.", id)

	policies, diags := d.getPoliciesByIDs(ctx, []string{id}, notFoundDetail)
	if diags.HasError() {
		return nil, diags
	}

	if len(policies) == 0 || policies[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	return policies[0], diags
}

// findPolicyByFilter resolves exactly one policy from a practitioner-supplied
// FQL filter, using QueriesPolicyGetV2 to search a single platform and
// EntitiesPolicyGetV2 to fetch the full policy for the ID it returns.
//
// The filter is passed through verbatim: the search API owns FQL parsing and
// rejects a malformed filter or an unknown key with a 400 carrying a readable
// message, which is more accurate than anything the provider could pre-validate.
func (d *dataProtectionPolicyDataSource) findPolicyByFilter(
	ctx context.Context,
	wirePlatform string,
	filter string,
) (*policyOverride, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "[datasource] Looking up data protection policy by filter", map[string]any{
		"filter":        filter,
		"platform_name": wirePlatform,
	})

	notFoundDetail := fmt.Sprintf(
		"No data protection policy on platform %q matched filter %q.", wirePlatform, filter,
	)

	queryParams := data_protection_configuration.NewQueriesPolicyGetV2Params().
		WithContext(ctx).
		WithFilter(&filter)
	queryParams.PlatformName = wirePlatform

	queryRes, err := d.client.DataProtectionConfiguration.QueriesPolicyGetV2(queryParams)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Read, err, policyDataSourceRequiredScopes,
			tferrors.WithNotFoundDetail(notFoundDetail),
		))
		return nil, diags
	}

	if queryRes == nil || queryRes.Payload == nil || len(queryRes.Payload.Resources) == 0 {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	if len(queryRes.Payload.Resources) > 1 {
		diags.AddError(
			"Multiple data protection policies found",
			fmt.Sprintf(
				"Filter %q matched %d data protection policies on platform %q, but this data source "+
					"requires exactly one. Narrow the filter, or look the policy up by its `id`.",
				filter, len(queryRes.Payload.Resources), wirePlatform,
			),
		)
		return nil, diags
	}

	policies, fetchDiags := d.getPoliciesByIDs(ctx, queryRes.Payload.Resources, notFoundDetail)
	diags.Append(fetchDiags...)
	if diags.HasError() {
		return nil, diags
	}

	if len(policies) == 0 || policies[0] == nil {
		diags.Append(tferrors.NewNotFoundError(notFoundDetail))
		return nil, diags
	}

	return policies[0], diags
}
