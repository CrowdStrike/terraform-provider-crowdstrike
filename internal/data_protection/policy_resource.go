package dataprotection

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
)

var (
	_ resource.Resource                = &dataProtectionPolicyResource{}
	_ resource.ResourceWithConfigure   = &dataProtectionPolicyResource{}
	_ resource.ResourceWithImportState = &dataProtectionPolicyResource{}
)

var dataProtectionPolicyRequiredScopes = []scopes.Scope{
	{Name: "Data Protection", Read: true, Write: true},
}

var dataProtectionPolicyEUJOptionAttrTypes = map[string]attr.Type{
	"default":       types.BoolType,
	"id":            types.StringType,
	"justification": types.StringType,
	"selected":      types.BoolType,
}

var dataProtectionPolicyEUJHeaderAttrTypes = map[string]attr.Type{
	"default":  types.BoolType,
	"header":   types.StringType,
	"selected": types.BoolType,
}

var dataProtectionPolicyEUJDropdownOptionsAttrTypes = map[string]attr.Type{
	"justifications": types.ListType{ElemType: types.ObjectType{AttrTypes: dataProtectionPolicyEUJOptionAttrTypes}},
}

var dataProtectionPolicyEUJHeaderTextAttrTypes = map[string]attr.Type{
	"headers": types.ListType{ElemType: types.ObjectType{AttrTypes: dataProtectionPolicyEUJHeaderAttrTypes}},
}

var dataProtectionPolicyPropertiesAttrTypes = map[string]attr.Type{
	"allow_notifications":                               types.StringType,
	"be_exclude_domains":                                types.StringType,
	"be_paste_clipboard_max_size":                       types.Float64Type,
	"be_paste_clipboard_max_size_unit":                  types.StringType,
	"be_paste_clipboard_min_size":                       types.Float64Type,
	"be_paste_clipboard_min_size_unit":                  types.StringType,
	"be_paste_clipboard_over_size_behaviour_block":      types.BoolType,
	"be_paste_timeout_duration_milliseconds":            types.Int32Type,
	"be_paste_timeout_response":                         types.StringType,
	"be_splash_custom_message":                          types.StringType,
	"be_splash_enabled":                                 types.BoolType,
	"be_splash_message_source":                          types.StringType,
	"be_upload_timeout_duration_seconds":                types.Int32Type,
	"be_upload_timeout_response":                        types.StringType,
	"block_all_data_access":                             types.BoolType,
	"block_notifications":                               types.StringType,
	"browsers_without_active_extension":                 types.StringType,
	"classifications":                                   types.SetType{ElemType: types.StringType},
	"custom_allow_notification":                         types.StringType,
	"custom_block_notification":                         types.StringType,
	"enable_clipboard_inspection":                       types.BoolType,
	"enable_content_inspection":                         types.BoolType,
	"enable_context_inspection":                         types.BoolType,
	"enable_end_user_notifications_unsupported_browser": types.BoolType,
	"enable_network_inspection":                         types.BoolType,
	"euj_dialog_box_logo":                               types.StringType,
	"euj_dialog_timeout":                                types.Int32Type,
	"euj_dropdown_options":                              types.ObjectType{AttrTypes: dataProtectionPolicyEUJDropdownOptionsAttrTypes},
	"euj_header_text":                                   types.ObjectType{AttrTypes: dataProtectionPolicyEUJHeaderTextAttrTypes},
	"euj_require_additional_details":                    types.BoolType,
	"euj_response_cache_timeout":                        types.Int32Type,
	"evidence_download_enabled":                         types.BoolType,
	"evidence_duplication_enabled_default":              types.BoolType,
	"evidence_encrypted_enabled":                        types.BoolType,
	"evidence_storage_free_disk_perc":                   types.Float64Type,
	"evidence_storage_max_size":                         types.Float64Type,
	"inspection_depth":                                  types.StringType,
	"max_file_size_to_inspect":                          types.Float64Type,
	"max_file_size_to_inspect_unit":                     types.StringType,
	"min_confidence_level":                              types.StringType,
	"network_inspection_files_exceeding_size_limit":     types.StringType,
	"similarity_detection":                              types.BoolType,
	"similarity_threshold":                              types.StringType,
	"unsupported_browsers_action":                       types.StringType,
}

func NewDataProtectionPolicyResource() resource.Resource {
	return &dataProtectionPolicyResource{}
}

type dataProtectionPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

type dataProtectionPolicyResourceModel struct {
	ID               types.String `tfsdk:"id"`
	CID              types.String `tfsdk:"cid"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	PlatformName     types.String `tfsdk:"platform_name"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	HostGroups       types.Set    `tfsdk:"host_groups"`
	Precedence       types.Int32  `tfsdk:"precedence"`
	IsDefault        types.Bool   `tfsdk:"is_default"`
	PolicyType       types.String `tfsdk:"policy_type"`
	CreatedAt        types.String `tfsdk:"created_at"`
	CreatedBy        types.String `tfsdk:"created_by"`
	ModifiedAt       types.String `tfsdk:"modified_at"`
	ModifiedBy       types.String `tfsdk:"modified_by"`
	PolicyProperties types.Object `tfsdk:"policy_properties"`
}

type dataProtectionPolicyPropertiesModel struct {
	AllowNotifications                           types.String  `tfsdk:"allow_notifications"`
	BeExcludeDomains                             types.String  `tfsdk:"be_exclude_domains"`
	BePasteClipboardMaxSize                      types.Float64 `tfsdk:"be_paste_clipboard_max_size"`
	BePasteClipboardMaxSizeUnit                  types.String  `tfsdk:"be_paste_clipboard_max_size_unit"`
	BePasteClipboardMinSize                      types.Float64 `tfsdk:"be_paste_clipboard_min_size"`
	BePasteClipboardMinSizeUnit                  types.String  `tfsdk:"be_paste_clipboard_min_size_unit"`
	BePasteClipboardOverSizeBehaviourBlock       types.Bool    `tfsdk:"be_paste_clipboard_over_size_behaviour_block"`
	BePasteTimeoutDurationMilliseconds           types.Int32   `tfsdk:"be_paste_timeout_duration_milliseconds"`
	BePasteTimeoutResponse                       types.String  `tfsdk:"be_paste_timeout_response"`
	BeSplashCustomMessage                        types.String  `tfsdk:"be_splash_custom_message"`
	BeSplashEnabled                              types.Bool    `tfsdk:"be_splash_enabled"`
	BeSplashMessageSource                        types.String  `tfsdk:"be_splash_message_source"`
	BeUploadTimeoutDurationSeconds               types.Int32   `tfsdk:"be_upload_timeout_duration_seconds"`
	BeUploadTimeoutResponse                      types.String  `tfsdk:"be_upload_timeout_response"`
	BlockAllDataAccess                           types.Bool    `tfsdk:"block_all_data_access"`
	BlockNotifications                           types.String  `tfsdk:"block_notifications"`
	BrowsersWithoutActiveExtension               types.String  `tfsdk:"browsers_without_active_extension"`
	Classifications                              types.Set     `tfsdk:"classifications"`
	CustomAllowNotification                      types.String  `tfsdk:"custom_allow_notification"`
	CustomBlockNotification                      types.String  `tfsdk:"custom_block_notification"`
	EnableClipboardInspection                    types.Bool    `tfsdk:"enable_clipboard_inspection"`
	EnableContentInspection                      types.Bool    `tfsdk:"enable_content_inspection"`
	EnableContextInspection                      types.Bool    `tfsdk:"enable_context_inspection"`
	EnableEndUserNotificationsUnsupportedBrowser types.Bool    `tfsdk:"enable_end_user_notifications_unsupported_browser"`
	EnableNetworkInspection                      types.Bool    `tfsdk:"enable_network_inspection"`
	EujDialogBoxLogo                             types.String  `tfsdk:"euj_dialog_box_logo"`
	EujDialogTimeout                             types.Int32   `tfsdk:"euj_dialog_timeout"`
	EujDropdownOptions                           types.Object  `tfsdk:"euj_dropdown_options"`
	EujHeaderText                                types.Object  `tfsdk:"euj_header_text"`
	EujRequireAdditionalDetails                  types.Bool    `tfsdk:"euj_require_additional_details"`
	EujResponseCacheTimeout                      types.Int32   `tfsdk:"euj_response_cache_timeout"`
	EvidenceDownloadEnabled                      types.Bool    `tfsdk:"evidence_download_enabled"`
	EvidenceDuplicationEnabledDefault            types.Bool    `tfsdk:"evidence_duplication_enabled_default"`
	EvidenceEncryptedEnabled                     types.Bool    `tfsdk:"evidence_encrypted_enabled"`
	EvidenceStorageFreeDiskPerc                  types.Float64 `tfsdk:"evidence_storage_free_disk_perc"`
	EvidenceStorageMaxSize                       types.Float64 `tfsdk:"evidence_storage_max_size"`
	InspectionDepth                              types.String  `tfsdk:"inspection_depth"`
	MaxFileSizeToInspect                         types.Float64 `tfsdk:"max_file_size_to_inspect"`
	MaxFileSizeToInspectUnit                     types.String  `tfsdk:"max_file_size_to_inspect_unit"`
	MinConfidenceLevel                           types.String  `tfsdk:"min_confidence_level"`
	NetworkInspectionFilesExceedingSizeLimit     types.String  `tfsdk:"network_inspection_files_exceeding_size_limit"`
	SimilarityDetection                          types.Bool    `tfsdk:"similarity_detection"`
	SimilarityThreshold                          types.String  `tfsdk:"similarity_threshold"`
	UnsupportedBrowsersAction                    types.String  `tfsdk:"unsupported_browsers_action"`
}

type dataProtectionPolicyEUJDropdownOptionsModel struct {
	Justifications types.List `tfsdk:"justifications"`
}

type dataProtectionPolicyEUJOptionModel struct {
	Default       types.Bool   `tfsdk:"default"`
	ID            types.String `tfsdk:"id"`
	Justification types.String `tfsdk:"justification"`
	Selected      types.Bool   `tfsdk:"selected"`
}

type dataProtectionPolicyEUJHeaderTextModel struct {
	Headers types.List `tfsdk:"headers"`
}

type dataProtectionPolicyEUJHeaderModel struct {
	Default  types.Bool   `tfsdk:"default"`
	Header   types.String `tfsdk:"header"`
	Selected types.Bool   `tfsdk:"selected"`
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
			"Manages a Falcon Data Protection policy, including its precedence, host group assignments, enablement state, and policy properties.",
			dataProtectionPolicyRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the data protection policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "CID that owns the policy.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the data protection policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the data protection policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the policy. Valid values are `win` and `mac`. Changing this value requires replacement.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("win", "mac"),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the policy is enabled.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host group IDs attached to the policy.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
				},
			},
			"precedence": schema.Int32Attribute{
				Required:    true,
				Description: "Precedence of the policy.",
			},
			"is_default": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether this is a CrowdStrike-managed default policy.",
			},
			"policy_type": schema.StringAttribute{
				Computed:    true,
				Description: "Policy type reported by the CrowdStrike API.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the policy was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "User or service that created the policy.",
			},
			"modified_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the policy was last modified.",
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "User or service that last modified the policy.",
			},
			"policy_properties": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Policy behavior settings enforced by Falcon Data Protection.",
				Attributes: map[string]schema.Attribute{
					"allow_notifications": optionalPolicyStringAttribute("Windows-only notification mode for allow events.", stringvalidator.OneOf("default", "custom")),
					"be_exclude_domains":  optionalPolicyStringAttribute("Browser extension excluded domains."),
					"be_paste_clipboard_max_size": schema.Float64Attribute{
						Optional:    true,
						Description: "Maximum clipboard paste size threshold.",
					},
					"be_paste_clipboard_max_size_unit": optionalPolicyStringAttribute("Clipboard maximum size unit.", stringvalidator.OneOf("Bytes", "KiB")),
					"be_paste_clipboard_min_size": schema.Float64Attribute{
						Optional:    true,
						Description: "Minimum clipboard paste size threshold.",
					},
					"be_paste_clipboard_min_size_unit": optionalPolicyStringAttribute("Clipboard minimum size unit.", stringvalidator.OneOf("Bytes", "KiB")),
					"be_paste_clipboard_over_size_behaviour_block": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether oversized clipboard pastes are blocked.",
					},
					"be_paste_timeout_duration_milliseconds": schema.Int32Attribute{
						Optional:    true,
						Description: "Browser extension paste timeout in milliseconds.",
					},
					"be_paste_timeout_response": optionalPolicyStringAttribute("Browser extension paste timeout action.", stringvalidator.OneOf("block", "allow")),
					"be_splash_custom_message":  optionalPolicyStringAttribute("Custom browser extension splash message."),
					"be_splash_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether the browser extension splash is enabled.",
					},
					"be_splash_message_source": optionalPolicyStringAttribute("Browser extension splash message source.", stringvalidator.OneOf("default", "custom")),
					"be_upload_timeout_duration_seconds": schema.Int32Attribute{
						Optional:    true,
						Description: "Browser extension upload timeout in seconds.",
					},
					"be_upload_timeout_response": optionalPolicyStringAttribute("Browser extension upload timeout action.", stringvalidator.OneOf("block", "allow")),
					"block_all_data_access": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether all data access is blocked by the policy.",
					},
					"block_notifications":               optionalPolicyStringAttribute("Windows-only notification mode for block events.", stringvalidator.OneOf("default", "custom")),
					"browsers_without_active_extension": optionalPolicyStringAttribute("Action for browsers without an active extension.", stringvalidator.OneOf("allow", "block_policy")),
					"classifications": schema.SetAttribute{
						Required:    true,
						ElementType: types.StringType,
						Description: "Classification IDs associated with the policy.",
						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
							setvalidator.ValueStringsAre(fwvalidators.StringNotWhitespace()),
						},
					},
					"custom_allow_notification": optionalPolicyStringAttribute("Custom Windows allow notification text."),
					"custom_block_notification": optionalPolicyStringAttribute("Custom Windows block notification text."),
					"enable_clipboard_inspection": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether clipboard inspection is enabled.",
					},
					"enable_content_inspection": schema.BoolAttribute{
						Required:    true,
						Description: "Whether content inspection is enabled.",
					},
					"enable_context_inspection": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether context inspection is enabled.",
					},
					"enable_end_user_notifications_unsupported_browser": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether end user notifications are shown for unsupported browsers.",
					},
					"enable_network_inspection": schema.BoolAttribute{
						Optional:    true,
						Description: "Windows-only network inspection enablement.",
					},
					"euj_dialog_box_logo": optionalPolicyStringAttribute("Windows-only end-user justification dialog logo."),
					"euj_dialog_timeout": schema.Int32Attribute{
						Optional:    true,
						Description: "Windows-only end-user justification dialog timeout.",
					},
					"euj_dropdown_options": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Windows-only end-user justification dropdown options.",
						Attributes: map[string]schema.Attribute{
							"justifications": schema.ListNestedAttribute{
								Required:    true,
								Description: "Available justifications.",
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
								},
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"default": schema.BoolAttribute{
											Required:    true,
											Description: "Whether this justification is the default option.",
										},
										"id": schema.StringAttribute{
											Required:    true,
											Description: "Identifier for the justification option.",
											Validators: []validator.String{
												fwvalidators.StringNotWhitespace(),
											},
										},
										"justification": schema.StringAttribute{
											Required:    true,
											Description: "Display text for the justification option.",
											Validators: []validator.String{
												fwvalidators.StringNotWhitespace(),
											},
										},
										"selected": schema.BoolAttribute{
											Required:    true,
											Description: "Whether this option is currently selected.",
										},
									},
								},
							},
						},
					},
					"euj_header_text": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Windows-only end-user justification header text.",
						Attributes: map[string]schema.Attribute{
							"headers": schema.ListNestedAttribute{
								Required:    true,
								Description: "Available header entries.",
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
								},
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"default": schema.BoolAttribute{
											Required:    true,
											Description: "Whether this header is the default entry.",
										},
										"header": schema.StringAttribute{
											Required:    true,
											Description: "Header text.",
											Validators: []validator.String{
												fwvalidators.StringNotWhitespace(),
											},
										},
										"selected": schema.BoolAttribute{
											Required:    true,
											Description: "Whether this header is currently selected.",
										},
									},
								},
							},
						},
					},
					"euj_require_additional_details": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether additional details are required in the end-user justification dialog.",
					},
					"euj_response_cache_timeout": schema.Int32Attribute{
						Optional:    true,
						Description: "Windows-only response cache timeout for end-user justification.",
					},
					"evidence_download_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether evidence download is enabled.",
					},
					"evidence_duplication_enabled_default": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether evidence duplication is enabled by default.",
					},
					"evidence_encrypted_enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether evidence encryption is enabled.",
					},
					"evidence_storage_free_disk_perc": schema.Float64Attribute{
						Optional:    true,
						Description: "Minimum free disk percentage for evidence storage.",
					},
					"evidence_storage_max_size": schema.Float64Attribute{
						Optional:    true,
						Description: "Maximum evidence storage size.",
					},
					"inspection_depth": optionalPolicyStringAttribute("Inspection depth.", stringvalidator.OneOf("balanced", "high_performance", "deep_scan")),
					"max_file_size_to_inspect": schema.Float64Attribute{
						Optional:    true,
						Description: "Maximum file size to inspect.",
					},
					"max_file_size_to_inspect_unit":                 optionalPolicyStringAttribute("Unit for max file size to inspect.", stringvalidator.OneOf("Bytes", "KB", "MB")),
					"min_confidence_level":                          optionalPolicyStringAttribute("Minimum confidence level.", stringvalidator.OneOf("low", "medium", "high")),
					"network_inspection_files_exceeding_size_limit": optionalPolicyStringAttribute("Action for network inspection files exceeding the size limit.", stringvalidator.OneOf("block", "allow")),
					"similarity_detection": schema.BoolAttribute{
						Optional:    true,
						Description: "Whether similarity detection is enabled.",
					},
					"similarity_threshold":        optionalPolicyStringAttribute("Similarity threshold percentage.", stringvalidator.OneOf("10", "20", "30", "40", "50", "60", "70", "80", "90", "100")),
					"unsupported_browsers_action": optionalPolicyStringAttribute("Action for unsupported browsers.", stringvalidator.OneOf("allow", "block_policy", "block")),
				},
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

	policyProperties := expandDataProtectionPolicyProperties(ctx, plan.PolicyProperties, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := &models.PolicymanagerCreatePoliciesRequest{
		Resources: []*models.PolicymanagerExternalPolicyPost{
			{
				Name:             plan.Name.ValueStringPointer(),
				Description:      plan.Description.ValueStringPointer(),
				Precedence:       plan.Precedence.ValueInt32Pointer(),
				PolicyProperties: policyProperties,
			},
		},
	}

	params := data_protection_configuration.NewEntitiesPolicyPostV2Params().
		WithContext(ctx).
		WithPlatformName(plan.PlatformName.ValueString()).
		WithBody(createRequest)

	res, err := r.client.DataProtectionConfiguration.EntitiesPolicyPostV2(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			dataProtectionPolicyRequiredScopes,
		))
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := dataProtectionPolicyPayloadDiagnostic(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	policy := res.Payload.Resources[0]
	plan.ID = types.StringPointerValue(policy.ID)

	if plan.Enabled.ValueBool() || !plan.HostGroups.IsNull() {
		policy, resp.Diagnostics = r.updatePolicy(ctx, plan)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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

	params := data_protection_configuration.NewEntitiesPolicyGetV2Params().
		WithContext(ctx).
		WithIds([]string{state.ID.ValueString()})

	res, err := r.client.DataProtectionConfiguration.EntitiesPolicyGetV2(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(
			tferrors.Read,
			err,
			dataProtectionPolicyRequiredScopes,
		)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
		resp.State.RemoveResource(ctx)
		return
	}

	if diag := dataProtectionPolicyPayloadDiagnostic(tferrors.Read, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, res.Payload.Resources[0])...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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

	policy, diags := r.updatePolicy(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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

	if diag := deleteDataProtectionPolicy(ctx, r.client, encodeDataProtectionPolicySweepID(state.PlatformName.ValueString(), state.ID.ValueString())); diag != nil {
		tfDiag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, diag, dataProtectionPolicyRequiredScopes)
		if tfDiag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(tfDiag)
		return
	}
}

func (r *dataProtectionPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *dataProtectionPolicyResource) updatePolicy(
	ctx context.Context,
	plan dataProtectionPolicyResourceModel,
) (*models.PolicymanagerExternalPolicy, diag.Diagnostics) {
	var diags diag.Diagnostics

	policyProperties := expandDataProtectionPolicyProperties(ctx, plan.PolicyProperties, &diags)
	if diags.HasError() {
		return nil, diags
	}

	hostGroups := flex.ExpandSetAs[string](ctx, plan.HostGroups, &diags)
	if diags.HasError() {
		return nil, diags
	}

	updateRequest := &models.PolicymanagerUpdatePoliciesRequest{
		Resources: []*models.PolicymanagerExternalPolicyPatch{
			{
				ID:               plan.ID.ValueStringPointer(),
				Name:             plan.Name.ValueString(),
				Description:      plan.Description.ValueString(),
				HostGroups:       hostGroups,
				IsEnabled:        plan.Enabled.ValueBoolPointer(),
				PolicyProperties: policyProperties,
				Precedence:       plan.Precedence.ValueInt32Pointer(),
			},
		},
	}

	params := data_protection_configuration.NewEntitiesPolicyPatchV2Params().
		WithContext(ctx).
		WithPlatformName(plan.PlatformName.ValueString()).
		WithBody(updateRequest)

	res, err := r.client.DataProtectionConfiguration.EntitiesPolicyPatchV2(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Update,
			err,
			dataProtectionPolicyRequiredScopes,
		))
		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return nil, diags
	}

	if diag := dataProtectionPolicyPayloadDiagnostic(tferrors.Update, res.Payload.Errors); diag != nil {
		diags.Append(diag)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (m *dataProtectionPolicyResourceModel) wrap(
	ctx context.Context,
	policy *models.PolicymanagerExternalPolicy,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(policy.ID)
	m.CID = flex.StringPointerToFramework(policy.Cid)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.PlatformName = flex.StringPointerToFramework(policy.PlatformName)
	m.Enabled = types.BoolPointerValue(policy.IsEnabled)
	m.Precedence = flex.Int32PointerToFramework(policy.Precedence)
	m.IsDefault = types.BoolPointerValue(policy.IsDefault)
	m.PolicyType = flex.StringPointerToFramework(policy.PolicyType)
	m.CreatedAt = flex.StringPointerToFramework(policy.CreatedAt)
	m.CreatedBy = flex.StringPointerToFramework(policy.CreatedBy)
	m.ModifiedAt = flex.StringPointerToFramework(policy.ModifiedAt)
	m.ModifiedBy = flex.StringPointerToFramework(policy.ModifiedBy)

	hostGroups, hostGroupDiags := flex.FlattenStringValueSet(ctx, policy.HostGroups)
	diags.Append(hostGroupDiags...)
	if diags.HasError() {
		return diags
	}
	m.HostGroups = hostGroups

	policyProperties, policyPropertiesDiags := flattenDataProtectionPolicyProperties(ctx, policy.PolicyProperties, m.PolicyProperties)
	diags.Append(policyPropertiesDiags...)
	if diags.HasError() {
		return diags
	}
	m.PolicyProperties = policyProperties

	return diags
}

func optionalPolicyStringAttribute(description string, validators ...validator.String) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:    true,
		Description: description,
		Validators:  validators,
	}
}

func optionalBoolValue(value bool, prior types.Bool) types.Bool {
	if !value && (prior.IsNull() || prior.IsUnknown()) {
		return types.BoolNull()
	}
	return types.BoolValue(value)
}

func optionalInt32Value(value int32, prior types.Int32) types.Int32 {
	if value == 0 && (prior.IsNull() || prior.IsUnknown()) {
		return types.Int32Null()
	}
	return types.Int32Value(value)
}

func optionalFloat64Value(value float64, prior types.Float64) types.Float64 {
	if value == 0 && (prior.IsNull() || prior.IsUnknown()) {
		return types.Float64Null()
	}
	return types.Float64Value(value)
}

func expandDataProtectionPolicyProperties(
	ctx context.Context,
	object types.Object,
	diags *diag.Diagnostics,
) *models.PolicymanagerPolicyProperties {
	if object.IsNull() || object.IsUnknown() {
		return nil
	}

	var tfProperties dataProtectionPolicyPropertiesModel
	diags.Append(object.As(ctx, &tfProperties, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	properties := &models.PolicymanagerPolicyProperties{
		Classifications:         flex.ExpandSetAs[string](ctx, tfProperties.Classifications, diags),
		EnableContentInspection: tfProperties.EnableContentInspection.ValueBoolPointer(),
	}

	if !tfProperties.AllowNotifications.IsNull() && !tfProperties.AllowNotifications.IsUnknown() {
		properties.AllowNotifications = tfProperties.AllowNotifications.ValueString()
	}
	if !tfProperties.BeExcludeDomains.IsNull() && !tfProperties.BeExcludeDomains.IsUnknown() {
		properties.BeExcludeDomains = tfProperties.BeExcludeDomains.ValueString()
	}
	if !tfProperties.BePasteClipboardMaxSize.IsNull() && !tfProperties.BePasteClipboardMaxSize.IsUnknown() {
		properties.BePasteClipboardMaxSize = tfProperties.BePasteClipboardMaxSize.ValueFloat64()
	}
	if !tfProperties.BePasteClipboardMaxSizeUnit.IsNull() && !tfProperties.BePasteClipboardMaxSizeUnit.IsUnknown() {
		properties.BePasteClipboardMaxSizeUnit = tfProperties.BePasteClipboardMaxSizeUnit.ValueString()
	}
	if !tfProperties.BePasteClipboardMinSize.IsNull() && !tfProperties.BePasteClipboardMinSize.IsUnknown() {
		properties.BePasteClipboardMinSize = tfProperties.BePasteClipboardMinSize.ValueFloat64()
	}
	if !tfProperties.BePasteClipboardMinSizeUnit.IsNull() && !tfProperties.BePasteClipboardMinSizeUnit.IsUnknown() {
		properties.BePasteClipboardMinSizeUnit = tfProperties.BePasteClipboardMinSizeUnit.ValueString()
	}
	if !tfProperties.BePasteClipboardOverSizeBehaviourBlock.IsNull() && !tfProperties.BePasteClipboardOverSizeBehaviourBlock.IsUnknown() {
		properties.BePasteClipboardOverSizeBehaviourBlock = tfProperties.BePasteClipboardOverSizeBehaviourBlock.ValueBool()
	}
	if !tfProperties.BePasteTimeoutDurationMilliseconds.IsNull() && !tfProperties.BePasteTimeoutDurationMilliseconds.IsUnknown() {
		properties.BePasteTimeoutDurationMilliseconds = tfProperties.BePasteTimeoutDurationMilliseconds.ValueInt32()
	}
	if !tfProperties.BePasteTimeoutResponse.IsNull() && !tfProperties.BePasteTimeoutResponse.IsUnknown() {
		properties.BePasteTimeoutResponse = tfProperties.BePasteTimeoutResponse.ValueString()
	}
	if !tfProperties.BeSplashCustomMessage.IsNull() && !tfProperties.BeSplashCustomMessage.IsUnknown() {
		properties.BeSplashCustomMessage = tfProperties.BeSplashCustomMessage.ValueString()
	}
	if !tfProperties.BeSplashEnabled.IsNull() && !tfProperties.BeSplashEnabled.IsUnknown() {
		properties.BeSplashEnabled = tfProperties.BeSplashEnabled.ValueBool()
	}
	if !tfProperties.BeSplashMessageSource.IsNull() && !tfProperties.BeSplashMessageSource.IsUnknown() {
		properties.BeSplashMessageSource = tfProperties.BeSplashMessageSource.ValueString()
	}
	if !tfProperties.BeUploadTimeoutDurationSeconds.IsNull() && !tfProperties.BeUploadTimeoutDurationSeconds.IsUnknown() {
		properties.BeUploadTimeoutDurationSeconds = tfProperties.BeUploadTimeoutDurationSeconds.ValueInt32()
	}
	if !tfProperties.BeUploadTimeoutResponse.IsNull() && !tfProperties.BeUploadTimeoutResponse.IsUnknown() {
		properties.BeUploadTimeoutResponse = tfProperties.BeUploadTimeoutResponse.ValueString()
	}
	if !tfProperties.BlockAllDataAccess.IsNull() && !tfProperties.BlockAllDataAccess.IsUnknown() {
		properties.BlockAllDataAccess = tfProperties.BlockAllDataAccess.ValueBool()
	}
	if !tfProperties.BlockNotifications.IsNull() && !tfProperties.BlockNotifications.IsUnknown() {
		properties.BlockNotifications = tfProperties.BlockNotifications.ValueString()
	}
	if !tfProperties.BrowsersWithoutActiveExtension.IsNull() && !tfProperties.BrowsersWithoutActiveExtension.IsUnknown() {
		properties.BrowsersWithoutActiveExtension = tfProperties.BrowsersWithoutActiveExtension.ValueString()
	}
	if !tfProperties.CustomAllowNotification.IsNull() && !tfProperties.CustomAllowNotification.IsUnknown() {
		properties.CustomAllowNotification = tfProperties.CustomAllowNotification.ValueString()
	}
	if !tfProperties.CustomBlockNotification.IsNull() && !tfProperties.CustomBlockNotification.IsUnknown() {
		properties.CustomBlockNotification = tfProperties.CustomBlockNotification.ValueString()
	}
	if !tfProperties.EnableClipboardInspection.IsNull() && !tfProperties.EnableClipboardInspection.IsUnknown() {
		properties.EnableClipboardInspection = tfProperties.EnableClipboardInspection.ValueBool()
	}
	if !tfProperties.EnableContextInspection.IsNull() && !tfProperties.EnableContextInspection.IsUnknown() {
		properties.EnableContextInspection = tfProperties.EnableContextInspection.ValueBool()
	}
	if !tfProperties.EnableEndUserNotificationsUnsupportedBrowser.IsNull() && !tfProperties.EnableEndUserNotificationsUnsupportedBrowser.IsUnknown() {
		properties.EnableEndUserNotificationsUnsupportedBrowser = tfProperties.EnableEndUserNotificationsUnsupportedBrowser.ValueBool()
	}
	if !tfProperties.EnableNetworkInspection.IsNull() && !tfProperties.EnableNetworkInspection.IsUnknown() {
		properties.EnableNetworkInspection = tfProperties.EnableNetworkInspection.ValueBool()
	}
	if !tfProperties.EujDialogBoxLogo.IsNull() && !tfProperties.EujDialogBoxLogo.IsUnknown() {
		properties.EujDialogBoxLogo = tfProperties.EujDialogBoxLogo.ValueString()
	}
	if !tfProperties.EujDialogTimeout.IsNull() && !tfProperties.EujDialogTimeout.IsUnknown() {
		properties.EujDialogTimeout = tfProperties.EujDialogTimeout.ValueInt32()
	}
	if !tfProperties.EujRequireAdditionalDetails.IsNull() && !tfProperties.EujRequireAdditionalDetails.IsUnknown() {
		properties.EujRequireAdditionalDetails = tfProperties.EujRequireAdditionalDetails.ValueBool()
	}
	if !tfProperties.EujResponseCacheTimeout.IsNull() && !tfProperties.EujResponseCacheTimeout.IsUnknown() {
		properties.EujResponseCacheTimeout = tfProperties.EujResponseCacheTimeout.ValueInt32()
	}
	if !tfProperties.EvidenceDownloadEnabled.IsNull() && !tfProperties.EvidenceDownloadEnabled.IsUnknown() {
		properties.EvidenceDownloadEnabled = tfProperties.EvidenceDownloadEnabled.ValueBool()
	}
	if !tfProperties.EvidenceDuplicationEnabledDefault.IsNull() && !tfProperties.EvidenceDuplicationEnabledDefault.IsUnknown() {
		properties.EvidenceDuplicationEnabledDefault = tfProperties.EvidenceDuplicationEnabledDefault.ValueBool()
	}
	if !tfProperties.EvidenceEncryptedEnabled.IsNull() && !tfProperties.EvidenceEncryptedEnabled.IsUnknown() {
		properties.EvidenceEncryptedEnabled = tfProperties.EvidenceEncryptedEnabled.ValueBool()
	}
	if !tfProperties.EvidenceStorageFreeDiskPerc.IsNull() && !tfProperties.EvidenceStorageFreeDiskPerc.IsUnknown() {
		properties.EvidenceStorageFreeDiskPerc = tfProperties.EvidenceStorageFreeDiskPerc.ValueFloat64()
	}
	if !tfProperties.EvidenceStorageMaxSize.IsNull() && !tfProperties.EvidenceStorageMaxSize.IsUnknown() {
		properties.EvidenceStorageMaxSize = tfProperties.EvidenceStorageMaxSize.ValueFloat64()
	}
	if !tfProperties.InspectionDepth.IsNull() && !tfProperties.InspectionDepth.IsUnknown() {
		properties.InspectionDepth = tfProperties.InspectionDepth.ValueString()
	}
	if !tfProperties.MaxFileSizeToInspect.IsNull() && !tfProperties.MaxFileSizeToInspect.IsUnknown() {
		properties.MaxFileSizeToInspect = tfProperties.MaxFileSizeToInspect.ValueFloat64()
	}
	if !tfProperties.MaxFileSizeToInspectUnit.IsNull() && !tfProperties.MaxFileSizeToInspectUnit.IsUnknown() {
		properties.MaxFileSizeToInspectUnit = tfProperties.MaxFileSizeToInspectUnit.ValueString()
	}
	if !tfProperties.MinConfidenceLevel.IsNull() && !tfProperties.MinConfidenceLevel.IsUnknown() {
		properties.MinConfidenceLevel = tfProperties.MinConfidenceLevel.ValueString()
	}
	if !tfProperties.NetworkInspectionFilesExceedingSizeLimit.IsNull() && !tfProperties.NetworkInspectionFilesExceedingSizeLimit.IsUnknown() {
		properties.NetworkInspectionFilesExceedingSizeLimit = tfProperties.NetworkInspectionFilesExceedingSizeLimit.ValueString()
	}
	if !tfProperties.SimilarityDetection.IsNull() && !tfProperties.SimilarityDetection.IsUnknown() {
		properties.SimilarityDetection = tfProperties.SimilarityDetection.ValueBool()
	}
	if !tfProperties.SimilarityThreshold.IsNull() && !tfProperties.SimilarityThreshold.IsUnknown() {
		properties.SimilarityThreshold = tfProperties.SimilarityThreshold.ValueString()
	}
	if !tfProperties.UnsupportedBrowsersAction.IsNull() && !tfProperties.UnsupportedBrowsersAction.IsUnknown() {
		properties.UnsupportedBrowsersAction = tfProperties.UnsupportedBrowsersAction.ValueString()
	}

	properties.EujDropdownOptions = expandDataProtectionPolicyEUJDropdownOptions(ctx, tfProperties.EujDropdownOptions, diags)
	properties.EujHeaderText = expandDataProtectionPolicyEUJHeaderText(ctx, tfProperties.EujHeaderText, diags)

	return properties
}

func expandDataProtectionPolicyEUJDropdownOptions(
	ctx context.Context,
	object types.Object,
	diags *diag.Diagnostics,
) *models.PolicymanagerEUJDropdownOptions {
	if object.IsNull() || object.IsUnknown() {
		return nil
	}

	var tfOptions dataProtectionPolicyEUJDropdownOptionsModel
	diags.Append(object.As(ctx, &tfOptions, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	options := flex.ExpandListAs[dataProtectionPolicyEUJOptionModel](ctx, tfOptions.Justifications, diags)
	if diags.HasError() {
		return nil
	}

	justifications := make([]*models.PolicymanagerEUJOption, 0, len(options))
	for _, option := range options {
		justifications = append(justifications, &models.PolicymanagerEUJOption{
			Default:       option.Default.ValueBoolPointer(),
			ID:            option.ID.ValueStringPointer(),
			Justification: option.Justification.ValueStringPointer(),
			Selected:      option.Selected.ValueBoolPointer(),
		})
	}

	return &models.PolicymanagerEUJDropdownOptions{
		Justifications: justifications,
	}
}

func expandDataProtectionPolicyEUJHeaderText(
	ctx context.Context,
	object types.Object,
	diags *diag.Diagnostics,
) *models.PolicymanagerEUJHeaderText {
	if object.IsNull() || object.IsUnknown() {
		return nil
	}

	var tfHeaderText dataProtectionPolicyEUJHeaderTextModel
	diags.Append(object.As(ctx, &tfHeaderText, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	headers := flex.ExpandListAs[dataProtectionPolicyEUJHeaderModel](ctx, tfHeaderText.Headers, diags)
	if diags.HasError() {
		return nil
	}

	headerEntries := make([]*models.PolicymanagerEUJHeader, 0, len(headers))
	for _, header := range headers {
		headerEntries = append(headerEntries, &models.PolicymanagerEUJHeader{
			Default:  header.Default.ValueBoolPointer(),
			Header:   header.Header.ValueStringPointer(),
			Selected: header.Selected.ValueBoolPointer(),
		})
	}

	return &models.PolicymanagerEUJHeaderText{
		Headers: headerEntries,
	}
}

func flattenDataProtectionPolicyProperties(
	ctx context.Context,
	properties *models.PolicymanagerPolicyProperties,
	prior types.Object,
) (types.Object, diag.Diagnostics) {
	if properties == nil {
		return types.ObjectNull(dataProtectionPolicyPropertiesAttrTypes), nil
	}

	var diags diag.Diagnostics
	priorProperties := dataProtectionPolicyPropertiesModel{
		Classifications:    types.SetNull(types.StringType),
		EujDropdownOptions: types.ObjectNull(dataProtectionPolicyEUJDropdownOptionsAttrTypes),
		EujHeaderText:      types.ObjectNull(dataProtectionPolicyEUJHeaderTextAttrTypes),
	}

	if !prior.IsNull() && !prior.IsUnknown() {
		diags.Append(prior.As(ctx, &priorProperties, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return types.ObjectNull(dataProtectionPolicyPropertiesAttrTypes), diags
		}
	}

	classifications, setDiags := flex.FlattenStringValueSet(ctx, properties.Classifications)
	diags.Append(setDiags...)
	if diags.HasError() {
		return types.ObjectNull(dataProtectionPolicyPropertiesAttrTypes), diags
	}

	eujDropdownOptions, dropdownDiags := flattenDataProtectionPolicyEUJDropdownOptions(ctx, properties.EujDropdownOptions)
	diags.Append(dropdownDiags...)
	if diags.HasError() {
		return types.ObjectNull(dataProtectionPolicyPropertiesAttrTypes), diags
	}

	eujHeaderText, headerDiags := flattenDataProtectionPolicyEUJHeaderText(ctx, properties.EujHeaderText)
	diags.Append(headerDiags...)
	if diags.HasError() {
		return types.ObjectNull(dataProtectionPolicyPropertiesAttrTypes), diags
	}

	tfProperties := dataProtectionPolicyPropertiesModel{
		AllowNotifications:                           flex.StringValueToFramework(properties.AllowNotifications),
		BeExcludeDomains:                             flex.StringValueToFramework(properties.BeExcludeDomains),
		BePasteClipboardMaxSize:                      optionalFloat64Value(properties.BePasteClipboardMaxSize, priorProperties.BePasteClipboardMaxSize),
		BePasteClipboardMaxSizeUnit:                  flex.StringValueToFramework(properties.BePasteClipboardMaxSizeUnit),
		BePasteClipboardMinSize:                      optionalFloat64Value(properties.BePasteClipboardMinSize, priorProperties.BePasteClipboardMinSize),
		BePasteClipboardMinSizeUnit:                  flex.StringValueToFramework(properties.BePasteClipboardMinSizeUnit),
		BePasteClipboardOverSizeBehaviourBlock:       optionalBoolValue(properties.BePasteClipboardOverSizeBehaviourBlock, priorProperties.BePasteClipboardOverSizeBehaviourBlock),
		BePasteTimeoutDurationMilliseconds:           optionalInt32Value(properties.BePasteTimeoutDurationMilliseconds, priorProperties.BePasteTimeoutDurationMilliseconds),
		BePasteTimeoutResponse:                       flex.StringValueToFramework(properties.BePasteTimeoutResponse),
		BeSplashCustomMessage:                        flex.StringValueToFramework(properties.BeSplashCustomMessage),
		BeSplashEnabled:                              optionalBoolValue(properties.BeSplashEnabled, priorProperties.BeSplashEnabled),
		BeSplashMessageSource:                        flex.StringValueToFramework(properties.BeSplashMessageSource),
		BeUploadTimeoutDurationSeconds:               optionalInt32Value(properties.BeUploadTimeoutDurationSeconds, priorProperties.BeUploadTimeoutDurationSeconds),
		BeUploadTimeoutResponse:                      flex.StringValueToFramework(properties.BeUploadTimeoutResponse),
		BlockAllDataAccess:                           optionalBoolValue(properties.BlockAllDataAccess, priorProperties.BlockAllDataAccess),
		BlockNotifications:                           flex.StringValueToFramework(properties.BlockNotifications),
		BrowsersWithoutActiveExtension:               flex.StringValueToFramework(properties.BrowsersWithoutActiveExtension),
		Classifications:                              classifications,
		CustomAllowNotification:                      flex.StringValueToFramework(properties.CustomAllowNotification),
		CustomBlockNotification:                      flex.StringValueToFramework(properties.CustomBlockNotification),
		EnableClipboardInspection:                    optionalBoolValue(properties.EnableClipboardInspection, priorProperties.EnableClipboardInspection),
		EnableContentInspection:                      types.BoolPointerValue(properties.EnableContentInspection),
		EnableContextInspection:                      optionalBoolValue(properties.EnableContextInspection, priorProperties.EnableContextInspection),
		EnableEndUserNotificationsUnsupportedBrowser: optionalBoolValue(properties.EnableEndUserNotificationsUnsupportedBrowser, priorProperties.EnableEndUserNotificationsUnsupportedBrowser),
		EnableNetworkInspection:                      optionalBoolValue(properties.EnableNetworkInspection, priorProperties.EnableNetworkInspection),
		EujDialogBoxLogo:                             flex.StringValueToFramework(properties.EujDialogBoxLogo),
		EujDialogTimeout:                             optionalInt32Value(properties.EujDialogTimeout, priorProperties.EujDialogTimeout),
		EujDropdownOptions:                           eujDropdownOptions,
		EujHeaderText:                                eujHeaderText,
		EujRequireAdditionalDetails:                  optionalBoolValue(properties.EujRequireAdditionalDetails, priorProperties.EujRequireAdditionalDetails),
		EujResponseCacheTimeout:                      optionalInt32Value(properties.EujResponseCacheTimeout, priorProperties.EujResponseCacheTimeout),
		EvidenceDownloadEnabled:                      optionalBoolValue(properties.EvidenceDownloadEnabled, priorProperties.EvidenceDownloadEnabled),
		EvidenceDuplicationEnabledDefault:            optionalBoolValue(properties.EvidenceDuplicationEnabledDefault, priorProperties.EvidenceDuplicationEnabledDefault),
		EvidenceEncryptedEnabled:                     optionalBoolValue(properties.EvidenceEncryptedEnabled, priorProperties.EvidenceEncryptedEnabled),
		EvidenceStorageFreeDiskPerc:                  optionalFloat64Value(properties.EvidenceStorageFreeDiskPerc, priorProperties.EvidenceStorageFreeDiskPerc),
		EvidenceStorageMaxSize:                       optionalFloat64Value(properties.EvidenceStorageMaxSize, priorProperties.EvidenceStorageMaxSize),
		InspectionDepth:                              flex.StringValueToFramework(properties.InspectionDepth),
		MaxFileSizeToInspect:                         optionalFloat64Value(properties.MaxFileSizeToInspect, priorProperties.MaxFileSizeToInspect),
		MaxFileSizeToInspectUnit:                     flex.StringValueToFramework(properties.MaxFileSizeToInspectUnit),
		MinConfidenceLevel:                           flex.StringValueToFramework(properties.MinConfidenceLevel),
		NetworkInspectionFilesExceedingSizeLimit:     flex.StringValueToFramework(properties.NetworkInspectionFilesExceedingSizeLimit),
		SimilarityDetection:                          optionalBoolValue(properties.SimilarityDetection, priorProperties.SimilarityDetection),
		SimilarityThreshold:                          flex.StringValueToFramework(properties.SimilarityThreshold),
		UnsupportedBrowsersAction:                    flex.StringValueToFramework(properties.UnsupportedBrowsersAction),
	}

	object, objectDiags := types.ObjectValueFrom(ctx, dataProtectionPolicyPropertiesAttrTypes, tfProperties)
	diags.Append(objectDiags...)
	return object, diags
}

func flattenDataProtectionPolicyEUJDropdownOptions(
	ctx context.Context,
	options *models.PolicymanagerEUJDropdownOptions,
) (types.Object, diag.Diagnostics) {
	if options == nil {
		return types.ObjectNull(dataProtectionPolicyEUJDropdownOptionsAttrTypes), nil
	}

	var diags diag.Diagnostics
	justifications := make([]dataProtectionPolicyEUJOptionModel, 0, len(options.Justifications))
	for _, option := range options.Justifications {
		if option == nil {
			continue
		}

		justifications = append(justifications, dataProtectionPolicyEUJOptionModel{
			Default:       types.BoolPointerValue(option.Default),
			ID:            flex.StringPointerToFramework(option.ID),
			Justification: flex.StringPointerToFramework(option.Justification),
			Selected:      types.BoolPointerValue(option.Selected),
		})
	}

	listValue, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: dataProtectionPolicyEUJOptionAttrTypes}, justifications)
	diags.Append(listDiags...)
	if diags.HasError() {
		return types.ObjectNull(dataProtectionPolicyEUJDropdownOptionsAttrTypes), diags
	}

	object, objectDiags := types.ObjectValueFrom(ctx, dataProtectionPolicyEUJDropdownOptionsAttrTypes, dataProtectionPolicyEUJDropdownOptionsModel{
		Justifications: listValue,
	})
	diags.Append(objectDiags...)
	return object, diags
}

func flattenDataProtectionPolicyEUJHeaderText(
	ctx context.Context,
	headerText *models.PolicymanagerEUJHeaderText,
) (types.Object, diag.Diagnostics) {
	if headerText == nil {
		return types.ObjectNull(dataProtectionPolicyEUJHeaderTextAttrTypes), nil
	}

	var diags diag.Diagnostics
	headers := make([]dataProtectionPolicyEUJHeaderModel, 0, len(headerText.Headers))
	for _, header := range headerText.Headers {
		if header == nil {
			continue
		}

		headers = append(headers, dataProtectionPolicyEUJHeaderModel{
			Default:  types.BoolPointerValue(header.Default),
			Header:   flex.StringPointerToFramework(header.Header),
			Selected: types.BoolPointerValue(header.Selected),
		})
	}

	listValue, listDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: dataProtectionPolicyEUJHeaderAttrTypes}, headers)
	diags.Append(listDiags...)
	if diags.HasError() {
		return types.ObjectNull(dataProtectionPolicyEUJHeaderTextAttrTypes), diags
	}

	object, objectDiags := types.ObjectValueFrom(ctx, dataProtectionPolicyEUJHeaderTextAttrTypes, dataProtectionPolicyEUJHeaderTextModel{
		Headers: listValue,
	})
	diags.Append(objectDiags...)
	return object, diags
}

func encodeDataProtectionPolicySweepID(platformName, id string) string {
	return fmt.Sprintf("%s:%s", platformName, id)
}

func decodeDataProtectionPolicySweepID(resourceID string) (string, string, error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid data protection policy sweeper id %q", resourceID)
	}
	return parts[0], parts[1], nil
}

func dataProtectionPolicyPayloadDiagnostic(
	operation tferrors.Operation,
	payloadErrors []*models.PolicymanagerError,
) diag.Diagnostic {
	if len(payloadErrors) == 0 {
		return nil
	}

	var messages []string
	for _, payloadError := range payloadErrors {
		if payloadError == nil {
			continue
		}

		if payloadError.Code != nil && *payloadError.Code == 404 {
			detail := ""
			if payloadError.Message != nil {
				detail = *payloadError.Message
			}
			return tferrors.NewNotFoundError(detail)
		}

		if payloadError.Message != nil && *payloadError.Message != "" {
			messages = append(messages, *payloadError.Message)
		}
	}

	if len(messages) == 0 {
		return nil
	}

	return tferrors.NewOperationError(operation, fmt.Errorf("%s", strings.Join(messages, "; ")))
}
