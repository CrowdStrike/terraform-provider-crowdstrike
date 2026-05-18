package devicecontrolpolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &deviceControlPolicyResource{}
	_ resource.ResourceWithConfigure      = &deviceControlPolicyResource{}
	_ resource.ResourceWithImportState    = &deviceControlPolicyResource{}
	_ resource.ResourceWithValidateConfig = &deviceControlPolicyResource{}
)

var (
	documentationSection        string = "Device Control"
	resourceMarkdownDescription string = "Manages CrowdStrike Falcon Device Control policies that control USB device access on endpoints. Device Control policies determine enforcement mode, USB class-level actions, and per-device exceptions."
)

func NewDeviceControlPolicyResource() resource.Resource {
	return &deviceControlPolicyResource{}
}

type deviceControlPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// Top-level resource model.
type deviceControlPolicyResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	PlatformName         types.String `tfsdk:"platform_name"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	HostGroups           types.Set    `tfsdk:"host_groups"`
	EnforcementMode      types.String `tfsdk:"enforcement_mode"`
	EndUserNotification  types.String `tfsdk:"end_user_notification"`
	EnhancedFileMetadata types.Bool   `tfsdk:"enhanced_file_metadata"`
	CustomNotifications  types.List   `tfsdk:"custom_notifications"`
	Classes              types.List   `tfsdk:"classes"`
	LastUpdated          types.String `tfsdk:"last_updated"`
}

// Nested model for custom_notifications.
type customNotificationsModel struct {
	BlockedNotification    types.List `tfsdk:"blocked_notification"`
	RestrictedNotification types.List `tfsdk:"restricted_notification"`
}

// Nested model for a single notification.
type notificationModel struct {
	UseCustom     types.Bool   `tfsdk:"use_custom"`
	CustomMessage types.String `tfsdk:"custom_message"`
}

// Nested model for USB class settings.
type usbClassModel struct {
	ID         types.String `tfsdk:"id"`
	Action     types.String `tfsdk:"action"`
	Exceptions types.List   `tfsdk:"exceptions"`
}

// Nested model for USB class exceptions.
type usbExceptionModel struct {
	ID             types.String `tfsdk:"id"`
	Action         types.String `tfsdk:"action"`
	CombinedID     types.String `tfsdk:"combined_id"`
	Description    types.String `tfsdk:"description"`
	ExpirationTime types.String `tfsdk:"expiration_time"`
	ProductID      types.String `tfsdk:"product_id"`
	ProductName    types.String `tfsdk:"product_name"`
	SerialNumber   types.String `tfsdk:"serial_number"`
	VendorID       types.String `tfsdk:"vendor_id"`
	VendorName     types.String `tfsdk:"vendor_name"`
	UseWildcard    types.Bool   `tfsdk:"use_wildcard"`
}

var notificationModelAttrTypes = map[string]attr.Type{
	"use_custom":     types.BoolType,
	"custom_message": types.StringType,
}

var customNotificationsModelAttrTypes = map[string]attr.Type{
	"blocked_notification": types.ListType{
		ElemType: types.ObjectType{AttrTypes: notificationModelAttrTypes},
	},
	"restricted_notification": types.ListType{
		ElemType: types.ObjectType{AttrTypes: notificationModelAttrTypes},
	},
}

var usbExceptionModelAttrTypes = map[string]attr.Type{
	"id":              types.StringType,
	"action":          types.StringType,
	"combined_id":     types.StringType,
	"description":     types.StringType,
	"expiration_time": types.StringType,
	"product_id":      types.StringType,
	"product_name":    types.StringType,
	"serial_number":   types.StringType,
	"vendor_id":       types.StringType,
	"vendor_name":     types.StringType,
	"use_wildcard":    types.BoolType,
}

var usbClassModelAttrTypes = map[string]attr.Type{
	"id":     types.StringType,
	"action": types.StringType,
	"exceptions": types.ListType{
		ElemType: types.ObjectType{AttrTypes: usbExceptionModelAttrTypes},
	},
}

func (r *deviceControlPolicyResource) Configure(
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

func (r *deviceControlPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_device_control_policy"
}

func notificationSchema(description string) schema.ListNestedAttribute {
	return schema.ListNestedAttribute{
		Optional:    true,
		Description: description,
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
		},
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"use_custom": schema.BoolAttribute{
					Required:    true,
					Description: "Whether to use a custom notification message instead of the default.",
				},
				"custom_message": schema.StringAttribute{
					Optional:    true,
					Description: "Custom notification message displayed to the end user. Maximum 256 characters.",
					Validators: []validator.String{
						fwvalidators.StringNotWhitespace(),
						stringvalidator.LengthAtMost(256),
					},
				},
			},
		},
	}
}

func (r *deviceControlPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			documentationSection,
			resourceMarkdownDescription,
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the device control policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the device control policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the device control policy.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
				},
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the device control policy. (Windows, Mac, Linux). Changing this value will require replacing the resource.",
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
				Description: "Enable the device control policy.",
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
			"enforcement_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "How the policy is enforced. One of: MONITOR_ONLY, MONITOR_ENFORCE.",
				Default:     stringdefault.StaticString("MONITOR_ONLY"),
				Validators: []validator.String{
					stringvalidator.OneOf("MONITOR_ONLY", "MONITOR_ENFORCE"),
				},
			},
			"end_user_notification": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the end user receives a notification when the policy is violated. One of: SILENT, NOTIFY_USER.",
				Default:     stringdefault.StaticString("SILENT"),
				Validators: []validator.String{
					stringvalidator.OneOf("SILENT", "NOTIFY_USER"),
				},
			},
			"enhanced_file_metadata": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable enhanced file metadata collection on the sensor.",
				Default:     booldefault.StaticBool(false),
			},
			"custom_notifications": schema.ListNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Custom notifications triggered to the end user when the USB policy is violated.",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"blocked_notification":    notificationSchema("Custom notification when a USB device is blocked."),
						"restricted_notification": notificationSchema("Custom notification when a USB device is restricted."),
					},
				},
			},
			"classes": schema.ListNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "List of USB class settings for this policy.",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Required:    true,
							Description: "USB Class identifier. One of: ANY, AUDIO_VIDEO, IMAGING, MASS_STORAGE, MOBILE, PRINTER, WIRELESS.",
							Validators: []validator.String{
								stringvalidator.OneOf("ANY", "AUDIO_VIDEO", "IMAGING", "MASS_STORAGE", "MOBILE", "PRINTER", "WIRELESS"),
							},
						},
						"action": schema.StringAttribute{
							Required:    true,
							Description: "Policy action for this USB class. One of: FULL_ACCESS, BLOCK_ALL, BLOCK_EXECUTE, BLOCK_WRITE_EXECUTE. Note: BLOCK_EXECUTE and BLOCK_WRITE_EXECUTE are only valid for MASS_STORAGE.",
							Validators: []validator.String{
								stringvalidator.OneOf("FULL_ACCESS", "BLOCK_ALL", "BLOCK_EXECUTE", "BLOCK_WRITE_EXECUTE"),
							},
						},
						"exceptions": schema.ListNestedAttribute{
							Optional:    true,
							Description: "Exceptions to the policy action for this USB class.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"id": schema.StringAttribute{
										Computed:    true,
										Optional:    true,
										Description: "Unique identifier for the exception. Computed on creation, optional on update.",
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
										},
									},
									"action": schema.StringAttribute{
										Optional:    true,
										Description: "Action for this exception. One of: FULL_ACCESS, BLOCK_ALL, BLOCK_EXECUTE, BLOCK_WRITE_EXECUTE.",
										Validators: []validator.String{
											stringvalidator.OneOf("FULL_ACCESS", "BLOCK_ALL", "BLOCK_EXECUTE", "BLOCK_WRITE_EXECUTE"),
										},
									},
									"combined_id": schema.StringAttribute{
										Optional:    true,
										Description: "Combined identifier in the format 'vendorID_productID_serialNumber'. Not allowed if use_wildcard is true.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"description": schema.StringAttribute{
										Optional:    true,
										Description: "Description for this exception. Maximum 512 characters.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
											stringvalidator.LengthAtMost(512),
										},
									},
									"expiration_time": schema.StringAttribute{
										Optional:    true,
										Description: "Time to remove the exception (yyyy-mm-ddThh:mm:ssZ UTC format). Must be in the future.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"product_id": schema.StringAttribute{
										Optional:    true,
										Description: "Hexadecimal Product ID for the exception.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"product_name": schema.StringAttribute{
										Optional:    true,
										Description: "Product name for the exception.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"serial_number": schema.StringAttribute{
										Optional:    true,
										Description: "Serial number for the exception.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"vendor_id": schema.StringAttribute{
										Optional:    true,
										Description: "Hexadecimal Vendor ID for the exception.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"vendor_name": schema.StringAttribute{
										Optional:    true,
										Description: "Vendor name for the exception.",
										Validators: []validator.String{
											fwvalidators.StringNotWhitespace(),
										},
									},
									"use_wildcard": schema.BoolAttribute{
										Optional:    true,
										Description: "Whether to use wildcard matching. Not allowed with combined_id.",
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

// wrap converts an API response policy into the Terraform resource model.
// trackedClassIDs limits which USB classes are included in state. Pass nil
// to include all classes (e.g., during import or when classes is unset).
func (m *deviceControlPolicyResourceModel) wrap(
	ctx context.Context,
	policy *models.DeviceControlPolicyV1,
	trackedClassIDs map[string]bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = flex.StringPointerToFramework(policy.ID)
	m.Name = flex.StringPointerToFramework(policy.Name)
	m.Description = flex.StringPointerToFramework(policy.Description)
	m.PlatformName = flex.StringPointerToFramework(policy.PlatformName)
	m.Enabled = types.BoolPointerValue(policy.Enabled)

	hostGroupSet, d := flex.FlattenHostGroupsToSet(ctx, policy.Groups)
	if d.HasError() {
		diags.Append(d...)
		return diags
	}
	m.HostGroups = hostGroupSet

	if policy.Settings != nil {
		m.EnforcementMode = flex.StringPointerToFramework(policy.Settings.EnforcementMode)
		m.EndUserNotification = flex.StringPointerToFramework(policy.Settings.EndUserNotification)
		m.EnhancedFileMetadata = types.BoolPointerValue(policy.Settings.EnhancedFileMetadata)

		// Wrap custom_notifications
		diags.Append(m.wrapCustomNotifications(ctx, policy.Settings.CustomNotifications)...)
		if diags.HasError() {
			return diags
		}

		// Wrap classes — only include classes tracked in the current config/state.
		// The API always returns all 7 USB classes, but users may only manage a
		// subset. Passing trackedClassIDs filters the response to match.
		diags.Append(m.wrapClasses(ctx, policy.Settings.Classes, trackedClassIDs)...)
		if diags.HasError() {
			return diags
		}
	}

	return diags
}

func (m *deviceControlPolicyResourceModel) wrapCustomNotifications(
	ctx context.Context,
	apiNotifications *models.DeviceControlUSBCustomNotifications,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if apiNotifications == nil {
		m.CustomNotifications = types.ListNull(types.ObjectType{AttrTypes: customNotificationsModelAttrTypes})
		return diags
	}

	wrapSingleNotification := func(n *models.DeviceControlUSBCustomNotification) types.List {
		if n == nil {
			return types.ListNull(types.ObjectType{AttrTypes: notificationModelAttrTypes})
		}
		obj, d := types.ObjectValueFrom(ctx, notificationModelAttrTypes, notificationModel{
			UseCustom:     types.BoolPointerValue(n.UseCustom),
			CustomMessage: flex.StringPointerToFramework(n.CustomMessage),
		})
		diags.Append(d...)
		list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: notificationModelAttrTypes}, []attr.Value{obj})
		diags.Append(d...)
		return list
	}

	cn := customNotificationsModel{
		BlockedNotification:    wrapSingleNotification(apiNotifications.BlockedNotification),
		RestrictedNotification: wrapSingleNotification(apiNotifications.RestrictedNotification),
	}

	obj, d := types.ObjectValueFrom(ctx, customNotificationsModelAttrTypes, cn)
	diags.Append(d...)
	list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: customNotificationsModelAttrTypes}, []attr.Value{obj})
	diags.Append(d...)

	m.CustomNotifications = list
	return diags
}

func (m *deviceControlPolicyResourceModel) wrapClasses(
	ctx context.Context,
	apiClasses []*models.DeviceControlUSBClassExceptionsResponse,
	trackedClassIDs map[string]bool,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(apiClasses) == 0 {
		m.Classes = types.ListNull(types.ObjectType{AttrTypes: usbClassModelAttrTypes})
		return diags
	}

	var classValues []attr.Value
	for _, apiClass := range apiClasses {
		if apiClass == nil {
			continue
		}

		// Skip classes not tracked by the user's config
		if trackedClassIDs != nil && !trackedClassIDs[*apiClass.ID] {
			continue
		}

		// Wrap exceptions
		var exceptionList types.List
		if len(apiClass.Exceptions) == 0 {
			exceptionList = types.ListNull(types.ObjectType{AttrTypes: usbExceptionModelAttrTypes})
		} else {
			var exValues []attr.Value
			for _, apiEx := range apiClass.Exceptions {
				if apiEx == nil {
					continue
				}
				ex := usbExceptionModel{
					ID:           flex.StringPointerToFramework(apiEx.ID),
					Action:       flex.StringValueToFramework(apiEx.Action),
					CombinedID:   flex.StringValueToFramework(apiEx.CombinedID),
					Description:  flex.StringValueToFramework(apiEx.Description),
					ProductID:    flex.StringValueToFramework(apiEx.ProductID),
					ProductName:  flex.StringValueToFramework(apiEx.ProductName),
					SerialNumber: flex.StringValueToFramework(apiEx.SerialNumber),
					VendorID:     flex.StringValueToFramework(apiEx.VendorID),
					VendorName:   flex.StringValueToFramework(apiEx.VendorName),
				}

				if apiEx.ExpirationTime.String() != "" && apiEx.ExpirationTime.String() != "0001-01-01T00:00:00.000Z" {
					ex.ExpirationTime = types.StringValue(apiEx.ExpirationTime.String())
				} else {
					ex.ExpirationTime = types.StringNull()
				}

				obj, d := types.ObjectValueFrom(ctx, usbExceptionModelAttrTypes, ex)
				diags.Append(d...)
				exValues = append(exValues, obj)
			}
			if len(exValues) == 0 {
				exceptionList = types.ListNull(types.ObjectType{AttrTypes: usbExceptionModelAttrTypes})
			} else {
				list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: usbExceptionModelAttrTypes}, exValues)
				diags.Append(d...)
				exceptionList = list
			}
		}

		classObj, d := types.ObjectValueFrom(ctx, usbClassModelAttrTypes, usbClassModel{
			ID:         flex.StringPointerToFramework(apiClass.ID),
			Action:     flex.StringPointerToFramework(apiClass.Action),
			Exceptions: exceptionList,
		})
		diags.Append(d...)
		classValues = append(classValues, classObj)
	}

	if len(classValues) == 0 {
		m.Classes = types.ListNull(types.ObjectType{AttrTypes: usbClassModelAttrTypes})
	} else {
		list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: usbClassModelAttrTypes}, classValues)
		diags.Append(d...)
		m.Classes = list
	}

	return diags
}

// trackedClassIDsFromModel extracts the set of USB class IDs the user has
// configured, so that wrap can filter the API response to match.
func trackedClassIDsFromModel(ctx context.Context, classes types.List) map[string]bool {
	if classes.IsNull() || classes.IsUnknown() {
		return nil // nil means "track all classes"
	}
	var classList []usbClassModel
	classes.ElementsAs(ctx, &classList, false) //nolint:errcheck
	if len(classList) == 0 {
		return nil
	}
	ids := make(map[string]bool, len(classList))
	for _, cls := range classList {
		if !cls.ID.IsNull() && !cls.ID.IsUnknown() {
			ids[cls.ID.ValueString()] = true
		}
	}
	return ids
}

// expandSettings builds the API request settings from the Terraform model.
func (m *deviceControlPolicyResourceModel) expandSettings(
	ctx context.Context,
) (*models.DeviceControlSettingsReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	enforcementMode := m.EnforcementMode.ValueString()
	endUserNotification := m.EndUserNotification.ValueString()

	settings := &models.DeviceControlSettingsReqV1{
		EnforcementMode:      &enforcementMode,
		EndUserNotification:  &endUserNotification,
		EnhancedFileMetadata: m.EnhancedFileMetadata.ValueBool(),
		Classes:              []*models.DeviceControlUSBClassExceptionsReqV1{},
		DeleteExceptions:     []string{},
	}

	// Expand custom_notifications
	if !m.CustomNotifications.IsNull() && !m.CustomNotifications.IsUnknown() {
		var cnList []customNotificationsModel
		diags.Append(m.CustomNotifications.ElementsAs(ctx, &cnList, false)...)
		if diags.HasError() {
			return nil, diags
		}
		if len(cnList) > 0 {
			cn := cnList[0]
			apiCN := &models.DeviceControlUSBCustomNotifications{}

			if !cn.BlockedNotification.IsNull() && !cn.BlockedNotification.IsUnknown() {
				var nList []notificationModel
				diags.Append(cn.BlockedNotification.ElementsAs(ctx, &nList, false)...)
				if len(nList) > 0 {
					useCustom := nList[0].UseCustom.ValueBool()
					customMsg := nList[0].CustomMessage.ValueString()
					apiCN.BlockedNotification = &models.DeviceControlUSBCustomNotification{
						UseCustom:     &useCustom,
						CustomMessage: &customMsg,
					}
				}
			}

			if !cn.RestrictedNotification.IsNull() && !cn.RestrictedNotification.IsUnknown() {
				var nList []notificationModel
				diags.Append(cn.RestrictedNotification.ElementsAs(ctx, &nList, false)...)
				if len(nList) > 0 {
					useCustom := nList[0].UseCustom.ValueBool()
					customMsg := nList[0].CustomMessage.ValueString()
					apiCN.RestrictedNotification = &models.DeviceControlUSBCustomNotification{
						UseCustom:     &useCustom,
						CustomMessage: &customMsg,
					}
				}
			}

			settings.CustomNotifications = apiCN
		}
	}

	// Expand classes
	if !m.Classes.IsNull() && !m.Classes.IsUnknown() {
		var classList []usbClassModel
		diags.Append(m.Classes.ElementsAs(ctx, &classList, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, cls := range classList {
			classID := cls.ID.ValueString()
			action := cls.Action.ValueString()
			apiClass := &models.DeviceControlUSBClassExceptionsReqV1{
				ID:         &classID,
				Action:     &action,
				Exceptions: []*models.DeviceControlExceptionReqV1{},
			}

			if !cls.Exceptions.IsNull() && !cls.Exceptions.IsUnknown() {
				var exList []usbExceptionModel
				diags.Append(cls.Exceptions.ElementsAs(ctx, &exList, false)...)
				for _, ex := range exList {
					apiEx := &models.DeviceControlExceptionReqV1{
						ID:           ex.ID.ValueString(),
						Action:       ex.Action.ValueString(),
						CombinedID:   ex.CombinedID.ValueString(),
						Description:  ex.Description.ValueString(),
						ProductID:    ex.ProductID.ValueString(),
						ProductName:  ex.ProductName.ValueString(),
						SerialNumber: ex.SerialNumber.ValueString(),
						VendorID:     ex.VendorID.ValueString(),
						VendorName:   ex.VendorName.ValueString(),
						UseWildcard:  ex.UseWildcard.ValueBool(),
					}
					apiClass.Exceptions = append(apiClass.Exceptions, apiEx)
				}
			}

			settings.Classes = append(settings.Classes, apiClass)
		}
	}

	return settings, diags
}

// computeDeleteExceptions computes the list of exception IDs to delete
// by comparing state exceptions against plan exceptions.
func computeDeleteExceptions(
	ctx context.Context,
	stateClasses types.List,
	planClasses types.List,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if stateClasses.IsNull() || stateClasses.IsUnknown() {
		return nil, diags
	}

	// Build a set of exception IDs in the plan
	planExceptionIDs := map[string]bool{}
	if !planClasses.IsNull() && !planClasses.IsUnknown() {
		var planClassList []usbClassModel
		diags.Append(planClasses.ElementsAs(ctx, &planClassList, false)...)
		for _, cls := range planClassList {
			if !cls.Exceptions.IsNull() && !cls.Exceptions.IsUnknown() {
				var exList []usbExceptionModel
				diags.Append(cls.Exceptions.ElementsAs(ctx, &exList, false)...)
				for _, ex := range exList {
					if !ex.ID.IsNull() && !ex.ID.IsUnknown() && ex.ID.ValueString() != "" {
						planExceptionIDs[ex.ID.ValueString()] = true
					}
				}
			}
		}
	}

	// Find state exception IDs not in plan
	var deleteIDs []string
	var stateClassList []usbClassModel
	diags.Append(stateClasses.ElementsAs(ctx, &stateClassList, false)...)
	for _, cls := range stateClassList {
		if !cls.Exceptions.IsNull() && !cls.Exceptions.IsUnknown() {
			var exList []usbExceptionModel
			diags.Append(cls.Exceptions.ElementsAs(ctx, &exList, false)...)
			for _, ex := range exList {
				if !ex.ID.IsNull() && !ex.ID.IsUnknown() && ex.ID.ValueString() != "" {
					if !planExceptionIDs[ex.ID.ValueString()] {
						deleteIDs = append(deleteIDs, ex.ID.ValueString())
					}
				}
			}
		}
	}

	return deleteIDs, diags
}

func (r *deviceControlPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting device control policy create")

	var plan deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 1: Create the policy (without settings — the API ignores them on create)
	policyParams := device_control_policies.CreateDeviceControlPoliciesParams{
		Context: ctx,
		Body: &models.DeviceControlCreatePoliciesV1{
			Resources: []*models.DeviceControlCreatePolicyReqV1{
				{
					Name:         plan.Name.ValueStringPointer(),
					Description:  plan.Description.ValueString(),
					PlatformName: plan.PlatformName.ValueStringPointer(),
				},
			},
		},
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to create device control policy")
	res, err := r.client.DeviceControlPolicies.CreateDeviceControlPolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopesReadWrite,
			tferrors.WithBadRequestDetail("This could be due to a duplicate name. Verify that no policy with this name already exists."),
		))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	policy := res.Payload.Resources[0]
	tflog.Info(ctx, "Successfully created device control policy", map[string]interface{}{
		"policy_id": *policy.ID,
	})

	plan.ID = types.StringPointerValue(policy.ID)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 2: Update the policy settings (enforcement_mode, classes, etc.)
	settings, diags := plan.expandSettings(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err = r.client.DeviceControlPolicies.UpdateDeviceControlPolicies(
		&device_control_policies.UpdateDeviceControlPoliciesParams{
			Context: ctx,
			Body: &models.DeviceControlUpdatePoliciesReqV1{
				Resources: []*models.DeviceControlUpdatePolicyReqV1{
					{
						ID:       plan.ID.ValueStringPointer(),
						Name:     plan.Name.ValueString(),
						Settings: settings,
					},
				},
			},
		},
	)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	// Step 3: Enable if requested
	if plan.Enabled.ValueBool() {
		diag := r.setPolicyEnabled(ctx, plan.ID.ValueString(), "enable")
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	// Step 4: Attach host groups
	if len(plan.HostGroups.Elements()) > 0 {
		var hostGroupIDs []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &hostGroupIDs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		diag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupIDs, nil)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	// Step 5: Read back the final state from the API
	policy, diags = r.getDeviceControlPolicy(ctx, plan.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy, trackedClassIDsFromModel(ctx, plan.Classes))...)
	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *deviceControlPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting device control policy read")

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Retrieving device control policy", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})

	policy, diags := r.getDeviceControlPolicy(ctx, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, policy, trackedClassIDsFromModel(ctx, state.Classes))...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *deviceControlPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting device control policy update")

	var plan deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, diags := plan.expandSettings(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Compute exceptions to delete
	deleteIDs, diags := computeDeleteExceptions(ctx, state.Classes, plan.Classes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	settings.DeleteExceptions = deleteIDs

	policyParams := device_control_policies.UpdateDeviceControlPoliciesParams{
		Context: ctx,
		Body: &models.DeviceControlUpdatePoliciesReqV1{
			Resources: []*models.DeviceControlUpdatePolicyReqV1{
				{
					ID:          plan.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: plan.Description.ValueString(),
					Settings:    settings,
				},
			},
		},
	}

	res, err := r.client.DeviceControlPolicies.UpdateDeviceControlPolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		actionName := "disable"
		if plan.Enabled.ValueBool() {
			actionName = "enable"
		}

		diag := r.setPolicyEnabled(ctx, plan.ID.ValueString(), actionName)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
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
		diag := r.syncHostGroups(ctx, plan.ID.ValueString(), hostGroupsToAdd, hostGroupsToRemove)
		if diag != nil {
			resp.Diagnostics.Append(diag)
			return
		}
	}

	// Read back the final state from the API
	policy, diags := r.getDeviceControlPolicy(ctx, plan.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, policy, trackedClassIDsFromModel(ctx, plan.Classes))...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *deviceControlPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting device control policy delete")

	var state deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Always try to disable before deletion. The API rejects deleting enabled
	// policies, and after a failed apply the state may not reflect the real
	// enabled status. Disabling an already-disabled policy is harmless.
	tflog.Debug(ctx, "Disabling device control policy before deletion", map[string]interface{}{
		"policy_id": state.ID.ValueString(),
	})

	diag := r.setPolicyEnabled(ctx, state.ID.ValueString(), "disable")
	if diag != nil {
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	_, err := r.client.DeviceControlPolicies.DeleteDeviceControlPolicies(
		&device_control_policies.DeleteDeviceControlPoliciesParams{
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

func (r *deviceControlPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *deviceControlPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate BLOCK_EXECUTE and BLOCK_WRITE_EXECUTE are only used with MASS_STORAGE
	if !config.Classes.IsNull() && !config.Classes.IsUnknown() {
		var classList []usbClassModel
		resp.Diagnostics.Append(config.Classes.ElementsAs(ctx, &classList, false)...)
		for i, cls := range classList {
			action := cls.Action.ValueString()
			classID := cls.ID.ValueString()
			if (action == "BLOCK_EXECUTE" || action == "BLOCK_WRITE_EXECUTE") && classID != "MASS_STORAGE" {
				resp.Diagnostics.AddAttributeError(
					path.Root("classes").AtListIndex(i).AtName("action"),
					"Invalid action for USB class",
					fmt.Sprintf(
						"Action %q is only valid for MASS_STORAGE class, but class ID is %q.",
						action, classID,
					),
				)
			}
		}
	}
}

func (r *deviceControlPolicyResource) setPolicyEnabled(
	ctx context.Context,
	policyID string,
	actionName string,
) diag.Diagnostic {
	_, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
		&device_control_policies.PerformDeviceControlPoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)
	if err != nil {
		return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
	}

	return nil
}

func (r *deviceControlPolicyResource) syncHostGroups(
	ctx context.Context,
	policyID string,
	groupsToAdd []string,
	groupsToRemove []string,
) diag.Diagnostic {
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

		_, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
			&device_control_policies.PerformDeviceControlPoliciesActionParams{
				Context:    ctx,
				ActionName: "add-host-group",
				Body: &models.MsaEntityActionRequestV2{
					Ids:              []string{policyID},
					ActionParameters: actionParams,
				},
			},
		)
		if err != nil {
			return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
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

		_, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(
			&device_control_policies.PerformDeviceControlPoliciesActionParams{
				Context:    ctx,
				ActionName: "remove-host-group",
				Body: &models.MsaEntityActionRequestV2{
					Ids:              []string{policyID},
					ActionParameters: actionParams,
				},
			},
		)
		if err != nil {
			return tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite)
		}
	}

	return nil
}

func (r *deviceControlPolicyResource) getDeviceControlPolicy(
	ctx context.Context,
	policyID string,
) (*models.DeviceControlPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := device_control_policies.GetDeviceControlPoliciesParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	res, err := r.client.DeviceControlPolicies.GetDeviceControlPolicies(&params)
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
