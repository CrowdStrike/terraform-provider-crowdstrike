package ioarulegroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &ioaRuleGroupResource{}
	_ resource.ResourceWithConfigure      = &ioaRuleGroupResource{}
	_ resource.ResourceWithImportState    = &ioaRuleGroupResource{}
	_ resource.ResourceWithValidateConfig = &ioaRuleGroupResource{}
)

func invertMap[K, V comparable](m map[K]V) map[V]K {
	inv := make(map[V]K, len(m))
	for k, v := range m {
		inv[v] = k
	}
	return inv
}

func invertNestedMap[K, V comparable](m map[K]map[V]K) map[K]map[K]V {
	inv := make(map[K]map[K]V, len(m))
	for outerKey, inner := range m {
		inv[outerKey] = invertMap(inner)
	}
	return inv
}

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Custom IOA Rules",
		Read:  true,
		Write: true,
	},
}

var ruleTypeIDMap = map[string]map[string]string{
	"Windows": {
		"Process Creation":   "1",
		"File Creation":      "2",
		"Network Connection": "9",
		"Domain Name":        "11",
	},
	"Linux": {
		"Process Creation":   "12",
		"File Creation":      "13",
		"Network Connection": "17",
		"Domain Name":        "15",
	},
	"Mac": {
		"Process Creation":   "5",
		"File Creation":      "6",
		"Network Connection": "10",
		"Domain Name":        "16",
	},
}

var ruleTypeNameMap = invertNestedMap(ruleTypeIDMap)

var dispositionMap = map[string]int32{
	"Monitor":      10,
	"Detect":       20,
	"Kill Process": 30,
}

var dispositionNameMap = invertMap(dispositionMap)

var platformToAPI = map[string]string{
	"Windows": "windows",
	"Linux":   "linux",
	"Mac":     "mac",
}

var platformFromAPI = invertMap(platformToAPI)

func normalizePlatform(platform string) string {
	if v, ok := platformFromAPI[strings.ToLower(platform)]; ok {
		return v
	}
	return platform
}

var fieldNameToAPI = map[string]string{
	"grandparent_image_filename": "GrandparentImageFilename",
	"grandparent_command_line":   "GrandparentCommandLine",
	"parent_image_filename":      "ParentImageFilename",
	"parent_command_line":        "ParentCommandLine",
	"image_filename":             "ImageFilename",
	"command_line":               "CommandLine",
	"file_path":                  "FilePath",
	"file_type":                  "FileType",
	"remote_ip_address":          "RemoteIPAddress",
	"remote_port":                "RemotePort",
	"connection_type":            "ConnectionType",
	"domain_name":                "DomainName",
}

var fieldNameFromAPI = invertMap(fieldNameToAPI)

var fileTypeLabelMap = map[string]string{
	"PE":     "PE",
	"PDF":    "Pdf",
	"OLE":    "Object Linking and Embedding",
	"RTF":    "Rich Text Format",
	"ZIP":    "Zip Archive",
	"JAR":    "Java archive",
	"OOXML":  "Office Open XML",
	"DOCX":   "Microsoft Word",
	"XLSX":   "Microsoft Excel",
	"PPTX":   "Microsoft Powerpoint",
	"VSDX":   "Microsoft Visio",
	"RAR":    "RAR Archive format",
	"DMP":    "Memory Dump",
	"7ZIP":   "7-Zip Archive format",
	"DWG":    "2- and 3-D Drawings",
	"IDW":    "Image file format for Autodesk",
	"DXF":    "CAD file format for Autodesk",
	"SLD":    "SLiDe format for AutoCAD",
	"CAB":    "Cab file format",
	"MACHO":  "Binary executable format",
	"TAR":    "TAR Archive format",
	"XAR":    "XAR Archive format",
	"BZIP2":  "BZip2 Archive format",
	"SCRIPT": "Script file",
	"ESE":    "Database file format",
	"ARC":    "ARC Archive format",
	"ARJ":    "ARJ Archive format",
	"BMP":    "Bitmap image format",
	"CRX":    "CRX Chrome Extension file",
	"DEB":    "Debian Package",
	"EARC":   "Email Archive format",
	"EML":    "Email file format",
	"GIF":    "GIF image format",
	"HIVE":   "Registry Hive",
	"JCLASS": "Java Class",
	"JPG":    "JPEG image format",
	"LNK":    "LNK file format",
	"MSI":    "Microsoft Software Installer",
	"PNG":    "PNG image format",
	"PYTHON": "Python script",
	"RPM":    "Red Hat Package",
	"TIFF":   "TIFF image format",
	"VDI":    "Virtual Disk Image",
	"VMDK":   "Virtual Machine Disk Format",
	"OTHER":  "Anything else",
}

var connectionTypeLabelMap = map[string]string{
	"ICMP": "ICMP",
	"TCP":  "TCP",
	"UDP":  "UDP",
}

var setFieldLabelMaps = map[string]map[string]string{
	"file_type":       fileTypeLabelMap,
	"connection_type": connectionTypeLabelMap,
}

func NewIOARuleGroupResource() resource.Resource {
	return &ioaRuleGroupResource{}
}

type ioaRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type ioaRuleGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Platform    types.String `tfsdk:"platform"`
	Description types.String `tfsdk:"description"`
	Comment     types.String `tfsdk:"comment"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	CreatedBy   types.String `tfsdk:"created_by"`
	CreatedOn   types.String `tfsdk:"created_on"`
	ModifiedBy  types.String `tfsdk:"modified_by"`
	ModifiedOn  types.String `tfsdk:"modified_on"`
	CommittedOn types.String `tfsdk:"committed_on"`
	CID         types.String `tfsdk:"cid"`
	Deleted     types.Bool   `tfsdk:"deleted"`
	Rules       types.List   `tfsdk:"rules"`
}

type ioaRuleModel struct {
	InstanceID               types.String `tfsdk:"instance_id"`
	Name                     types.String `tfsdk:"name"`
	Description              types.String `tfsdk:"description"`
	Comment                  types.String `tfsdk:"comment"`
	PatternSeverity          types.String `tfsdk:"pattern_severity"`
	Type                     types.String `tfsdk:"type"`
	Action                   types.String `tfsdk:"action"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	GrandparentImageFilename types.Object `tfsdk:"grandparent_image_filename"`
	GrandparentCommandLine   types.Object `tfsdk:"grandparent_command_line"`
	ParentImageFilename      types.Object `tfsdk:"parent_image_filename"`
	ParentCommandLine        types.Object `tfsdk:"parent_command_line"`
	ImageFilename            types.Object `tfsdk:"image_filename"`
	CommandLine              types.Object `tfsdk:"command_line"`
	FilePath                 types.Object `tfsdk:"file_path"`
	FileType                 types.Set    `tfsdk:"file_type"`
	RemoteIPAddress          types.Object `tfsdk:"remote_ip_address"`
	RemotePort               types.Object `tfsdk:"remote_port"`
	ConnectionType           types.Set    `tfsdk:"connection_type"`
	DomainName               types.Object `tfsdk:"domain_name"`
}

type excludableField struct {
	Include types.String `tfsdk:"include"`
	Exclude types.String `tfsdk:"exclude"`
}

var excludableFieldAttrTypes = map[string]attr.Type{
	"include": types.StringType,
	"exclude": types.StringType,
}

var excludableFieldNames = []string{
	"grandparent_image_filename",
	"grandparent_command_line",
	"parent_image_filename",
	"parent_command_line",
	"image_filename",
	"command_line",
	"file_path",
	"remote_ip_address",
	"remote_port",
	"domain_name",
}

type namedObjectField struct {
	name  string
	value types.Object
}

func (r ioaRuleModel) excludableFields() []namedObjectField {
	return []namedObjectField{
		{"grandparent_image_filename", r.GrandparentImageFilename},
		{"grandparent_command_line", r.GrandparentCommandLine},
		{"parent_image_filename", r.ParentImageFilename},
		{"parent_command_line", r.ParentCommandLine},
		{"image_filename", r.ImageFilename},
		{"command_line", r.CommandLine},
		{"file_path", r.FilePath},
		{"remote_ip_address", r.RemoteIPAddress},
		{"remote_port", r.RemotePort},
		{"domain_name", r.DomainName},
	}
}

func (r ioaRuleModel) hasNonWildcardInclude(ctx context.Context, diags *diag.Diagnostics) bool {
	for _, f := range r.excludableFields() {
		if !utils.IsKnown(f.value) {
			continue
		}
		var ef excludableField
		diags.Append(f.value.As(ctx, &ef, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return false
		}

		include := ef.Include.ValueString()
		if include != "" && include != ".*" {
			return true
		}
	}

	for _, sf := range []types.Set{r.FileType, r.ConnectionType} {
		if utils.IsKnown(sf) && len(sf.Elements()) > 0 {
			return true
		}
	}

	return false
}

func (r *ioaRuleGroupResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

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

	r.client = config.Client
}

func (r *ioaRuleGroupResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ioa_rule_group"
}

func excludableFieldSchema(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:    true,
		Computed:    true,
		Description: description,
		Attributes: map[string]schema.Attribute{
			"include": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Regex pattern for inclusion.",
			},
			"exclude": schema.StringAttribute{
				Optional:    true,
				Description: "Regex pattern for exclusion.",
			},
		},
	}
}

func (r *ioaRuleGroupResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Endpoint Security",
			"Manages IOA (Indicator of Attack) rule groups in CrowdStrike Falcon. Rule groups contain custom IOA rules that define detection logic for suspicious activities based on process creation, file creation, network connections, and domain name patterns.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the IOA rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the IOA rule group.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "The platform for the IOA rule group. One of: `Windows`, `Linux`, `Mac`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("Windows", "Linux", "Mac"),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the IOA rule group.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "The comment stored in audit logs when making changes to the IOA rule group.",
				Validators: []validator.String{
					validators.StringNotWhitespace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the IOA rule group is enabled.",
				Default:     booldefault.StaticBool(false),
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The user who created the rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_on": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "The user who last modified the rule group.",
			},
			"modified_on": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was last modified.",
			},
			"committed_on": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was committed.",
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "The customer ID associated with the rule group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule group has been marked as deleted.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Ordered list of IOA rules within this rule group.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"instance_id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique instance ID of the rule.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "The name of the IOA rule.",
							Validators: []validator.String{
								validators.StringNotWhitespace(),
							},
						},
						"description": schema.StringAttribute{
							Required:    true,
							Description: "The description of the IOA rule.",
							Validators: []validator.String{
								validators.StringNotWhitespace(),
							},
						},
						"comment": schema.StringAttribute{
							Required:    true,
							Description: "The comment stored in audit logs when making changes to the IOA rule group rule.",
							Validators: []validator.String{
								validators.StringNotWhitespace(),
							},
						},
						"pattern_severity": schema.StringAttribute{
							Required:    true,
							Description: "The severity of the pattern.",
							Validators: []validator.String{
								stringvalidator.OneOf("critical", "high", "medium", "low", "informational"),
							},
						},
						"type": schema.StringAttribute{
							Required:    true,
							Description: "The rule type.",
							Validators: []validator.String{
								stringvalidator.OneOf("Process Creation", "File Creation", "Network Connection", "Domain Name"),
							},
						},
						"action": schema.StringAttribute{
							Required:    true,
							Description: "The action to take when the rule triggers.",
							Validators: []validator.String{
								stringvalidator.OneOf("Monitor", "Detect", "Kill Process"),
							},
						},
						"enabled": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Whether the rule is enabled.",
							Default:     booldefault.StaticBool(false),
						},
						"grandparent_image_filename": excludableFieldSchema("Grandparent image filename match criteria."),
						"grandparent_command_line":   excludableFieldSchema("Grandparent command line match criteria."),
						"parent_image_filename":      excludableFieldSchema("Parent image filename match criteria."),
						"parent_command_line":        excludableFieldSchema("Parent command line match criteria."),
						"image_filename":             excludableFieldSchema("Image filename match criteria."),
						"command_line":               excludableFieldSchema("Command line match criteria."),
						"file_path":                  excludableFieldSchema("File path match criteria. Only valid for File Creation rules."),
						"file_type": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "File types to match. Only valid for File Creation rules.",
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(
									stringvalidator.OneOf("7ZIP", "ARC", "ARJ", "BMP", "BZIP2", "CAB", "CRX", "DEB", "DMP", "DOCX", "DWG", "DXF", "EARC", "EML", "ESE", "GIF", "HIVE", "IDW", "JAR", "JCLASS", "JPG", "LNK", "MACHO", "MSI", "OLE", "OOXML", "PDF", "PE", "PNG", "PPTX", "PYTHON", "RAR", "RPM", "RTF", "SCRIPT", "SLD", "TAR", "TIFF", "VDI", "VMDK", "VSDX", "XAR", "XLSX", "ZIP", "OTHER"),
								),
							},
						},
						"remote_ip_address": excludableFieldSchema("Remote IP address match criteria. Only valid for Network Connection rules."),
						"remote_port":       excludableFieldSchema("Remote port match criteria. Only valid for Network Connection rules."),
						"connection_type": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Connection types to match. Only valid for Network Connection rules.",
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(
									stringvalidator.OneOf("ICMP", "TCP", "UDP"),
								),
							},
						},
						"domain_name": excludableFieldSchema("Domain name match criteria. Only valid for Domain Name rules."),
					},
				},
			},
		},
	}
}

func (m *ioaRuleGroupResourceModel) wrap(
	ctx context.Context,
	group *models.APIRuleGroupV1,
	platform string,
	ruleOrder []string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(group.ID)
	m.Name = types.StringPointerValue(group.Name)
	if group.Platform != nil {
		m.Platform = types.StringValue(normalizePlatform(*group.Platform))
	}
	m.Description = flex.StringPointerToFramework(group.Description)
	m.Enabled = types.BoolPointerValue(group.Enabled)
	m.CreatedBy = types.StringPointerValue(group.CreatedBy)
	m.ModifiedBy = types.StringPointerValue(group.ModifiedBy)
	m.CID = types.StringPointerValue(group.CustomerID)
	m.Deleted = types.BoolPointerValue(group.Deleted)

	if group.CreatedOn != nil {
		m.CreatedOn = types.StringValue(group.CreatedOn.String())
	}
	if group.ModifiedOn != nil {
		m.ModifiedOn = types.StringValue(group.ModifiedOn.String())
	}
	if group.CommittedOn != nil {
		m.CommittedOn = types.StringValue(group.CommittedOn.String())
	}

	rules, d := wrapRules(ctx, group.Rules, platform, ruleOrder)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	m.Rules = rules

	return diags
}

func wrapRules(
	ctx context.Context,
	apiRules []*models.APIRuleV1,
	platform string,
	ruleOrder []string,
) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics

	ruleAttrTypes := ruleObjectAttrTypes()

	if len(apiRules) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
	}

	if len(ruleOrder) > 0 {
		apiRules = reorderRules(apiRules, ruleOrder)
	}

	ruleObjects := make([]attr.Value, 0, len(apiRules))
	for _, apiRule := range apiRules {
		if apiRule == nil || (apiRule.Deleted != nil && *apiRule.Deleted) {
			continue
		}

		ruleTypeName := ""
		if apiRule.RuletypeID != nil {
			if nameMap, ok := ruleTypeNameMap[platform]; ok {
				if name, found := nameMap[*apiRule.RuletypeID]; found {
					ruleTypeName = name
				} else {
					diags.AddError(
						"Unknown rule type ID",
						fmt.Sprintf("Rule type ID %q for platform %q is not recognized by this provider version.", *apiRule.RuletypeID, platform),
					)
					return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
				}
			}
		}

		actionName := ""
		if apiRule.DispositionID != nil {
			if name, found := dispositionNameMap[*apiRule.DispositionID]; found {
				actionName = name
			} else {
				diags.AddError(
					"Unknown disposition ID",
					fmt.Sprintf("Disposition ID %d is not recognized by this provider version.", *apiRule.DispositionID),
				)
				return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
			}
		}

		ruleAttrs := map[string]attr.Value{
			"instance_id":      types.StringPointerValue(apiRule.InstanceID),
			"name":             types.StringPointerValue(apiRule.Name),
			"description":      types.StringPointerValue(apiRule.Description),
			"comment":          types.StringPointerValue(apiRule.Comment),
			"pattern_severity": types.StringPointerValue(apiRule.PatternSeverity),
			"type":             types.StringValue(ruleTypeName),
			"action":           types.StringValue(actionName),
			"enabled":          types.BoolPointerValue(apiRule.Enabled),
		}

		fieldMap := buildFieldValueMap(apiRule.FieldValues)

		for _, fieldName := range excludableFieldNames {
			val, d := wrapExcludableField(fieldMap, fieldName)
			diags.Append(d...)
			if diags.HasError() {
				return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
			}
			ruleAttrs[fieldName] = val
		}

		fileTypeVal, d := wrapSetField(ctx, fieldMap, "file_type")
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
		}
		ruleAttrs["file_type"] = fileTypeVal

		connTypeVal, d := wrapSetField(ctx, fieldMap, "connection_type")
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
		}
		ruleAttrs["connection_type"] = connTypeVal

		ruleObj, d := types.ObjectValue(ruleAttrTypes, ruleAttrs)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
		}
		ruleObjects = append(ruleObjects, ruleObj)
	}

	if len(ruleObjects) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: ruleAttrTypes}), diags
	}

	ruleList, d := types.ListValue(types.ObjectType{AttrTypes: ruleAttrTypes}, ruleObjects)
	diags.Append(d...)
	return ruleList, diags
}

func ruleObjectAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"instance_id":                types.StringType,
		"name":                       types.StringType,
		"description":                types.StringType,
		"comment":                    types.StringType,
		"pattern_severity":           types.StringType,
		"type":                       types.StringType,
		"action":                     types.StringType,
		"enabled":                    types.BoolType,
		"grandparent_image_filename": types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"grandparent_command_line":   types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"parent_image_filename":      types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"parent_command_line":        types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"image_filename":             types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"command_line":               types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"file_path":                  types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"file_type":                  types.SetType{ElemType: types.StringType},
		"remote_ip_address":          types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"remote_port":                types.ObjectType{AttrTypes: excludableFieldAttrTypes},
		"connection_type":            types.SetType{ElemType: types.StringType},
		"domain_name":                types.ObjectType{AttrTypes: excludableFieldAttrTypes},
	}
}

func reorderRules(apiRules []*models.APIRuleV1, ruleOrder []string) []*models.APIRuleV1 {
	apiRuleMap := indexRulesByInstanceID(apiRules)

	ordered := make([]*models.APIRuleV1, 0, len(apiRules))
	seen := make(map[string]bool)
	for _, id := range ruleOrder {
		if r, ok := apiRuleMap[id]; ok {
			ordered = append(ordered, r)
			seen[id] = true
		}
	}
	for _, r := range apiRules {
		if r != nil && r.InstanceID != nil && !seen[*r.InstanceID] {
			ordered = append(ordered, r)
		}
	}
	return ordered
}

func indexRulesByInstanceID(rules []*models.APIRuleV1) map[string]*models.APIRuleV1 {
	m := make(map[string]*models.APIRuleV1, len(rules))
	for _, rule := range rules {
		if rule != nil && rule.InstanceID != nil {
			m[*rule.InstanceID] = rule
		}
	}
	return m
}

func buildFieldValueMap(fieldValues []*models.DomainFieldValue) map[string]*models.DomainFieldValue {
	m := make(map[string]*models.DomainFieldValue)
	for _, fv := range fieldValues {
		if fv != nil && fv.Name != nil {
			tfName, ok := fieldNameFromAPI[*fv.Name]
			if !ok {
				tfName = *fv.Name
			}
			m[tfName] = fv
		}
	}
	return m
}

func wrapExcludableField(fieldMap map[string]*models.DomainFieldValue, fieldName string) (attr.Value, diag.Diagnostics) {
	fv, ok := fieldMap[fieldName]
	if !ok || fv == nil {
		return types.ObjectNull(excludableFieldAttrTypes), nil
	}

	var includePtr, excludePtr *string
	for _, item := range fv.Values {
		if item == nil || item.Label == nil || item.Value == nil {
			continue
		}
		switch *item.Label {
		case "include":
			includePtr = item.Value
		case "exclude":
			excludePtr = item.Value
		}
	}

	include := flex.StringPointerToFramework(includePtr)
	exclude := flex.StringPointerToFramework(excludePtr)

	if include.IsNull() && exclude.IsNull() {
		return types.ObjectNull(excludableFieldAttrTypes), nil
	}

	obj, d := types.ObjectValue(excludableFieldAttrTypes, map[string]attr.Value{
		"include": include,
		"exclude": exclude,
	})
	return obj, d
}

func wrapSetField(
	ctx context.Context,
	fieldMap map[string]*models.DomainFieldValue,
	fieldName string,
) (attr.Value, diag.Diagnostics) {
	fv, ok := fieldMap[fieldName]
	if !ok || fv == nil {
		return types.SetNull(types.StringType), nil
	}

	var values []string
	for _, item := range fv.Values {
		if item != nil && item.Value != nil {
			values = append(values, *item.Value)
		}
	}

	if len(values) == 0 {
		return types.SetNull(types.StringType), nil
	}

	setVal, d := types.SetValueFrom(ctx, types.StringType, values)
	return setVal, d
}

func expandRuleToFieldValues(ctx context.Context, rule ioaRuleModel) ([]*models.DomainFieldValue, diag.Diagnostics) {
	var diags diag.Diagnostics
	var fieldValues []*models.DomainFieldValue

	for _, f := range rule.excludableFields() {
		if !utils.IsKnown(f.value) {
			continue
		}

		var ef excludableField
		d := f.value.As(ctx, &ef, basetypes.ObjectAsOptions{})
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}

		include := ef.Include.ValueString()
		exclude := ef.Exclude.ValueString()

		fv := expandExcludableField(f.name, include, exclude)
		fieldValues = append(fieldValues, fv)
	}

	setFields := []struct {
		name  string
		value types.Set
	}{
		{"file_type", rule.FileType},
		{"connection_type", rule.ConnectionType},
	}

	for _, f := range setFields {
		if !utils.IsKnown(f.value) {
			continue
		}

		var vals []string
		d := f.value.ElementsAs(ctx, &vals, false)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}

		fv := expandSetToFieldValue(f.name, vals)
		fieldValues = append(fieldValues, fv)
	}

	return fieldValues, diags
}

func expandExcludableField(name, include, exclude string) *models.DomainFieldValue {
	apiName := fieldNameToAPI[name]
	if apiName == "" {
		apiName = name
	}
	fieldType := "excludable"
	includeLabel := "include"
	excludeLabel := "exclude"

	return &models.DomainFieldValue{
		Name:  &apiName,
		Type:  &fieldType,
		Value: &include,
		Values: []*models.DomainValueItem{
			{Label: &includeLabel, Value: &include},
			{Label: &excludeLabel, Value: &exclude},
		},
	}
}

func expandSetToFieldValue(name string, values []string) *models.DomainFieldValue {
	apiName := fieldNameToAPI[name]
	if apiName == "" {
		apiName = name
	}
	fieldType := "set"
	labelMap := setFieldLabelMaps[name]

	items := make([]*models.DomainValueItem, 0, len(values))
	for _, v := range values {
		val := v
		label := v
		if l, ok := labelMap[v]; ok {
			label = l
		}
		items = append(items, &models.DomainValueItem{
			Label: &label,
			Value: &val,
		})
	}

	emptyValue := ""
	return &models.DomainFieldValue{
		Name:   &apiName,
		Type:   &fieldType,
		Value:  &emptyValue,
		Values: items,
	}
}

func (r *ioaRuleGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	comment := plan.Comment.ValueString()
	if comment == "" {
		comment = "Created by Terraform"
	}
	description := plan.Description.ValueString()

	apiPlatform := platformToAPI[plan.Platform.ValueString()]

	createParams := custom_ioa.NewCreateRuleGroupMixin0ParamsWithContext(ctx)
	createParams.Body = &models.APIRuleGroupCreateRequestV1{
		Name:        plan.Name.ValueStringPointer(),
		Platform:    &apiPlatform,
		Description: &description,
		Comment:     &comment,
	}

	tflog.Debug(ctx, "Creating IOA rule group")
	res, err := r.client.CustomIoa.CreateRuleGroupMixin0(createParams)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	group := res.Payload.Resources[0]

	if group.ID == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	groupID := *group.ID

	if group.Version == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}
	version := *group.Version

	tflog.Info(ctx, "Created IOA rule group", map[string]any{
		"id": groupID,
	})

	plan.ID = types.StringValue(groupID)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var orderedInstanceIDs []string

	rules := utils.ListTypeAs[ioaRuleModel](ctx, plan.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(rules) > 0 {
		platform := plan.Platform.ValueString()

		for _, rule := range rules {
			instanceID, newVersion, d := r.createRule(ctx, groupID, rule, platform, version)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			version = newVersion
			if instanceID != "" {
				orderedInstanceIDs = append(orderedInstanceIDs, instanceID)
			}
		}
	}

	if plan.Enabled.ValueBool() {
		_, d := r.enableRuleGroup(ctx, groupID, plan, version)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	group, d := r.readRuleGroup(ctx, groupID)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, group, plan.Platform.ValueString(), orderedInstanceIDs)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ioaRuleGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ruleOrder []string
	stateRules := utils.ListTypeAs[ioaRuleModel](ctx, state.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, r := range stateRules {
		if !r.InstanceID.IsNull() {
			ruleOrder = append(ruleOrder, r.InstanceID.ValueString())
		}
	}

	group, diags := r.readRuleGroup(ctx, state.ID.ValueString())
	if diags.HasError() {
		if tferrors.HasNotFoundError(diags) {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	platform := ""
	if group.Platform != nil {
		platform = normalizePlatform(*group.Platform)
	}

	resp.Diagnostics.Append(state.wrap(ctx, group, platform, ruleOrder)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ioaRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := plan.ID.ValueString()
	platform := plan.Platform.ValueString()

	currentGroup, d := r.readRuleGroup(ctx, groupID)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	version := *currentGroup.Version

	comment := plan.Comment.ValueString()
	if comment == "" {
		comment = "Updated by Terraform"
	}
	description := plan.Description.ValueString()

	updateGroupParams := custom_ioa.NewUpdateRuleGroupMixin0ParamsWithContext(ctx)
	updateGroupParams.Body = &models.APIRuleGroupModifyRequestV1{
		ID:               &groupID,
		Name:             plan.Name.ValueStringPointer(),
		Description:      &description,
		Enabled:          plan.Enabled.ValueBoolPointer(),
		Comment:          &comment,
		RulegroupVersion: &version,
	}

	tflog.Debug(ctx, "Updating IOA rule group", map[string]any{
		"id": groupID,
	})
	updateRes, err := r.client.CustomIoa.UpdateRuleGroupMixin0(updateGroupParams)
	if err != nil {
		resp.Diagnostics.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite),
		)
		return
	}

	if updateRes == nil || updateRes.Payload == nil || len(updateRes.Payload.Resources) == 0 || updateRes.Payload.Resources[0] == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}

	if diag := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateRes.Payload.Errors); diag != nil {
		resp.Diagnostics.Append(diag)
		return
	}

	if updateRes.Payload.Resources[0].Version == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return
	}
	version = *updateRes.Payload.Resources[0].Version

	existingRules := indexRulesByInstanceID(currentGroup.Rules)

	planRules := utils.ListTypeAs[ioaRuleModel](ctx, plan.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	planInstanceIDs := make(map[string]bool)
	for _, rule := range planRules {
		if utils.IsKnown(rule.InstanceID) {
			planInstanceIDs[rule.InstanceID.ValueString()] = true
		}
	}

	var ruleIDsToDelete []string
	for _, rule := range currentGroup.Rules {
		if rule != nil && rule.InstanceID != nil && (rule.Deleted == nil || !*rule.Deleted) {
			if !planInstanceIDs[*rule.InstanceID] {
				ruleIDsToDelete = append(ruleIDsToDelete, *rule.InstanceID)
			}
		}
	}

	if len(ruleIDsToDelete) > 0 {
		deleteRulesParams := custom_ioa.NewDeleteRulesParamsWithContext(ctx)
		deleteRulesParams.RuleGroupID = groupID
		deleteRulesParams.Ids = ruleIDsToDelete
		deleteRulesParams.Comment = &comment

		deleteRes, err := r.client.CustomIoa.DeleteRules(deleteRulesParams)
		if err != nil {
			resp.Diagnostics.Append(
				tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite),
			)
			return
		}

		if deleteRes != nil && deleteRes.Payload != nil {
			if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, deleteRes.Payload.Errors); d != nil {
				resp.Diagnostics.Append(d)
				return
			}
		}

		refreshedGroup, d := r.readRuleGroup(ctx, groupID)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		version = *refreshedGroup.Version
		existingRules = indexRulesByInstanceID(refreshedGroup.Rules)
	}

	var orderedInstanceIDs []string

	for _, planRule := range planRules {
		var existingRule *models.APIRuleV1
		if utils.IsKnown(planRule.InstanceID) {
			existingRule = existingRules[planRule.InstanceID.ValueString()]
		}

		if existingRule != nil {
			newVersion, d := r.updateRule(ctx, groupID, planRule, existingRule, version)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			version = newVersion
			orderedInstanceIDs = append(orderedInstanceIDs, *existingRule.InstanceID)
		} else {
			instanceID, newVersion, d := r.createRule(ctx, groupID, planRule, platform, version)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			version = newVersion
			if instanceID != "" {
				orderedInstanceIDs = append(orderedInstanceIDs, instanceID)
			}
		}
	}

	group, d := r.readRuleGroup(ctx, groupID)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, group, platform, orderedInstanceIDs)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ioaRuleGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()

	deleteParams := custom_ioa.NewDeleteRuleGroupsMixin0ParamsWithContext(ctx)
	deleteParams.Ids = []string{groupID}

	tflog.Debug(ctx, "Deleting IOA rule group", map[string]any{
		"id": groupID,
	})

	_, err := r.client.CustomIoa.DeleteRuleGroupsMixin0(deleteParams)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}
}

func (r *ioaRuleGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *ioaRuleGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !utils.IsKnown(config.Rules) {
		return
	}

	rules := utils.ListTypeAs[ioaRuleModel](ctx, config.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, rule := range rules {
		ruleType := rule.Type.ValueString()
		if ruleType == "" {
			continue
		}

		ruleName := rule.Name.ValueString()

		typeSpecificFields := []struct {
			name     string
			validFor string
			isSet    bool
		}{
			{"file_path", "File Creation", utils.IsKnown(rule.FilePath)},
			{"file_type", "File Creation", utils.IsKnown(rule.FileType)},
			{"remote_ip_address", "Network Connection", utils.IsKnown(rule.RemoteIPAddress)},
			{"remote_port", "Network Connection", utils.IsKnown(rule.RemotePort)},
			{"connection_type", "Network Connection", utils.IsKnown(rule.ConnectionType)},
			{"domain_name", "Domain Name", utils.IsKnown(rule.DomainName)},
		}

		for _, f := range typeSpecificFields {
			if f.isSet && f.validFor != ruleType {
				resp.Diagnostics.AddAttributeError(
					path.Root("rules"),
					fmt.Sprintf("Invalid field for rule type %q", ruleType),
					fmt.Sprintf("Rule %q: %s is only valid for %s rules.", ruleName, f.name, f.validFor),
				)
			}
		}

		hasNonWildcardInclude := rule.hasNonWildcardInclude(ctx, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		if !hasNonWildcardInclude {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules"),
				"At least one non-exclude regex must match something besides .*",
				fmt.Sprintf(
					"Rule %q: At least one field must have an include pattern that is not just '.*'. Having all fields with only wildcard includes would match everything, which is not a valid IOA rule configuration.",
					ruleName,
				),
			)
		}
	}
}

func (r *ioaRuleGroupResource) updateRule(
	ctx context.Context,
	groupID string,
	planRule ioaRuleModel,
	existingRule *models.APIRuleV1,
	version int64,
) (int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	fieldValues, d := expandRuleToFieldValues(ctx, planRule)
	diags.Append(d...)
	if diags.HasError() {
		return version, diags
	}

	dispID, ok := dispositionMap[planRule.Action.ValueString()]
	if !ok {
		diags.AddError(
			"Invalid action",
			fmt.Sprintf("Action %q is not valid.", planRule.Action.ValueString()),
		)
		return version, diags
	}

	ruleComment := planRule.Comment.ValueString()
	ruleName := planRule.Name.ValueString()

	updateRuleParams := custom_ioa.NewUpdateRulesV2ParamsWithContext(ctx)
	updateRuleParams.Body = &models.APIRuleUpdatesRequestV2{
		RulegroupID:      &groupID,
		Comment:          &ruleComment,
		RulegroupVersion: &version,
		RuleUpdates: []*models.APIRuleUpdateV2{
			{
				InstanceID:       existingRule.InstanceID,
				Name:             &ruleName,
				Description:      planRule.Description.ValueStringPointer(),
				PatternSeverity:  planRule.PatternSeverity.ValueStringPointer(),
				DispositionID:    &dispID,
				FieldValues:      fieldValues,
				Enabled:          planRule.Enabled.ValueBoolPointer(),
				RulegroupVersion: &version,
			},
		},
	}

	updateRuleRes, err := r.client.CustomIoa.UpdateRulesV2(updateRuleParams)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite),
		)
		return version, diags
	}

	if updateRuleRes == nil || updateRuleRes.Payload == nil || len(updateRuleRes.Payload.Resources) == 0 || updateRuleRes.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return version, diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateRuleRes.Payload.Errors); d != nil {
		diags.Append(d)
		return version, diags
	}

	refreshedGroup, d := r.readRuleGroup(ctx, groupID)
	diags.Append(d...)
	if diags.HasError() {
		return version, diags
	}

	return *refreshedGroup.Version, diags
}

func (r *ioaRuleGroupResource) createRule(
	ctx context.Context,
	groupID string,
	rule ioaRuleModel,
	platform string,
	version int64,
) (instanceID string, newVersion int64, diags diag.Diagnostics) {
	fieldValues, d := expandRuleToFieldValues(ctx, rule)
	diags.Append(d...)
	if diags.HasError() {
		return "", version, diags
	}

	ruleTypeID, ok := ruleTypeIDMap[platform][rule.Type.ValueString()]
	if !ok {
		diags.AddError(
			"Invalid rule type",
			fmt.Sprintf("Rule type %q is not valid for platform %q.", rule.Type.ValueString(), platform),
		)
		return "", version, diags
	}

	dispID, ok := dispositionMap[rule.Action.ValueString()]
	if !ok {
		diags.AddError(
			"Invalid action",
			fmt.Sprintf("Action %q is not valid.", rule.Action.ValueString()),
		)
		return "", version, diags
	}

	ruleComment := rule.Comment.ValueString()
	createRuleParams := custom_ioa.NewCreateRuleParamsWithContext(ctx)
	createRuleParams.Body = &models.APIRuleCreateV1{
		RulegroupID:     &groupID,
		Name:            rule.Name.ValueStringPointer(),
		Description:     rule.Description.ValueStringPointer(),
		PatternSeverity: rule.PatternSeverity.ValueStringPointer(),
		RuletypeID:      &ruleTypeID,
		DispositionID:   &dispID,
		FieldValues:     fieldValues,
		Comment:         &ruleComment,
	}

	ruleRes, err := r.client.CustomIoa.CreateRule(createRuleParams)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite),
		)
		return "", version, diags
	}

	if ruleRes == nil || ruleRes.Payload == nil || len(ruleRes.Payload.Resources) == 0 || ruleRes.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return "", version, diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, ruleRes.Payload.Errors); d != nil {
		diags.Append(d)
		return "", version, diags
	}

	createdRule := ruleRes.Payload.Resources[0]

	refreshedGroup, d := r.readRuleGroup(ctx, groupID)
	diags.Append(d...)
	if diags.HasError() {
		return "", version, diags
	}
	version = *refreshedGroup.Version

	if createdRule.InstanceID != nil {
		instanceID = *createdRule.InstanceID
	}

	if rule.Enabled.ValueBool() && (createdRule.Enabled == nil || !*createdRule.Enabled) {
		version, d = r.enableRule(ctx, groupID, createdRule, version)
		diags.Append(d...)
		if diags.HasError() {
			return instanceID, version, diags
		}
	}

	return instanceID, version, diags
}

func (r *ioaRuleGroupResource) readRuleGroup(
	ctx context.Context,
	groupID string,
) (*models.APIRuleGroupV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	getParams := custom_ioa.NewGetRuleGroupsMixin0ParamsWithContext(ctx)
	getParams.Ids = []string{groupID}

	res, err := r.client.CustomIoa.GetRuleGroupsMixin0(getParams)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite),
		)
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

	if res.Payload.Resources[0].Version == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

func (r *ioaRuleGroupResource) enableRule(
	ctx context.Context,
	groupID string,
	rule *models.APIRuleV1,
	version int64,
) (int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	enabled := true
	updateParams := custom_ioa.NewUpdateRulesV2ParamsWithContext(ctx)
	updateParams.Body = &models.APIRuleUpdatesRequestV2{
		RulegroupID:      &groupID,
		Comment:          rule.Comment,
		RulegroupVersion: &version,
		RuleUpdates: []*models.APIRuleUpdateV2{
			{
				InstanceID:       rule.InstanceID,
				Name:             rule.Name,
				Description:      rule.Description,
				PatternSeverity:  rule.PatternSeverity,
				DispositionID:    rule.DispositionID,
				FieldValues:      rule.FieldValues,
				Enabled:          &enabled,
				RulegroupVersion: &version,
			},
		},
	}

	updateRes, err := r.client.CustomIoa.UpdateRulesV2(updateParams)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite),
		)
		return version, diags
	}

	if updateRes == nil || updateRes.Payload == nil || len(updateRes.Payload.Resources) == 0 || updateRes.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return version, diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateRes.Payload.Errors); d != nil {
		diags.Append(d)
		return version, diags
	}

	group, d := r.readRuleGroup(ctx, groupID)
	diags.Append(d...)
	if diags.HasError() {
		return version, diags
	}

	return *group.Version, diags
}

func (r *ioaRuleGroupResource) enableRuleGroup(
	ctx context.Context,
	groupID string,
	plan ioaRuleGroupResourceModel,
	version int64,
) (int64, diag.Diagnostics) {
	var diags diag.Diagnostics

	enabled := true
	comment := plan.Comment.ValueString()
	if comment == "" {
		comment = "Enable rule group via Terraform"
	}
	description := plan.Description.ValueString()

	updateParams := custom_ioa.NewUpdateRuleGroupMixin0ParamsWithContext(ctx)
	updateParams.Body = &models.APIRuleGroupModifyRequestV1{
		ID:               &groupID,
		Name:             plan.Name.ValueStringPointer(),
		Description:      &description,
		Enabled:          &enabled,
		Comment:          &comment,
		RulegroupVersion: &version,
	}

	updateRes, err := r.client.CustomIoa.UpdateRuleGroupMixin0(updateParams)
	if err != nil {
		diags.Append(
			tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite),
		)
		return version, diags
	}

	if updateRes == nil || updateRes.Payload == nil || len(updateRes.Payload.Resources) == 0 || updateRes.Payload.Resources[0] == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return version, diags
	}

	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Update, updateRes.Payload.Errors); d != nil {
		diags.Append(d)
		return version, diags
	}

	if updateRes.Payload.Resources[0].Version == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Update))
		return version, diags
	}

	return *updateRes.Payload.Resources[0].Version, diags
}
