package ioarulegroup

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
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
)

var (
	_ resource.Resource                   = &ioaRuleGroupResource{}
	_ resource.ResourceWithConfigure      = &ioaRuleGroupResource{}
	_ resource.ResourceWithImportState    = &ioaRuleGroupResource{}
	_ resource.ResourceWithValidateConfig = &ioaRuleGroupResource{}
)

func NewIOARuleGroupResource() resource.Resource {
	return &ioaRuleGroupResource{}
}

type ioaRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type ioaRuleGroupResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Platform     types.String `tfsdk:"platform"`
	Description  types.String `tfsdk:"description"`
	Comment      types.String `tfsdk:"comment"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	CreatedBy    types.String `tfsdk:"created_by"`
	CreatedOn    types.String `tfsdk:"created_on"`
	ModifiedBy   types.String `tfsdk:"modified_by"`
	ModifiedOn   types.String `tfsdk:"modified_on"`
	CommittedOn  types.String `tfsdk:"committed_on"`
	CID          types.String `tfsdk:"cid"`
	Deleted      types.Bool   `tfsdk:"deleted"`
	Rules        types.Set    `tfsdk:"rules"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

type ioaRule struct {
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Comment         types.String `tfsdk:"comment"`
	PatternSeverity types.String `tfsdk:"pattern_severity"`
	Type            types.String `tfsdk:"type"`
	Action          types.String `tfsdk:"action"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	ActionLabel     types.String `tfsdk:"action_label"`

	GrandparentImageFilename types.Object `tfsdk:"grandparent_image_filename"`
	GrandparentCommandLine   types.Object `tfsdk:"grandparent_command_line"`
	ParentImageFilename      types.Object `tfsdk:"parent_image_filename"`
	ParentCommandLine        types.Object `tfsdk:"parent_command_line"`
	ImageFilename            types.Object `tfsdk:"image_filename"`
	CommandLine              types.Object `tfsdk:"command_line"`

	FilePath types.Object `tfsdk:"file_path"`
	FileType types.List   `tfsdk:"file_type"`

	RemoteIPAddress types.Object `tfsdk:"remote_ip_address"`
	RemotePort      types.Object `tfsdk:"remote_port"`
	ConnectionType  types.List   `tfsdk:"connection_type"`

	DomainName types.Object `tfsdk:"domain_name"`

	InstanceID types.String `tfsdk:"instance_id"`
}

type excludableField struct {
	Include types.String `tfsdk:"include"`
	Exclude types.String `tfsdk:"exclude"`
}

func (e excludableField) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"include": types.StringType,
		"exclude": types.StringType,
	}
}

func (r ioaRule) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name":              types.StringType,
		"description":       types.StringType,
		"comment":           types.StringType,
		"pattern_severity":  types.StringType,
		"type":              types.StringType,
		"action":            types.StringType,
		"enabled":           types.BoolType,
		"action_label":      types.StringType,
		"grandparent_image_filename": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"grandparent_command_line": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"parent_image_filename": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"parent_command_line": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"image_filename": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"command_line": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"file_path": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"file_type": types.ListType{
			ElemType: types.StringType,
		},
		"remote_ip_address": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"remote_port": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"connection_type": types.ListType{
			ElemType: types.StringType,
		},
		"domain_name": types.ObjectType{
			AttrTypes: excludableField{}.attrTypes(),
		},
		"instance_id": types.StringType,
	}
}

var ruleTypeToID = map[string]map[string]string{
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

var dispositionNameToID = map[string]int32{
	"Monitor":      10,
	"Detect":       20,
	"Kill Process": 30,
}

var dispositionIDToName = map[int32]string{
	10: "Monitor",
	20: "Detect",
	30: "Kill Process",
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
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ioa_rule_group"
}

func (r *ioaRuleGroupResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Custom IOA Rules",
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
					fwvalidators.StringNotWhitespace(),
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
					fwvalidators.StringNotWhitespace(),
				},
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "The comment for the IOA rule group.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
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
			},
			"created_on": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was created.",
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
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule group has been marked as deleted.",
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the rule group was last updated.",
			},
			"rules": schema.SetNestedAttribute{
				Optional:    true,
				Description: "Set of IOA rules within this rule group.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: r.ruleSchema(),
				},
			},
		},
	}
}

func (r *ioaRuleGroupResource) ruleSchema() map[string]schema.Attribute {
	excludableFieldSchema := schema.SingleNestedAttribute{
		Optional:    true,
		Description: "Pattern matching configuration.",
		Attributes: map[string]schema.Attribute{
			"include": schema.StringAttribute{
				Optional:    true,
				Description: "The inclusion regex pattern.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"exclude": schema.StringAttribute{
				Optional:    true,
				Description: "The exclusion regex pattern.",
			},
		},
	}

	return map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Required:    true,
			Description: "The name of the IOA rule.",
			Validators: []validator.String{
				fwvalidators.StringNotWhitespace(),
			},
		},
		"description": schema.StringAttribute{
			Required:    true,
			Description: "The description of the IOA rule.",
			Validators: []validator.String{
				fwvalidators.StringNotWhitespace(),
			},
		},
		"comment": schema.StringAttribute{
			Required:    true,
			Description: "The comment for audit log.",
			Validators: []validator.String{
				fwvalidators.StringNotWhitespace(),
			},
		},
		"pattern_severity": schema.StringAttribute{
			Required:    true,
			Description: "The severity of the pattern. One of: `critical`, `high`, `medium`, `low`, `informational`.",
			Validators: []validator.String{
				stringvalidator.OneOf("critical", "high", "medium", "low", "informational"),
			},
		},
		"type": schema.StringAttribute{
			Required:    true,
			Description: "The rule type. One of: `Process Creation`, `File Creation`, `Network Connection`, `Domain Name`.",
			Validators: []validator.String{
				stringvalidator.OneOf("Process Creation", "File Creation", "Network Connection", "Domain Name"),
			},
		},
		"action": schema.StringAttribute{
			Required:    true,
			Description: "The action to take when the rule triggers. One of: `Monitor`, `Detect`, `Kill Process`.",
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
		"action_label": schema.StringAttribute{
			Computed:    true,
			Description: "The action label returned by the API.",
		},
		"instance_id": schema.StringAttribute{
			Computed:    true,
			Description: "The instance ID of the rule (used internally for updates/deletes).",
		},
		"grandparent_image_filename": excludableFieldSchema,
		"grandparent_command_line":   excludableFieldSchema,
		"parent_image_filename":      excludableFieldSchema,
		"parent_command_line":        excludableFieldSchema,
		"image_filename":             excludableFieldSchema,
		"command_line":               excludableFieldSchema,
		"file_path":                  excludableFieldSchema,
		"file_type": schema.ListAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "File types to match. Only available for File Creation rule type. Valid values: `7ZIP`, `ARC`, `ARJ`, `BMP`, `BZIP2`, `CAB`, `CRX`, `DEB`, `DMP`, `DOCX`, `DWG`, `DXF`, `EARC`, `EML`, `ESE`, `GIF`, `HIVE`, `IDW`, `JAR`, `JCLASS`, `JPG`, `LNK`, `MACHO`, `MSI`, `OLE`, `OOXML`, `PDF`, `PE`, `PNG`, `PPTX`, `PYTHON`, `RAR`, `RPM`, `RTF`, `SCRIPT`, `SLD`, `TAR`, `TIFF`, `VDI`, `VMDK`, `VSDX`, `XAR`, `XLSX`, `ZIP`, `OTHER`.",
			Validators: []validator.List{
				listvalidator.ValueStringsAre(
					stringvalidator.OneOf("7ZIP", "ARC", "ARJ", "BMP", "BZIP2", "CAB", "CRX", "DEB", "DMP", "DOCX", "DWG", "DXF", "EARC", "EML", "ESE", "GIF", "HIVE", "IDW", "JAR", "JCLASS", "JPG", "LNK", "MACHO", "MSI", "OLE", "OOXML", "PDF", "PE", "PNG", "PPTX", "PYTHON", "RAR", "RPM", "RTF", "SCRIPT", "SLD", "TAR", "TIFF", "VDI", "VMDK", "VSDX", "XAR", "XLSX", "ZIP", "OTHER"),
				),
			},
		},
		"remote_ip_address": excludableFieldSchema,
		"remote_port":       excludableFieldSchema,
		"connection_type": schema.ListAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Connection types to match. Only available for Network Connection rule type. Valid values: `ICMP`, `TCP`, `UDP`.",
			Validators: []validator.List{
				listvalidator.ValueStringsAre(
					stringvalidator.OneOf("ICMP", "TCP", "UDP"),
				),
			},
		},
		"domain_name": excludableFieldSchema,
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

	createParams := custom_ioa.NewCreateRuleGroupMixin0Params().WithContext(ctx).WithBody(&models.APIRuleGroupCreateRequestV1{
		Name:        plan.Name.ValueStringPointer(),
		Platform:    plan.Platform.ValueStringPointer(),
		Description: plan.Description.ValueStringPointer(),
		Comment:     plan.Comment.ValueStringPointer(),
	})

	createResp, err := r.client.CustomIoa.CreateRuleGroupMixin0(createParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
		return
	}

	if len(createResp.Payload.Resources) == 0 {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	ruleGroup := createResp.Payload.Resources[0]
	plan.ID = flex.StringPointerToFramework(ruleGroup.ID)

	if !plan.Rules.IsNull() && !plan.Rules.IsUnknown() {
		var rules []ioaRule
		resp.Diagnostics.Append(plan.Rules.ElementsAs(ctx, &rules, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		for _, rule := range rules {
			ruleCreate := r.expandRule(ctx, &rule, plan.ID.ValueString(), plan.Platform.ValueString(), &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}

			createRuleParams := custom_ioa.NewCreateRuleParams().WithContext(ctx).WithBody(ruleCreate)
			_, err := r.client.CustomIoa.CreateRule(createRuleParams)
			if err != nil {
				resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
				return
			}
		}
	}

	state, diags := r.read(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
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

	newState, diags := r.read(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if newState == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	newState.LastUpdated = state.LastUpdated

	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *ioaRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state ioaRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateParams := custom_ioa.NewUpdateRuleGroupMixin0Params().WithContext(ctx).WithBody(&models.APIRuleGroupModifyRequestV1{
		ID:          plan.ID.ValueStringPointer(),
		Name:        plan.Name.ValueStringPointer(),
		Description: plan.Description.ValueStringPointer(),
		Comment:     plan.Comment.ValueStringPointer(),
		Enabled:     plan.Enabled.ValueBoolPointer(),
	})

	_, err := r.client.CustomIoa.UpdateRuleGroupMixin0(updateParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	var planRules, stateRules []ioaRule
	if !plan.Rules.IsNull() && !plan.Rules.IsUnknown() {
		resp.Diagnostics.Append(plan.Rules.ElementsAs(ctx, &planRules, false)...)
	}
	if !state.Rules.IsNull() && !state.Rules.IsUnknown() {
		resp.Diagnostics.Append(state.Rules.ElementsAs(ctx, &stateRules, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	stateRuleMap := make(map[string]ioaRule)
	for _, rule := range stateRules {
		stateRuleMap[rule.Name.ValueString()] = rule
	}

	planRuleMap := make(map[string]ioaRule)
	for _, rule := range planRules {
		planRuleMap[rule.Name.ValueString()] = rule
	}

	for _, planRule := range planRules {
		ruleName := planRule.Name.ValueString()
		if stateRule, exists := stateRuleMap[ruleName]; exists {
			ruleUpdate := r.expandRuleUpdate(ctx, &planRule, stateRule.InstanceID.ValueString(), plan.Platform.ValueString(), &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}

			updateRuleParams := custom_ioa.NewUpdateRulesV2Params().WithContext(ctx).WithBody(&models.APIRuleUpdatesRequestV2{
				RuleUpdates: []*models.APIRuleUpdateV2{ruleUpdate},
			})
			_, err := r.client.CustomIoa.UpdateRulesV2(updateRuleParams)
			if err != nil {
				resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
				return
			}
		} else {
			ruleCreate := r.expandRule(ctx, &planRule, plan.ID.ValueString(), plan.Platform.ValueString(), &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}

			createRuleParams := custom_ioa.NewCreateRuleParams().WithContext(ctx).WithBody(ruleCreate)
			_, err := r.client.CustomIoa.CreateRule(createRuleParams)
			if err != nil {
				resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Create, err, apiScopesReadWrite))
				return
			}
		}
	}

	for _, stateRule := range stateRules {
		ruleName := stateRule.Name.ValueString()
		if _, exists := planRuleMap[ruleName]; !exists {
			deleteParams := custom_ioa.NewDeleteRulesParams().WithContext(ctx).WithIds([]string{stateRule.InstanceID.ValueString()})
			_, err := r.client.CustomIoa.DeleteRules(deleteParams)
			if err != nil {
				resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite))
				return
			}
		}
	}

	newState, diags := r.read(ctx, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	newState.LastUpdated = utils.GenerateUpdateTimestamp()

	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
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

	getRulesParams := custom_ioa.NewGetRulesMixin0Params().WithContext(ctx).WithIds([]string{state.ID.ValueString()})
	getRulesResp, err := r.client.CustomIoa.GetRulesMixin0(getRulesParams)
	if err == nil && getRulesResp.Payload != nil && len(getRulesResp.Payload.Resources) > 0 {
		var ruleIDs []string
		for _, rule := range getRulesResp.Payload.Resources {
			if rule.InstanceID != nil {
				ruleIDs = append(ruleIDs, *rule.InstanceID)
			}
		}

		if len(ruleIDs) > 0 {
			deleteRulesParams := custom_ioa.NewDeleteRulesParams().WithContext(ctx).WithIds(ruleIDs)
			_, err := r.client.CustomIoa.DeleteRules(deleteRulesParams)
			if err != nil {
				resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite))
				return
			}
		}
	}

	deleteParams := custom_ioa.NewDeleteRuleGroupsMixin0Params().WithContext(ctx).WithIds([]string{state.ID.ValueString()})
	_, err = r.client.CustomIoa.DeleteRuleGroupsMixin0(deleteParams)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite))
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

	if config.Rules.IsNull() || config.Rules.IsUnknown() {
		return
	}

	var rules []ioaRule
	resp.Diagnostics.Append(config.Rules.ElementsAs(ctx, &rules, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, rule := range rules {
		ruleType := rule.Type.ValueString()

		hasValidInclude := false
		excludableFields := []struct {
			name  string
			field types.Object
		}{
			{"grandparent_image_filename", rule.GrandparentImageFilename},
			{"grandparent_command_line", rule.GrandparentCommandLine},
			{"parent_image_filename", rule.ParentImageFilename},
			{"parent_command_line", rule.ParentCommandLine},
			{"image_filename", rule.ImageFilename},
			{"command_line", rule.CommandLine},
		}

		if ruleType == "File Creation" {
			excludableFields = append(excludableFields, struct {
				name  string
				field types.Object
			}{"file_path", rule.FilePath})
		}
		if ruleType == "Network Connection" {
			excludableFields = append(excludableFields,
				struct {
					name  string
					field types.Object
				}{"remote_ip_address", rule.RemoteIPAddress},
				struct {
					name  string
					field types.Object
				}{"remote_port", rule.RemotePort},
			)
		}
		if ruleType == "Domain Name" {
			excludableFields = append(excludableFields, struct {
				name  string
				field types.Object
			}{"domain_name", rule.DomainName})
		}

		for _, ef := range excludableFields {
			if ef.field.IsNull() || ef.field.IsUnknown() {
				continue
			}

			var fieldValue excludableField
			resp.Diagnostics.Append(ef.field.As(ctx, &fieldValue, basetypes.ObjectAsOptions{})...)
			if resp.Diagnostics.HasError() {
				return
			}

			if !fieldValue.Include.IsNull() && !fieldValue.Include.IsUnknown() {
				includeVal := fieldValue.Include.ValueString()
				if includeVal != "" && includeVal != ".*" {
					hasValidInclude = true
				}
			}

			if !fieldValue.Exclude.IsNull() && !fieldValue.Exclude.IsUnknown() && fieldValue.Exclude.ValueString() != "" {
				if fieldValue.Include.IsNull() || fieldValue.Include.IsUnknown() || fieldValue.Include.ValueString() == "" {
					resp.Diagnostics.AddAttributeError(
						path.Root("rules"),
						"Invalid Rule Configuration",
						fmt.Sprintf("Rule '%s': field '%s' has an exclude pattern but no include pattern. When using exclude, you must also provide an include pattern.", rule.Name.ValueString(), ef.name),
					)
				}
			}
		}

		if !hasValidInclude {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules"),
				"Invalid Rule Configuration",
				fmt.Sprintf("Rule '%s': At least one non-exclude regex must match something besides \".*\"", rule.Name.ValueString()),
			)
		}

		if ruleType != "File Creation" {
			if (!rule.FilePath.IsNull() && !rule.FilePath.IsUnknown()) || (!rule.FileType.IsNull() && !rule.FileType.IsUnknown()) {
				resp.Diagnostics.AddAttributeError(
					path.Root("rules"),
					"Invalid Field for Rule Type",
					fmt.Sprintf("Rule '%s': file_path and file_type are only valid for File Creation rule type.", rule.Name.ValueString()),
				)
			}
		}

		if ruleType != "Network Connection" {
			if (!rule.RemoteIPAddress.IsNull() && !rule.RemoteIPAddress.IsUnknown()) ||
				(!rule.RemotePort.IsNull() && !rule.RemotePort.IsUnknown()) ||
				(!rule.ConnectionType.IsNull() && !rule.ConnectionType.IsUnknown()) {
				resp.Diagnostics.AddAttributeError(
					path.Root("rules"),
					"Invalid Field for Rule Type",
					fmt.Sprintf("Rule '%s': remote_ip_address, remote_port, and connection_type are only valid for Network Connection rule type.", rule.Name.ValueString()),
				)
			}
		}

		if ruleType != "Domain Name" {
			if !rule.DomainName.IsNull() && !rule.DomainName.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("rules"),
					"Invalid Field for Rule Type",
					fmt.Sprintf("Rule '%s': domain_name is only valid for Domain Name rule type.", rule.Name.ValueString()),
				)
			}
		}
	}
}

func (r *ioaRuleGroupResource) read(ctx context.Context, id string) (*ioaRuleGroupResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	getParams := custom_ioa.NewGetRuleGroupsMixin0Params().WithContext(ctx).WithIds([]string{id})
	getResp, err := r.client.CustomIoa.GetRuleGroupsMixin0(getParams)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite))
		return nil, diags
	}

	if len(getResp.Payload.Resources) == 0 {
		return nil, diags
	}

	ruleGroup := getResp.Payload.Resources[0]
	if ruleGroup.Deleted != nil && *ruleGroup.Deleted {
		return nil, diags
	}

	model := &ioaRuleGroupResourceModel{
		ID:          flex.StringPointerToFramework(ruleGroup.ID),
		Name:        flex.StringPointerToFramework(ruleGroup.Name),
		Platform:    flex.StringPointerToFramework(ruleGroup.Platform),
		Description: flex.StringPointerToFramework(ruleGroup.Description),
		Comment:     flex.StringPointerToFramework(ruleGroup.Comment),
		Enabled:     types.BoolPointerValue(ruleGroup.Enabled),
		CreatedBy:   flex.StringPointerToFramework(ruleGroup.CreatedBy),
		ModifiedBy:  flex.StringPointerToFramework(ruleGroup.ModifiedBy),
		CID:         flex.StringPointerToFramework(ruleGroup.CustomerID),
		Deleted:     types.BoolPointerValue(ruleGroup.Deleted),
	}

	if ruleGroup.CreatedOn != nil {
		model.CreatedOn = types.StringValue(ruleGroup.CreatedOn.String())
	}
	if ruleGroup.ModifiedOn != nil {
		model.ModifiedOn = types.StringValue(ruleGroup.ModifiedOn.String())
	}
	if ruleGroup.CommittedOn != nil {
		model.CommittedOn = types.StringValue(ruleGroup.CommittedOn.String())
	}

	if len(ruleGroup.RuleIds) > 0 {
		getRulesParams := custom_ioa.NewGetRulesMixin0Params().WithContext(ctx).WithIds(ruleGroup.RuleIds)
		getRulesResp, err := r.client.CustomIoa.GetRulesMixin0(getRulesParams)
		if err != nil {
			diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite))
			return nil, diags
		}

		var rules []ioaRule
		for _, apiRule := range getRulesResp.Payload.Resources {
			rule := r.flattenRule(ctx, apiRule, ruleGroup.Platform, &diags)
			if diags.HasError() {
				return nil, diags
			}
			rules = append(rules, rule)
		}

		rulesSet, setDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: ioaRule{}.attrTypes()}, rules)
		diags.Append(setDiags...)
		if diags.HasError() {
			return nil, diags
		}
		model.Rules = rulesSet
	} else {
		model.Rules = types.SetNull(types.ObjectType{AttrTypes: ioaRule{}.attrTypes()})
	}

	return model, diags
}

func (r *ioaRuleGroupResource) expandRule(
	ctx context.Context,
	rule *ioaRule,
	ruleGroupID string,
	platform string,
	diags *diag.Diagnostics,
) *models.APIRuleCreateV1 {
	ruleTypeID := ruleTypeToID[platform][rule.Type.ValueString()]
	dispositionID := dispositionNameToID[rule.Action.ValueString()]

	fieldValues := r.buildFieldValues(ctx, rule, diags)
	if diags.HasError() {
		return nil
	}

	return &models.APIRuleCreateV1{
		Name:            rule.Name.ValueStringPointer(),
		Description:     rule.Description.ValueStringPointer(),
		Comment:         rule.Comment.ValueStringPointer(),
		PatternSeverity: rule.PatternSeverity.ValueStringPointer(),
		RuletypeID:      &ruleTypeID,
		DispositionID:   &dispositionID,
		RulegroupID:     &ruleGroupID,
		FieldValues:     fieldValues,
	}
}

func (r *ioaRuleGroupResource) expandRuleUpdate(
	ctx context.Context,
	rule *ioaRule,
	instanceID string,
	platform string,
	diags *diag.Diagnostics,
) *models.APIRuleUpdateV2 {
	dispositionID := dispositionNameToID[rule.Action.ValueString()]

	fieldValues := r.buildFieldValues(ctx, rule, diags)
	if diags.HasError() {
		return nil
	}

	enabled := rule.Enabled.ValueBool()
	ruleGroupVersion := int64(0)

	return &models.APIRuleUpdateV2{
		InstanceID:       &instanceID,
		Name:             rule.Name.ValueStringPointer(),
		Description:      rule.Description.ValueStringPointer(),
		PatternSeverity:  rule.PatternSeverity.ValueStringPointer(),
		DispositionID:    &dispositionID,
		FieldValues:      fieldValues,
		Enabled:          &enabled,
		RulegroupVersion: &ruleGroupVersion,
	}
}

func (r *ioaRuleGroupResource) buildFieldValues(
	ctx context.Context,
	rule *ioaRule,
	diags *diag.Diagnostics,
) []*models.DomainFieldValue {
	var fieldValues []*models.DomainFieldValue

	fieldMappings := []struct {
		obj  types.Object
		name string
	}{
		{rule.GrandparentImageFilename, "GrandparentImageFilename"},
		{rule.GrandparentCommandLine, "GrandparentCommandLine"},
		{rule.ParentImageFilename, "ParentImageFilename"},
		{rule.ParentCommandLine, "ParentCommandLine"},
		{rule.ImageFilename, "ImageFilename"},
		{rule.CommandLine, "CommandLine"},
		{rule.FilePath, "FilePath"},
		{rule.RemoteIPAddress, "RemoteIPAddress"},
		{rule.RemotePort, "RemotePort"},
		{rule.DomainName, "DomainName"},
	}

	for _, fm := range fieldMappings {
		if fm.obj.IsNull() || fm.obj.IsUnknown() {
			continue
		}

		var field excludableField
		diags.Append(fm.obj.As(ctx, &field, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil
		}

		var values []*models.DomainValueItem
		if !field.Include.IsNull() && !field.Include.IsUnknown() && field.Include.ValueString() != "" {
			includeLabel := "include"
			includeValue := field.Include.ValueString()
			values = append(values, &models.DomainValueItem{
				Label: &includeLabel,
				Value: &includeValue,
			})
		}
		if !field.Exclude.IsNull() && !field.Exclude.IsUnknown() && field.Exclude.ValueString() != "" {
			excludeLabel := "exclude"
			excludeValue := field.Exclude.ValueString()
			values = append(values, &models.DomainValueItem{
				Label: &excludeLabel,
				Value: &excludeValue,
			})
		}

		if len(values) > 0 {
			fieldType := "excludable"
			fieldValues = append(fieldValues, &models.DomainFieldValue{
				Name:   &fm.name,
				Type:   &fieldType,
				Values: values,
			})
		}
	}

	if !rule.FileType.IsNull() && !rule.FileType.IsUnknown() {
		var fileTypes []string
		diags.Append(rule.FileType.ElementsAs(ctx, &fileTypes, false)...)
		if diags.HasError() {
			return nil
		}

		if len(fileTypes) > 0 {
			var values []*models.DomainValueItem
			for _, ft := range fileTypes {
				ftCopy := ft
				values = append(values, &models.DomainValueItem{
					Label: &ftCopy,
					Value: &ftCopy,
				})
			}

			fieldName := "FileType"
			fieldType := "set"
			fieldValues = append(fieldValues, &models.DomainFieldValue{
				Name:   &fieldName,
				Type:   &fieldType,
				Values: values,
			})
		}
	}

	if !rule.ConnectionType.IsNull() && !rule.ConnectionType.IsUnknown() {
		var connectionTypes []string
		diags.Append(rule.ConnectionType.ElementsAs(ctx, &connectionTypes, false)...)
		if diags.HasError() {
			return nil
		}

		if len(connectionTypes) > 0 {
			var values []*models.DomainValueItem
			for _, ct := range connectionTypes {
				ctCopy := ct
				values = append(values, &models.DomainValueItem{
					Label: &ctCopy,
					Value: &ctCopy,
				})
			}

			fieldName := "ConnectionType"
			fieldType := "set"
			fieldValues = append(fieldValues, &models.DomainFieldValue{
				Name:   &fieldName,
				Type:   &fieldType,
				Values: values,
			})
		}
	}

	return fieldValues
}

func (r *ioaRuleGroupResource) flattenRule(
	ctx context.Context,
	apiRule *models.APIRuleV1,
	platform *string,
	diags *diag.Diagnostics,
) ioaRule {
	rule := ioaRule{
		Name:            flex.StringPointerToFramework(apiRule.Name),
		Description:     flex.StringPointerToFramework(apiRule.Description),
		Comment:         flex.StringPointerToFramework(apiRule.Comment),
		PatternSeverity: flex.StringPointerToFramework(apiRule.PatternSeverity),
		Enabled:         types.BoolPointerValue(apiRule.Enabled),
		ActionLabel:     flex.StringPointerToFramework(apiRule.ActionLabel),
		InstanceID:      flex.StringPointerToFramework(apiRule.InstanceID),
	}

	if apiRule.RuletypeID != nil {
		for ruleType, id := range ruleTypeToID[*platform] {
			if id == *apiRule.RuletypeID {
				rule.Type = types.StringValue(ruleType)
				break
			}
		}
	}

	if apiRule.DispositionID != nil {
		if actionName, ok := dispositionIDToName[*apiRule.DispositionID]; ok {
			rule.Action = types.StringValue(actionName)
		}
	}

	rule.GrandparentImageFilename = types.ObjectNull(excludableField{}.attrTypes())
	rule.GrandparentCommandLine = types.ObjectNull(excludableField{}.attrTypes())
	rule.ParentImageFilename = types.ObjectNull(excludableField{}.attrTypes())
	rule.ParentCommandLine = types.ObjectNull(excludableField{}.attrTypes())
	rule.ImageFilename = types.ObjectNull(excludableField{}.attrTypes())
	rule.CommandLine = types.ObjectNull(excludableField{}.attrTypes())
	rule.FilePath = types.ObjectNull(excludableField{}.attrTypes())
	rule.RemoteIPAddress = types.ObjectNull(excludableField{}.attrTypes())
	rule.RemotePort = types.ObjectNull(excludableField{}.attrTypes())
	rule.DomainName = types.ObjectNull(excludableField{}.attrTypes())
	rule.FileType = types.ListNull(types.StringType)
	rule.ConnectionType = types.ListNull(types.StringType)

	for _, fieldValue := range apiRule.FieldValues {
		if fieldValue.Type != nil && *fieldValue.Type == "excludable" {
			var includeVal, excludeVal types.String
			includeVal = types.StringNull()
			excludeVal = types.StringNull()

			for _, item := range fieldValue.Values {
				if item.Label != nil && item.Value != nil {
					if *item.Label == "include" {
						includeVal = types.StringValue(*item.Value)
					} else if *item.Label == "exclude" {
						excludeVal = types.StringValue(*item.Value)
					}
				}
			}

			obj, objDiags := types.ObjectValue(
				excludableField{}.attrTypes(),
				map[string]attr.Value{
					"include": includeVal,
					"exclude": excludeVal,
				},
			)
			diags.Append(objDiags...)
			if diags.HasError() {
				return rule
			}

			if fieldValue.Name != nil {
				switch *fieldValue.Name {
				case "GrandparentImageFilename":
					rule.GrandparentImageFilename = obj
				case "GrandparentCommandLine":
					rule.GrandparentCommandLine = obj
				case "ParentImageFilename":
					rule.ParentImageFilename = obj
				case "ParentCommandLine":
					rule.ParentCommandLine = obj
				case "ImageFilename":
					rule.ImageFilename = obj
				case "CommandLine":
					rule.CommandLine = obj
				case "FilePath":
					rule.FilePath = obj
				case "RemoteIPAddress":
					rule.RemoteIPAddress = obj
				case "RemotePort":
					rule.RemotePort = obj
				case "DomainName":
					rule.DomainName = obj
				}
			}
		} else if fieldValue.Type != nil && *fieldValue.Type == "set" {
			var values []string
			for _, item := range fieldValue.Values {
				if item.Value != nil {
					values = append(values, *item.Value)
				}
			}

			if fieldValue.Name != nil {
				switch *fieldValue.Name {
				case "FileType":
					listVal, listDiags := types.ListValueFrom(ctx, types.StringType, values)
					diags.Append(listDiags...)
					if !diags.HasError() {
						rule.FileType = listVal
					}
				case "ConnectionType":
					listVal, listDiags := types.ListValueFrom(ctx, types.StringType, values)
					diags.Append(listDiags...)
					if !diags.HasError() {
						rule.ConnectionType = listVal
					}
				}
			}
		}
	}

	return rule
}
