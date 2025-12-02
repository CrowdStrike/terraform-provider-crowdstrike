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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &filevantageRuleGroupResource{}
	_ resource.ResourceWithConfigure      = &filevantageRuleGroupResource{}
	_ resource.ResourceWithImportState    = &filevantageRuleGroupResource{}
	_ resource.ResourceWithValidateConfig = &filevantageRuleGroupResource{}
)

const (
	LinuxFiles      = "LinuxFiles"
	MacFiles        = "MacFiles"
	WindowsFiles    = "WindowsFiles"
	WindowsRegistry = "WindowsRegistry"
)

// NewFilevantageRuleGroupResource is a helper function to simplify the provider implementation.
func NewFilevantageRuleGroupResource() resource.Resource {
	return &filevantageRuleGroupResource{}
}

// filevantageRuleGroupResource is the resource implementation.
type filevantageRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// filevantageRuleGroupResourceModel is the resource implementation.
type filevantageRuleGroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Description types.String `tfsdk:"description"`
	Rules       types.List   `tfsdk:"rules"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

// fimRule is the resource implementation.
type fimRule struct {
	ID                   types.String `tfsdk:"id"`
	Description          types.String `tfsdk:"description"`
	Precedence           types.Int64  `tfsdk:"precedence"`
	Path                 types.String `tfsdk:"path"`
	Severity             types.String `tfsdk:"severity"`
	Depth                types.String `tfsdk:"depth"`
	Include              types.String `tfsdk:"include"`
	Exclude              types.String `tfsdk:"exclude"`
	IncludeUsers         types.String `tfsdk:"include_users"`
	IncludeProcesses     types.String `tfsdk:"include_processes"`
	ExcludeUsers         types.String `tfsdk:"exclude_users"`
	ExcludeProcesses     types.String `tfsdk:"exclude_processes"`
	ContentFiles         types.List   `tfsdk:"file_names"`
	ContentRegistry      types.List   `tfsdk:"registry_values"`
	EnableContentCapture types.Bool   `tfsdk:"enable_content_capture"`

	// Directory monitoring
	WatchDeleteDirectoryChanges     types.Bool `tfsdk:"watch_directory_delete_changes"`
	WatchCreateDirectoryChanges     types.Bool `tfsdk:"watch_directory_create_changes"`
	WatchRenameDirectoryChanges     types.Bool `tfsdk:"watch_directory_rename_changes"`
	WatchAttributeDirectoryChanges  types.Bool `tfsdk:"watch_directory_attribute_changes"`
	WatchPermissionDirectoryChanges types.Bool `tfsdk:"watch_directory_permission_changes"`

	// File monitoring
	WatchRenameFileChanges     types.Bool `tfsdk:"watch_file_rename_changes"`
	WatchWriteFileChanges      types.Bool `tfsdk:"watch_file_write_changes"`
	WatchCreateFileChanges     types.Bool `tfsdk:"watch_file_create_changes"`
	WatchDeleteFileChanges     types.Bool `tfsdk:"watch_file_delete_changes"`
	WatchAttributeFileChanges  types.Bool `tfsdk:"watch_file_attribute_changes"`
	WatchPermissionFileChanges types.Bool `tfsdk:"watch_file_permission_changes"`

	// Registry monitoring
	WatchCreateKeyChanges      types.Bool `tfsdk:"watch_key_create_changes"`
	WatchDeleteKeyChanges      types.Bool `tfsdk:"watch_key_delete_changes"`
	WatchRenameKeyChanges      types.Bool `tfsdk:"watch_key_rename_changes"`
	WatchPermissionsKeyChanges types.Bool `tfsdk:"watch_key_permissions_changes"`
	WatchSetValueChanges       types.Bool `tfsdk:"watch_key_value_set_changes"`
	WatchDeleteValueChanges    types.Bool `tfsdk:"watch_key_value_delete_changes"`
}

func (f fimRule) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                types.StringType,
		"description":       types.StringType,
		"precedence":        types.Int64Type,
		"path":              types.StringType,
		"severity":          types.StringType,
		"depth":             types.StringType,
		"include":           types.StringType,
		"exclude":           types.StringType,
		"include_users":     types.StringType,
		"include_processes": types.StringType,
		"exclude_users":     types.StringType,
		"exclude_processes": types.StringType,
		"file_names": types.ListType{
			ElemType: types.StringType,
		},
		"registry_values": types.ListType{
			ElemType: types.StringType,
		},
		"enable_content_capture":             types.BoolType,
		"watch_directory_delete_changes":     types.BoolType,
		"watch_directory_create_changes":     types.BoolType,
		"watch_directory_rename_changes":     types.BoolType,
		"watch_directory_attribute_changes":  types.BoolType,
		"watch_directory_permission_changes": types.BoolType,
		"watch_file_rename_changes":          types.BoolType,
		"watch_file_write_changes":           types.BoolType,
		"watch_file_create_changes":          types.BoolType,
		"watch_file_delete_changes":          types.BoolType,
		"watch_file_attribute_changes":       types.BoolType,
		"watch_file_permission_changes":      types.BoolType,
		"watch_key_create_changes":           types.BoolType,
		"watch_key_delete_changes":           types.BoolType,
		"watch_key_rename_changes":           types.BoolType,
		"watch_key_permissions_changes":      types.BoolType,
		"watch_key_value_set_changes":        types.BoolType,
		"watch_key_value_delete_changes":     types.BoolType,
	}
}

// Configure adds the provider configured client to the resource.
func (r *filevantageRuleGroupResource) Configure(
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
func (r *filevantageRuleGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_filevantage_rule_group"
}

// Schema defines the schema for the resource.
func (r *filevantageRuleGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"FileVantage",
			"This resource allows management of a FileVantage rule group. A FileVantage rule group is a collection of file integrity rules that can be assigned to a FileVantge policy.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the filevantage rule group.",
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
				Description: "Name of the filevantage rule group.",
			},
			"type": schema.StringAttribute{
				Optional:    true,
				Description: "The type of filevantage rule group.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"LinuxFiles",
						"MacFiles",
						"WindowsFiles",
						"WindowsRegistry",
					),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the filevantage rule group.",
			},
			"rules": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Rules to be associated with the rule group. Precedence is determined by the order of the rules in the list.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Identifier for the filevantage rule.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"precedence": schema.Int64Attribute{
							Computed:    true,
							Description: "Precedence of the rule in the rule group.",
							PlanModifiers: []planmodifier.Int64{
								int64planmodifier.UseStateForUnknown(),
							},
						},
						"path": schema.StringAttribute{
							Required:    true,
							Description: "Representing the file system or registry path to monitor. All paths must end with the path separator, e.g. c:\\windows\\ for windows and /usr/bin/ for linux/mac.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 255),
							},
						},
						"description": schema.StringAttribute{
							Required:    true,
							Description: "Description of the filevantage rule.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 500),
							},
						},
						"severity": schema.StringAttribute{
							Required:    true,
							Description: "Severity to categorize change events produced by this rule.",
							Validators: []validator.String{
								stringvalidator.OneOf(
									"Low",
									"Medium",
									"High",
									"Critical",
								),
							},
						},
						"depth": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Depth below the base path to monitor.",
							Default:     stringdefault.StaticString("ANY"),
							Validators: []validator.String{
								stringvalidator.OneOf(
									"ANY",
									"1",
									"2",
									"3",
									"4",
									"5",
								),
							},
						},
						"include": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the files, directories, registry keys, or registry values that will be monitored. Defaults to all (*)",
							Default:     stringdefault.StaticString("*"),
						},
						"exclude": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the files, directories, registry keys, or registry values that will be excluded from monitoring.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"include_users": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific users that will be monitored.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"include_processes": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific processes that will be monitored.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"exclude_users": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific users that will be excluded from monitoring.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"exclude_processes": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific processes that will be excluded from monitoring.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"file_names": schema.ListAttribute{
							Optional:    true,
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of file names whose content will be monitored. Listed files must match the file include pattern and not match the file exclude pattern.",
						},
						"registry_values": schema.ListAttribute{
							Optional:    true,
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of registry values whose content will be monitored. Listed registry values must match the registry include pattern and not match the registry exclude pattern.",
						},
						"enable_content_capture": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Enable content capture for the rule. Requires watch_file_write_changes or watch_key_value_set_changes to be enabled.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_directory_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory deletion events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_directory_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory creation events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_directory_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory rename events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_directory_attribute_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory attribute change events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_directory_permission_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory permission change events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file rename events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_write_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file write events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file creation events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file deletion events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_attribute_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file attribute change events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_file_permission_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file permission change events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key creation events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key deletion events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key rename events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_permissions_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key permission change events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_value_set_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry value set events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
						"watch_key_value_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry value deletion events.",
							PlanModifiers: []planmodifier.Bool{
								boolplanmodifier.UseStateForUnknown(),
							},
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *filevantageRuleGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan filevantageRuleGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rgType := plan.Type.ValueString()

	params := filevantage.CreateRuleGroupsParams{
		Context: ctx,
		Body: &models.RulegroupsCreateRequest{
			Name:        plan.Name.ValueStringPointer(),
			Type:        &rgType,
			Description: plan.Description.ValueString(),
		},
	}

	res, err := r.client.Filevantage.CreateRuleGroups(&params)

	if res == nil {
		res = &filevantage.CreateRuleGroupsOK{}
	}

	resp.Diagnostics.Append(handleRuleGroupErrors(plan.Name.ValueString(), res, err, "create")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules := utils.ListTypeAs[*fimRule](ctx, plan.Rules, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncRules(ctx, rgType, rules, []*fimRule{}, plan.ID.ValueString())...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules, diags := r.getRules(
		ctx,
		plan.ID.ValueString(),
		[]*models.RulegroupsAssignedRule{},
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(rules) > 0 {
		ruleList, diags := types.ListValueFrom(
			ctx,
			types.ObjectType{AttrTypes: fimRule{}.attrTypes()},
			rules,
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Rules = ruleList
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *filevantageRuleGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state filevantageRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, diags := r.getRuleGroup(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if res == nil {
		res = &filevantage.GetRuleGroupsOK{}
	}

	resp.Diagnostics.Append(handleRuleGroupErrors(state.ID.ValueString(), res, nil, "read")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &state)

	rules, diags := r.getRules(
		ctx,
		state.ID.ValueString(),
		res.Payload.Resources[0].AssignedRules,
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(rules) > 0 {
		ruleList, diags := types.ListValueFrom(
			ctx,
			types.ObjectType{AttrTypes: fimRule{}.attrTypes()},
			&rules,
		)

		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Rules = ruleList
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *filevantageRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	// Retrieve values from plan
	var plan filevantageRuleGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve values from state
	var state filevantageRuleGroupResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := filevantage.UpdateRuleGroupsParams{
		Context: ctx,
		Body: &models.RulegroupsUpdateRequest{
			ID:          plan.ID.ValueStringPointer(),
			Name:        plan.Name.ValueStringPointer(),
			Description: plan.Description.ValueString(),
		},
	}

	res, err := r.client.Filevantage.UpdateRuleGroups(&params)

	if res == nil {
		res = &filevantage.UpdateRuleGroupsOK{}
	}

	resp.Diagnostics.Append(handleRuleGroupErrors(plan.ID.ValueString(), res, err, "update")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	planRules := utils.ListTypeAs[*fimRule](ctx, plan.Rules, &resp.Diagnostics)
	stateRules := utils.ListTypeAs[*fimRule](ctx, state.Rules, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(
		r.syncRules(
			ctx,
			plan.Type.ValueString(),
			planRules,
			stateRules,
			plan.ID.ValueString(),
		)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules, diags := r.getRules(
		ctx,
		plan.ID.ValueString(),
		[]*models.RulegroupsAssignedRule{},
	)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(rules) > 0 {
		ruleList, diags := types.ListValueFrom(
			ctx,
			types.ObjectType{AttrTypes: fimRule{}.attrTypes()},
			rules,
		)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Rules = ruleList
	}

	resp.Diagnostics.Append(
		resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *filevantageRuleGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state filevantageRuleGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()

	if id == "" {
		return
	}

	params := filevantage.DeleteRuleGroupsParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := r.client.Filevantage.DeleteRuleGroups(&params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete filevantage rule group",
			fmt.Sprintf("Failed to delete filevantage rule group (%s): %s", id, err.Error()),
		)
	}
}

// ImportState implements the logic to support resource imports.
func (r *filevantageRuleGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *filevantageRuleGroupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config filevantageRuleGroupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rgType := config.Type.ValueString()

	if rgType == "" {
		return
	}

	rules := utils.ListTypeAs[*fimRule](ctx, config.Rules, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	for i, rule := range rules {
		rPath := path.Root("rules").AtListIndex(i)

		if rgType == LinuxFiles || rgType == MacFiles || rgType == WindowsFiles {
			if len(rule.ContentFiles.Elements()) > 0 {
				if !rule.WatchWriteFileChanges.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"watch_file_write_changes must be enabled when file_names is set",
					)
				}

				if !rule.EnableContentCapture.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"enable_content_capture must be enabled when file_names is set",
					)
				}
			}

			if rule.EnableContentCapture.ValueBool() {
				if len(rule.ContentFiles.Elements()) == 0 {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"file_names must be set when enable_content_capture is enabled",
					)
				}

				if !rule.WatchWriteFileChanges.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"watch_file_write_changes must be enabled when enable_content_capture is set",
					)
				}
			}

			invalidFields := map[string]bool{
				"watch_key_value_set_changes":    !rule.WatchSetValueChanges.IsNull(),
				"watch_key_value_delete_changes": !rule.WatchDeleteValueChanges.IsNull(),
				"watch_key_create_changes":       !rule.WatchCreateKeyChanges.IsNull(),
				"watch_key_delete_changes":       !rule.WatchDeleteKeyChanges.IsNull(),
				"watch_key_rename_changes":       !rule.WatchRenameKeyChanges.IsNull(),
				"watch_key_permissions_changes":  !rule.WatchPermissionsKeyChanges.IsNull(),
				"registry_values":                !rule.ContentRegistry.IsNull(),
			}

			for k, v := range invalidFields {
				if v {
					resp.Diagnostics.AddAttributeError(
						rPath.AtName(k),
						"Invalid attribute",
						fmt.Sprintf(
							"%s is not a valid attribute for %s rule group type and should be removed.",
							k,
							rgType,
						),
					)
				}
			}
		}

		if rgType == WindowsRegistry {
			invalidFields := map[string]bool{
				"watch_file_write_changes":           !rule.WatchWriteFileChanges.IsNull(),
				"watch_file_create_changes":          !rule.WatchCreateFileChanges.IsNull(),
				"watch_file_delete_changes":          !rule.WatchDeleteFileChanges.IsNull(),
				"watch_file_rename_changes":          !rule.WatchRenameFileChanges.IsNull(),
				"watch_file_attribute_changes":       !rule.WatchAttributeFileChanges.IsNull(),
				"watch_file_permission_changes":      !rule.WatchPermissionFileChanges.IsNull(),
				"watch_directory_delete_changes":     !rule.WatchDeleteDirectoryChanges.IsNull(),
				"watch_directory_create_changes":     !rule.WatchCreateDirectoryChanges.IsNull(),
				"watch_directory_rename_changes":     !rule.WatchRenameDirectoryChanges.IsNull(),
				"watch_directory_attribute_changes":  !rule.WatchAttributeDirectoryChanges.IsNull(),
				"watch_directory_permission_changes": !rule.WatchPermissionDirectoryChanges.IsNull(),
				"file_names":                         !rule.ContentFiles.IsNull(),
			}

			for k, v := range invalidFields {
				if v {
					resp.Diagnostics.AddAttributeError(
						rPath.AtName(k),
						"Invalid attribute",
						fmt.Sprintf(
							"%s is not a valid attribute for %s rule group type and should be removed.",
							k,
							rgType,
						),
					)
				}
			}

			if rule.EnableContentCapture.ValueBool() {
				if len(rule.ContentRegistry.Elements()) == 0 {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"registry_values must be set when enable_content_capture is enabled",
					)
				}

				if !rule.WatchSetValueChanges.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"watch_key_value_set_changes must be enabled when enable_content_capture is set",
					)
				}
			}

			if len(rule.ContentRegistry.Elements()) > 0 {
				if !rule.WatchSetValueChanges.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"watch_key_value_set_changes must be enabled when registry_contant is set",
					)
				}

				if !rule.EnableContentCapture.ValueBool() {
					resp.Diagnostics.AddAttributeError(
						rPath,
						"Missing required attribute",
						"enable_content_capture must be enabled when registry_values is set",
					)
				}
			}
		}
	}
}

// rgResponse is a helper interface to simplify the response handling for create, get, and update.
type rgResponse interface {
	GetPayload() *models.RulegroupsResponse
}

// assignRuleGroup is a helper function to assign the rule group response to the resource model.
func assignRuleGroup(
	rg rgResponse,
	config *filevantageRuleGroupResourceModel,
) {
	res := rg.GetPayload().Resources[0]
	config.ID = types.StringValue(*res.ID)
	config.Name = types.StringValue(res.Name)
	config.Description = types.StringValue(res.Description)
	config.Type = types.StringValue(res.Type)
}

// handleRuleGroupErrors is a helper function to handle common errors returned from the API.
func handleRuleGroupErrors(
	rgID string,
	r rgResponse,
	err error,
	action string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	summary := fmt.Sprintf("Failed to %s filevantage rule group", action)

	if err != nil {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group (%s): %s",
				action,
				rgID,
				err.Error(),
			),
		)
		return diags
	}

	res := r.GetPayload()

	if res == nil {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group (%s): response payload contained no information.",
				action,
				rgID,
			),
		)
		return diags
	}

	for _, err := range res.Errors {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group (%s): %s",
				action,
				rgID,
				err.String(),
			),
		)
	}

	if len(res.Resources) == 0 {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group (%s): response payload contained no resources.",
				action,
				rgID,
			),
		)
	}

	return diags
}

// getRuleGroup retrieves the rule group associated with the resource.
func (r *filevantageRuleGroupResource) getRuleGroup(
	ctx context.Context,
	id string,
) (*filevantage.GetRuleGroupsOK, diag.Diagnostics) {
	params := filevantage.GetRuleGroupsParams{
		Context: ctx,
		Ids:     []string{id},
	}

	res, err := r.client.Filevantage.GetRuleGroups(&params)

	if res == nil {
		res = &filevantage.GetRuleGroupsOK{}
	}

	diags := handleRuleGroupErrors(id, res, err, "read")

	return res, diags
}

// ruleResponse is a helper interface to simplify the response handling for create, get, and update.
type ruleResponse interface {
	GetPayload() *models.RulegroupsRulesResponse
}

// handleRuleGroupRulesErrors is a helper function to handle common errors returned from the API.
func handleRuleGroupRulesErrors(
	rule fimRule,
	ruleResponse ruleResponse,
	err error,
	action string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	summary := fmt.Sprintf("Failed to %s filevantage rule group rule", action)

	if err != nil {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group rule (%s): %s",
				action,
				rule.Path.ValueString(),
				err.Error(),
			),
		)

		return diags
	}

	res := ruleResponse.GetPayload()

	if res == nil {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group rule (%s): response payload contained no information.",
				action,
				rule.Path.ValueString(),
			),
		)
		return diags
	}

	for _, err := range res.Errors {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group rule (%s): %s",
				action,
				rule.Path.ValueString(),
				err.String(),
			),
		)
	}

	if len(res.Resources) == 0 {
		diags.AddError(
			summary,
			fmt.Sprintf(
				"Failed to %s filevantage rule group rule (%s): response payload contained no resources.",
				action,
				rule.Path.ValueString(),
			),
		)
	}

	return diags
}

// syncRules syncs the rule group rules from the resource model to the api.
func (r *filevantageRuleGroupResource) syncRules(
	ctx context.Context,
	ruleGroupType string,
	planRules, stateRules []*fimRule,
	ruleGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	var rulesToCreate []fimRule
	var rulesToDelete []string
	var rulesToUpdate []fimRule

	stateMap := make(map[string]fimRule)
	planMap := make(map[string]fimRule)

	for _, rule := range stateRules {
		rule := *rule
		stateMap[rule.ID.ValueString()] = rule
	}

	for _, rule := range planRules {
		rule := *rule

		// null id means it is a new exclusion
		if rule.ID.IsNull() || rule.ID.IsUnknown() {
			rulesToCreate = append(rulesToCreate, rule)
			continue
		}

		planMap[rule.ID.ValueString()] = rule
		if _, ok := stateMap[rule.ID.ValueString()]; ok {
			if !reflect.DeepEqual(rule, stateMap[rule.ID.ValueString()]) {
				rulesToUpdate = append(rulesToUpdate, rule)
			}
		}
	}

	for _, rule := range stateRules {
		rule := *rule
		if _, ok := planMap[rule.ID.ValueString()]; !ok {
			rulesToDelete = append(rulesToDelete, rule.ID.ValueString())
		}
	}

	diags.Append(r.createRules(ctx, ruleGroupType, rulesToCreate, ruleGroupID)...)
	diags.Append(r.updateRules(ctx, ruleGroupType, rulesToUpdate, ruleGroupID)...)
	diags.Append(r.deleteRules(ctx, rulesToDelete, ruleGroupID)...)

	return diags
}

// getRules retrieves the rules associated with the rule group.
func (r *filevantageRuleGroupResource) getRules(
	ctx context.Context,
	ruleGroupID string,
	assignedRules []*models.RulegroupsAssignedRule,
) ([]*fimRule, diag.Diagnostics) {
	var rules []*fimRule
	var diags diag.Diagnostics

	if len(assignedRules) == 0 {
		res, diags := r.getRuleGroup(ctx, ruleGroupID)
		if diags.HasError() {
			return rules, diags
		}

		assignedRules = res.Payload.Resources[0].AssignedRules
	}

	if len(assignedRules) > 0 {
		assignedRuleIDs := []string{}
		for _, rule := range assignedRules {
			r := rule
			assignedRuleIDs = append(assignedRuleIDs, *r.ID)
		}

		res, err := r.client.Filevantage.GetRules(&filevantage.GetRulesParams{
			Ids:         assignedRuleIDs,
			RuleGroupID: ruleGroupID,
			Context:     ctx,
		})
		if err != nil {
			diags.AddError(
				"Failed to get rules assigned to rule group",
				fmt.Sprintf(
					"Failed to get rules for ids (%s): %s",
					strings.Join(assignedRuleIDs, ", "),
					err.Error(),
				),
			)
			return rules, diags
		}

		if res == nil || res.Payload == nil {
			diags.AddError(
				"Failed to get rules assigned to rule group",
				"Failed to get rules: response payload is nil",
			)
			return rules, diags
		}

		for _, rule := range res.Payload.Resources {
			r := rule
			fimRule := fimRule{}

			fimRule.ID = types.StringValue(*r.ID)
			fimRule.Precedence = types.Int64Value(int64(r.Precedence))
			fimRule.Description = types.StringValue(r.Description)
			fimRule.Path = types.StringValue(*r.Path)
			fimRule.Severity = types.StringValue(*r.Severity)
			fimRule.Depth = types.StringValue(*r.Depth)
			fimRule.Include = types.StringValue(*r.Include)
			fimRule.Exclude = types.StringValue(r.Exclude)
			fimRule.IncludeUsers = types.StringValue(r.IncludeUsers)
			fimRule.IncludeProcesses = types.StringValue(r.IncludeProcesses)
			fimRule.ExcludeUsers = types.StringValue(r.ExcludeUsers)
			fimRule.ExcludeProcesses = types.StringValue(r.ExcludeProcesses)
			filesList, diags := types.ListValueFrom(ctx, types.StringType, r.ContentFiles)
			diags.Append(diags...)
			if diags.HasError() {
				return rules, diags
			}

			fimRule.ContentFiles = filesList
			registryList, diags := types.ListValueFrom(
				ctx,
				types.StringType,
				r.ContentRegistryValues,
			)
			diags.Append(diags...)
			if diags.HasError() {
				return rules, diags
			}
			fimRule.ContentRegistry = registryList
			fimRule.EnableContentCapture = types.BoolValue(r.EnableContentCapture)

			fimRule.WatchCreateKeyChanges = types.BoolValue(r.WatchCreateKeyChanges)
			fimRule.WatchDeleteKeyChanges = types.BoolValue(r.WatchDeleteKeyChanges)
			fimRule.WatchRenameKeyChanges = types.BoolValue(r.WatchRenameKeyChanges)
			fimRule.WatchPermissionsKeyChanges = types.BoolValue(
				r.WatchPermissionsKeyChanges,
			)
			fimRule.WatchSetValueChanges = types.BoolValue(r.WatchSetValueChanges)
			fimRule.WatchDeleteValueChanges = types.BoolValue(r.WatchDeleteValueChanges)
			fimRule.WatchDeleteDirectoryChanges = types.BoolValue(r.WatchDeleteDirectoryChanges)
			fimRule.WatchCreateDirectoryChanges = types.BoolValue(r.WatchCreateDirectoryChanges)
			fimRule.WatchRenameDirectoryChanges = types.BoolValue(r.WatchRenameDirectoryChanges)
			fimRule.WatchAttributeDirectoryChanges = types.BoolValue(
				r.WatchAttributesDirectoryChanges,
			)
			fimRule.WatchPermissionDirectoryChanges = types.BoolValue(
				r.WatchPermissionsDirectoryChanges,
			)
			fimRule.WatchRenameFileChanges = types.BoolValue(r.WatchRenameFileChanges)
			fimRule.WatchWriteFileChanges = types.BoolValue(r.WatchWriteFileChanges)
			fimRule.WatchCreateFileChanges = types.BoolValue(r.WatchCreateFileChanges)
			fimRule.WatchDeleteFileChanges = types.BoolValue(r.WatchDeleteFileChanges)
			fimRule.WatchAttributeFileChanges = types.BoolValue(r.WatchAttributesFileChanges)
			fimRule.WatchPermissionFileChanges = types.BoolValue(r.WatchPermissionsFileChanges)
			rules = append(rules, &fimRule)
		}
	}

	return rules, diags
}

// deleteRules deletes the rules associated with the rule group.
func (r *filevantageRuleGroupResource) deleteRules(
	ctx context.Context,
	rulesToDelete []string,
	ruleGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(rulesToDelete) == 0 {
		return diags
	}

	params := filevantage.DeleteRulesParams{
		Ids:         rulesToDelete,
		RuleGroupID: ruleGroupID,
		Context:     ctx,
	}

	res, err := r.client.Filevantage.DeleteRules(&params)
	if err != nil {
		diags.AddError(
			"Failed to delete rules associated with rule group",
			fmt.Sprintf(
				"Failed to delete rules for rule group (%s): %s",
				ruleGroupID,
				err.Error(),
			),
		)
	}

	if res != nil {
		for _, err := range res.Payload.Errors {
			diags.AddError(
				"Failed to delete rules associated with rule group",
				fmt.Sprintf(
					"Failed to delete rules for rule group (%s): %s",
					ruleGroupID,
					err.String(),
				),
			)
		}
	}

	return diags
}

// updateRules updates the rules associated with the rule group.
func (r *filevantageRuleGroupResource) updateRules(
	ctx context.Context,
	rgType string,
	rules []fimRule,
	ruleGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(rules) == 0 {
		return diags
	}

	for _, rule := range rules {
		rule := rule

		var contentFiles []string
		var contentRegistryValues []string

		if len(rule.ContentFiles.Elements()) > 0 {
			diags.Append(rule.ContentFiles.ElementsAs(ctx, &contentFiles, true)...)
			if diags.HasError() {
				return diags
			}
		}

		if len(rule.ContentRegistry.Elements()) > 0 {
			diags.Append(rule.ContentRegistry.ElementsAs(ctx, &contentRegistryValues, true)...)
			if diags.HasError() {
				return diags
			}
		}

		params := filevantage.UpdateRulesParams{
			Context: ctx,
			Body: &models.RulegroupsRule{
				ID:                    rule.ID.ValueStringPointer(),
				Precedence:            int32(rule.Precedence.ValueInt64()),
				RuleGroupID:           &ruleGroupID,
				Type:                  &rgType,
				Path:                  rule.Path.ValueStringPointer(),
				Description:           rule.Description.ValueString(),
				EnableContentCapture:  rule.EnableContentCapture.ValueBool(),
				Exclude:               rule.Exclude.ValueString(),
				ExcludeProcesses:      rule.ExcludeProcesses.ValueString(),
				ExcludeUsers:          rule.ExcludeUsers.ValueString(),
				Include:               rule.Include.ValueStringPointer(),
				IncludeProcesses:      rule.IncludeProcesses.ValueString(),
				IncludeUsers:          rule.IncludeUsers.ValueString(),
				Depth:                 rule.Depth.ValueStringPointer(),
				Severity:              rule.Severity.ValueStringPointer(),
				ContentFiles:          contentFiles,
				ContentRegistryValues: contentRegistryValues,

				// Directory monitoring
				WatchDeleteDirectoryChanges:      rule.WatchDeleteDirectoryChanges.ValueBool(),
				WatchCreateDirectoryChanges:      rule.WatchCreateDirectoryChanges.ValueBool(),
				WatchRenameDirectoryChanges:      rule.WatchRenameDirectoryChanges.ValueBool(),
				WatchAttributesDirectoryChanges:  rule.WatchAttributeDirectoryChanges.ValueBool(),
				WatchPermissionsDirectoryChanges: rule.WatchPermissionDirectoryChanges.ValueBool(),

				// File monitoring
				WatchRenameFileChanges:      rule.WatchRenameFileChanges.ValueBool(),
				WatchWriteFileChanges:       rule.WatchWriteFileChanges.ValueBool(),
				WatchCreateFileChanges:      rule.WatchCreateFileChanges.ValueBool(),
				WatchDeleteFileChanges:      rule.WatchDeleteFileChanges.ValueBool(),
				WatchAttributesFileChanges:  rule.WatchAttributeFileChanges.ValueBool(),
				WatchPermissionsFileChanges: rule.WatchPermissionFileChanges.ValueBool(),

				// Registry monitoring
				WatchCreateKeyChanges:      rule.WatchCreateKeyChanges.ValueBool(),
				WatchDeleteKeyChanges:      rule.WatchDeleteKeyChanges.ValueBool(),
				WatchRenameKeyChanges:      rule.WatchRenameKeyChanges.ValueBool(),
				WatchPermissionsKeyChanges: rule.WatchPermissionsKeyChanges.ValueBool(),
				WatchSetValueChanges:       rule.WatchSetValueChanges.ValueBool(),
				WatchDeleteValueChanges:    rule.WatchDeleteValueChanges.ValueBool(),
			},
		}

		res, err := r.client.Filevantage.UpdateRules(&params)

		if res == nil {
			res = &filevantage.UpdateRulesOK{}
		}

		diags.Append(handleRuleGroupRulesErrors(rule, res, err, "update")...)

		if diags.HasError() {
			return diags
		}
	}

	return diags
}

// createRules creates the rules associated with the rule group.
func (r *filevantageRuleGroupResource) createRules(
	ctx context.Context,
	rgType string,
	rules []fimRule,
	ruleGroupID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(rules) == 0 {
		return diags
	}

	for _, rule := range rules {
		rule := rule

		var contentFiles []string
		var contentRegistryValues []string

		if len(rule.ContentFiles.Elements()) > 0 {
			diags.Append(rule.ContentFiles.ElementsAs(ctx, &contentFiles, true)...)
			if diags.HasError() {
				return diags
			}
		}

		if len(rule.ContentRegistry.Elements()) > 0 {
			diags.Append(rule.ContentRegistry.ElementsAs(ctx, &contentRegistryValues, true)...)
			if diags.HasError() {
				return diags
			}
		}

		params := filevantage.CreateRulesParams{
			Context: ctx,
			Body: &models.RulegroupsRule{
				RuleGroupID:           &ruleGroupID,
				Type:                  &rgType,
				Path:                  rule.Path.ValueStringPointer(),
				Description:           rule.Description.ValueString(),
				EnableContentCapture:  rule.EnableContentCapture.ValueBool(),
				Exclude:               rule.Exclude.ValueString(),
				ExcludeProcesses:      rule.ExcludeProcesses.ValueString(),
				ExcludeUsers:          rule.ExcludeUsers.ValueString(),
				Include:               rule.Include.ValueStringPointer(),
				IncludeProcesses:      rule.IncludeProcesses.ValueString(),
				IncludeUsers:          rule.IncludeUsers.ValueString(),
				Depth:                 rule.Depth.ValueStringPointer(),
				Severity:              rule.Severity.ValueStringPointer(),
				ContentFiles:          contentFiles,
				ContentRegistryValues: contentRegistryValues,

				// Directory monitoring
				WatchDeleteDirectoryChanges:      rule.WatchDeleteDirectoryChanges.ValueBool(),
				WatchCreateDirectoryChanges:      rule.WatchCreateDirectoryChanges.ValueBool(),
				WatchRenameDirectoryChanges:      rule.WatchRenameDirectoryChanges.ValueBool(),
				WatchAttributesDirectoryChanges:  rule.WatchAttributeDirectoryChanges.ValueBool(),
				WatchPermissionsDirectoryChanges: rule.WatchPermissionDirectoryChanges.ValueBool(),

				// File monitoring
				WatchRenameFileChanges:      rule.WatchRenameFileChanges.ValueBool(),
				WatchWriteFileChanges:       rule.WatchWriteFileChanges.ValueBool(),
				WatchCreateFileChanges:      rule.WatchCreateFileChanges.ValueBool(),
				WatchDeleteFileChanges:      rule.WatchDeleteFileChanges.ValueBool(),
				WatchAttributesFileChanges:  rule.WatchAttributeFileChanges.ValueBool(),
				WatchPermissionsFileChanges: rule.WatchPermissionFileChanges.ValueBool(),

				// Registry monitoring
				WatchCreateKeyChanges:      rule.WatchCreateKeyChanges.ValueBool(),
				WatchDeleteKeyChanges:      rule.WatchDeleteKeyChanges.ValueBool(),
				WatchRenameKeyChanges:      rule.WatchRenameKeyChanges.ValueBool(),
				WatchPermissionsKeyChanges: rule.WatchPermissionsKeyChanges.ValueBool(),
				WatchSetValueChanges:       rule.WatchSetValueChanges.ValueBool(),
				WatchDeleteValueChanges:    rule.WatchDeleteValueChanges.ValueBool(),
			},
		}

		res, err := r.client.Filevantage.CreateRules(&params)

		if res == nil {
			res = &filevantage.CreateRulesOK{}
		}

		diags.Append(handleRuleGroupRulesErrors(rule, res, err, "create")...)

		if diags.HasError() {
			return diags
		}
	}

	return diags
}
