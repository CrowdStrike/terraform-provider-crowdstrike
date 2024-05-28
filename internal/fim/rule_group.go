package fim

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/filevantage"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	ID          types.String                    `tfsdk:"id"`
	Name        types.String                    `tfsdk:"name"`
	Type        types.String                    `tfsdk:"type"`
	Description types.String                    `tfsdk:"description"`
	Rules       []*filevantageRuleResourceModel `tfsdk:"rules"`
	LastUpdated types.String                    `tfsdk:"last_updated"`
}

// filevantageRuleResourceModel is the resource implementation.
type filevantageRuleResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Description          types.String `tfsdk:"description"`
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
						},
						"include_users": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific users that will be monitored.",
						},
						"include_processes": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific processes that will be monitored.",
						},
						"exclude_users": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific users that will be excluded from monitoring.",
						},
						"exclude_processes": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Represents the changes performed by specific processes that will be excluded from monitoring.",
						},
						"file_names": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "List of file names whose content will be monitored. Listed files must match the file include pattern and not match the file exclude pattern.",
						},
						"registry_values": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "List of registry values whose content will be monitored. Listed registry values must match the registry include pattern and not match the registry exclude pattern.",
						},
						"enable_content_capture": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Enable content capture for the rule. Requires watch_file_write_changes or watch_key_value_set_changes to be enabled.",
						},
						"watch_directory_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory deletion events.",
						},
						"watch_directory_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory creation events.",
						},
						"watch_directory_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory rename events.",
						},
						"watch_directory_attribute_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory attribute change events.",
						},
						"watch_directory_permission_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor directory permission change events.",
						},
						"watch_file_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file rename events.",
						},
						"watch_file_write_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file write events.",
						},
						"watch_file_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file creation events.",
						},
						"watch_file_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file deletion events.",
						},
						"watch_file_attribute_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file attribute change events.",
						},
						"watch_file_permission_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor file permission change events.",
						},
						"watch_key_create_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key creation events.",
						},
						"watch_key_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key deletion events.",
						},
						"watch_key_rename_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key rename events.",
						},
						"watch_key_permissions_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry key permission change events.",
						},
						"watch_key_value_set_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry value set events.",
						},
						"watch_key_value_delete_changes": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Monitor registry value deletion events.",
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

	resp.Diagnostics.Append(handleRuleGroupErrors(plan, res, err, "create")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules, diags := r.createRules(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(rules) > 0 {
		plan.Rules = make([]*filevantageRuleResourceModel, len(rules))

		for i, rule := range rules {
			plan.Rules[i] = &filevantageRuleResourceModel{}
			r := rule.GetPayload().Resources[0]

			plan.Rules[i].ID = types.StringValue(*r.ID)
			plan.Rules[i].Description = types.StringValue(r.Description)
			plan.Rules[i].Path = types.StringValue(*r.Path)
			plan.Rules[i].Severity = types.StringValue(*r.Severity)
			plan.Rules[i].Depth = types.StringValue(*r.Depth)
			plan.Rules[i].Include = types.StringValue(*r.Include)
			plan.Rules[i].Exclude = types.StringValue(r.Exclude)
			plan.Rules[i].IncludeUsers = types.StringValue(r.IncludeUsers)
			plan.Rules[i].IncludeProcesses = types.StringValue(r.IncludeProcesses)
			plan.Rules[i].ExcludeUsers = types.StringValue(r.ExcludeUsers)
			plan.Rules[i].ExcludeProcesses = types.StringValue(r.ExcludeProcesses)
			filesList, diags := types.ListValueFrom(ctx, types.StringType, r.ContentFiles)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			plan.Rules[i].ContentFiles = filesList
			registryList, diags := types.ListValueFrom(
				ctx,
				types.StringType,
				r.ContentRegistryValues,
			)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			plan.Rules[i].ContentRegistry = registryList
			plan.Rules[i].EnableContentCapture = types.BoolValue(r.EnableContentCapture)

			if plan.Type.ValueString() == WindowsRegistry {
				plan.Rules[i].WatchCreateKeyChanges = types.BoolValue(r.WatchCreateKeyChanges)
				plan.Rules[i].WatchDeleteKeyChanges = types.BoolValue(r.WatchDeleteKeyChanges)
				plan.Rules[i].WatchRenameKeyChanges = types.BoolValue(r.WatchRenameKeyChanges)
				plan.Rules[i].WatchPermissionsKeyChanges = types.BoolValue(
					r.WatchPermissionsKeyChanges,
				)
				plan.Rules[i].WatchSetValueChanges = types.BoolValue(r.WatchSetValueChanges)
				plan.Rules[i].WatchDeleteValueChanges = types.BoolValue(r.WatchDeleteValueChanges)
			} else {
				plan.Rules[i].WatchDeleteDirectoryChanges = types.BoolValue(r.WatchDeleteDirectoryChanges)
				plan.Rules[i].WatchCreateDirectoryChanges = types.BoolValue(r.WatchCreateDirectoryChanges)
				plan.Rules[i].WatchRenameDirectoryChanges = types.BoolValue(r.WatchRenameDirectoryChanges)
				plan.Rules[i].WatchAttributeDirectoryChanges = types.BoolValue(r.WatchAttributesDirectoryChanges)
				plan.Rules[i].WatchPermissionDirectoryChanges = types.BoolValue(r.WatchPermissionsDirectoryChanges)
				plan.Rules[i].WatchRenameFileChanges = types.BoolValue(r.WatchRenameFileChanges)
				plan.Rules[i].WatchWriteFileChanges = types.BoolValue(r.WatchWriteFileChanges)
				plan.Rules[i].WatchCreateFileChanges = types.BoolValue(r.WatchCreateFileChanges)
				plan.Rules[i].WatchDeleteFileChanges = types.BoolValue(r.WatchDeleteFileChanges)
				plan.Rules[i].WatchAttributeFileChanges = types.BoolValue(r.WatchAttributesFileChanges)
				plan.Rules[i].WatchPermissionFileChanges = types.BoolValue(r.WatchPermissionsFileChanges)
			}
		}
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

	params := filevantage.GetRuleGroupsParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	res, err := r.client.Filevantage.GetRuleGroups(&params)

	if res == nil {
		res = &filevantage.GetRuleGroupsOK{}
	}

	resp.Diagnostics.Append(handleRuleGroupErrors(state, res, err, "read")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &state)
	state.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	assignedRules := res.Payload.Resources[0].AssignedRules

	if len(assignedRules) > 0 {
		state.Rules = make([]*filevantageRuleResourceModel, len(assignedRules))

		assignedRuleIDs := []string{}
		for _, rule := range assignedRules {
			r := rule
			assignedRuleIDs = append(assignedRuleIDs, *r.ID)
		}

		rules, err := r.client.Filevantage.GetRules(&filevantage.GetRulesParams{
			Ids:         assignedRuleIDs,
			RuleGroupID: state.ID.ValueString(),
			Context:     ctx,
		})

		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to get rules assigned to rule group",
				fmt.Sprintf(
					"Failed to get rules for ids (%s): %s",
					strings.Join(assignedRuleIDs, ", "),
					err.Error(),
				),
			)
			return
		}

		if rules == nil || rules.Payload == nil {
			resp.Diagnostics.AddError(
				"Failed to get rules assigned to rule group",
				"Failed to get rules: response payload is nil",
			)
			return
		}

		for i, rule := range rules.Payload.Resources {
			state.Rules[i] = &filevantageRuleResourceModel{}
			r := rule

			state.Rules[i].ID = types.StringValue(*r.ID)
			state.Rules[i].Description = types.StringValue(r.Description)
			state.Rules[i].Path = types.StringValue(*r.Path)
			state.Rules[i].Severity = types.StringValue(*r.Severity)
			state.Rules[i].Depth = types.StringValue(*r.Depth)
			state.Rules[i].Include = types.StringValue(*r.Include)
			state.Rules[i].Exclude = types.StringValue(r.Exclude)
			state.Rules[i].IncludeUsers = types.StringValue(r.IncludeUsers)
			state.Rules[i].IncludeProcesses = types.StringValue(r.IncludeProcesses)
			state.Rules[i].ExcludeUsers = types.StringValue(r.ExcludeUsers)
			state.Rules[i].ExcludeProcesses = types.StringValue(r.ExcludeProcesses)
			filesList, diags := types.ListValueFrom(ctx, types.StringType, r.ContentFiles)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			state.Rules[i].ContentFiles = filesList
			registryList, diags := types.ListValueFrom(
				ctx,
				types.StringType,
				r.ContentRegistryValues,
			)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			state.Rules[i].ContentRegistry = registryList
			state.Rules[i].EnableContentCapture = types.BoolValue(r.EnableContentCapture)

			if state.Type.ValueString() == WindowsRegistry {
				state.Rules[i].WatchCreateKeyChanges = types.BoolValue(r.WatchCreateKeyChanges)
				state.Rules[i].WatchDeleteKeyChanges = types.BoolValue(r.WatchDeleteKeyChanges)
				state.Rules[i].WatchRenameKeyChanges = types.BoolValue(r.WatchRenameKeyChanges)
				state.Rules[i].WatchPermissionsKeyChanges = types.BoolValue(
					r.WatchPermissionsKeyChanges,
				)
				state.Rules[i].WatchSetValueChanges = types.BoolValue(r.WatchSetValueChanges)
				state.Rules[i].WatchDeleteValueChanges = types.BoolValue(r.WatchDeleteValueChanges)
			} else {
				state.Rules[i].WatchDeleteDirectoryChanges = types.BoolValue(r.WatchDeleteDirectoryChanges)
				state.Rules[i].WatchCreateDirectoryChanges = types.BoolValue(r.WatchCreateDirectoryChanges)
				state.Rules[i].WatchRenameDirectoryChanges = types.BoolValue(r.WatchRenameDirectoryChanges)
				state.Rules[i].WatchAttributeDirectoryChanges = types.BoolValue(r.WatchAttributesDirectoryChanges)
				state.Rules[i].WatchPermissionDirectoryChanges = types.BoolValue(r.WatchPermissionsDirectoryChanges)
				state.Rules[i].WatchRenameFileChanges = types.BoolValue(r.WatchRenameFileChanges)
				state.Rules[i].WatchWriteFileChanges = types.BoolValue(r.WatchWriteFileChanges)
				state.Rules[i].WatchCreateFileChanges = types.BoolValue(r.WatchCreateFileChanges)
				state.Rules[i].WatchDeleteFileChanges = types.BoolValue(r.WatchDeleteFileChanges)
				state.Rules[i].WatchAttributeFileChanges = types.BoolValue(r.WatchAttributesFileChanges)
				state.Rules[i].WatchPermissionFileChanges = types.BoolValue(r.WatchPermissionsFileChanges)
			}
		}
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
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
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

	resp.Diagnostics.Append(handleRuleGroupErrors(plan, res, err, "update")...)
	if resp.Diagnostics.HasError() {
		return
	}

	assignRuleGroup(res, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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

	for i, rule := range config.Rules {
		rPath := path.Root("rules").AtListIndex(i)

		if rgType == LinuxFiles || rgType == MacFiles || rgType == WindowsFiles {
			if len(rule.ContentFiles.Elements()) > 0 &&
				!rule.WatchWriteFileChanges.ValueBool() {
				resp.Diagnostics.AddAttributeError(
					rPath.AtName("watch_file_write_changes"),
					"Missing required attribute",
					"watch_file_write_changes must be enabled when file_names is set",
				)
			}

			invalidFields := map[string]bool{
				"watch_key_value_set_changes":    !rule.WatchSetValueChanges.IsNull(),
				"watch_key_value_delete_changes": !rule.WatchDeleteValueChanges.IsNull(),
				"watch_key_create_changes":       !rule.WatchCreateKeyChanges.IsNull(),
				"watch_key_delete_changes":       !rule.WatchDeleteKeyChanges.IsNull(),
				"watch_key_rename_changes":       !rule.WatchRenameKeyChanges.IsNull(),
				"watch_key_permissions_changes":  !rule.WatchPermissionsKeyChanges.IsNull(),
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

			if len(rule.ContentRegistry.Elements()) > 0 &&
				!rule.WatchSetValueChanges.ValueBool() {
				resp.Diagnostics.AddAttributeError(
					rPath.AtName("watch_key_value_set_changes"),
					"Missing required attribute",
					"watch_key_value_set_changes must be enabled when registry_contant is set",
				)
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
	config filevantageRuleGroupResourceModel,
	r rgResponse,
	err error,
	action string,
) diag.Diagnostics {
	var diags diag.Diagnostics
	var rgID string

	summary := fmt.Sprintf("Failed to %s filevantage rule group", action)

	if config.ID.ValueString() != "" {
		rgID = config.ID.ValueString()
	} else {
		rgID = config.Name.ValueString()
	}

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

	if res.Resources == nil || len(res.Resources) == 0 {
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

// ruleResponse is a helper interface to simplify the response handling for create, get, and update.
type ruleResponse interface {
	GetPayload() *models.RulegroupsRulesResponse
}

// handleRuleGroupRulesErrors is a helper function to handle common errors returned from the API.
func handleRuleGroupRulesErrors(
	rule *filevantageRuleResourceModel,
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

	if res.Resources == nil || len(res.Resources) == 0 {
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

func (r *filevantageRuleGroupResource) createRules(
	ctx context.Context,
	config filevantageRuleGroupResourceModel,
) ([]*filevantage.CreateRulesOK, diag.Diagnostics) {
	var diags diag.Diagnostics
	var rules []*filevantage.CreateRulesOK

	rgType := config.Type.ValueString()

	for _, rule := range config.Rules {
		rule := rule

		var contentFiles []string
		var contentRegistryValues []string

		if len(rule.ContentFiles.Elements()) > 0 {
			diags.Append(rule.ContentFiles.ElementsAs(ctx, &contentFiles, true)...)
			if diags.HasError() {
				return rules, diags
			}
		}

		if len(rule.ContentRegistry.Elements()) > 0 {
			diags.Append(rule.ContentRegistry.ElementsAs(ctx, &contentRegistryValues, true)...)
			if diags.HasError() {
				return rules, diags
			}
		}

		params := filevantage.CreateRulesParams{
			Context: ctx,
			Body: &models.RulegroupsRule{
				RuleGroupID:           config.ID.ValueStringPointer(),
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
		rules = append(rules, res)

		if res == nil {
			res = &filevantage.CreateRulesOK{}
		}

		diags.Append(handleRuleGroupRulesErrors(rule, res, err, "create")...)

		if diags.HasError() {
			return rules, diags
		}
	}

	return rules, diags
}
