package lookupfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
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

var (
	_ resource.Resource                   = &ngsiemlookupResource{}
	_ resource.ResourceWithConfigure      = &ngsiemlookupResource{}
	_ resource.ResourceWithImportState    = &ngsiemlookupResource{}
	_ resource.ResourceWithValidateConfig = &ngsiemlookupResource{}
)

func NewNGSIEMLookupFileResource() resource.Resource {
	return &ngsiemlookupResource{}
}

type ngsiemlookupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type ngsiemlookupResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Filename        types.String `tfsdk:"filename"`
	Repository      types.String `tfsdk:"repository"`
	Content         types.String `tfsdk:"content"`
	ContentSHA256   types.String `tfsdk:"content_sha256"`
	AssumeUnchanged types.Bool   `tfsdk:"assume_unchanged"`
}

func (r *ngsiemlookupResource) Configure(
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

func (r *ngsiemlookupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_ngsiem_lookup_file"
}

func (r *ngsiemlookupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Next-Gen SIEM",
			"Manages custom lookup files in CrowdStrike Falcon Next-Gen SIEM. Lookup files are CSV or JSON files with external data that you upload to a repository to enrich and correlate with your Falcon data.",
			apiScopesReadWrite,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the lookup file in the format `repository:filename`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"filename": schema.StringAttribute{
				Required:    true,
				Description: "The name of the lookup file (e.g. `my_lookup.csv`). Must include a `.csv` or `.json` extension. File names must not use reserved prefixes: `aid_`, `cs_lookups_`, `cs_`, `ffc_`, `platform_`.",
				Validators: []validator.String{
					fwvalidators.StringNotWhitespace(),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\.(csv|json)$`),
						"filename must end with `.csv` or `.json`",
					),
					filenameNoReservedPrefix(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"repository": schema.StringAttribute{
				Required:    true,
				Description: "The repository to upload the file to. Valid values include: `all`, `search-all`, `investigate_view`, `falcon`, `third-party`, `falcon_for_it_view`, `forensics_view`, `forensics`, `3pi_parsers`.",
				Validators: []validator.String{
					stringvalidator.OneOf(validRepositories...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"content": schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Description: "The lookup file's content. This value is write-only and not stored in state.",
			},
			"content_sha256": schema.StringAttribute{
				Required:    true,
				Description: "SHA256 checksum of the file content. Use `filesha256()` or `sha256()` to compute it. Changes to this value trigger an update.",
			},
			"assume_unchanged": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to `true`, Terraform will not download the file during state refresh and will not detect out-of-band changes made to the file on the server. **NOTE**: Skipping the download entails that there is no way for terraform to detect if the file has been changed on serverside. If you do this, do not rely on terraform for integrity checks.",
			},
		},
	}
}

var validRepositories = []string{
	"all",
	"search-all",
	"investigate_view",
	"falcon",
	"third-party",
	"falcon_for_it_view",
	"forensics_view",
	"forensics",
	"3pi_parsers",
}

var reservedPrefixes = []string{"aid_", "cs_lookups_", "cs_", "ffc_", "platform_"}

type reservedPrefixValidator struct{}

func (v reservedPrefixValidator) Description(_ context.Context) string {
	return "filename must not start with a reserved prefix (aid_, cs_lookups_, cs_, ffc_, platform_)"
}

func (v reservedPrefixValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v reservedPrefixValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := strings.ToLower(req.ConfigValue.ValueString())
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(value, prefix) {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Reserved filename prefix",
				fmt.Sprintf("Filename must not start with the reserved prefix %q.", prefix),
			)
			return
		}
	}
}

func filenameNoReservedPrefix() validator.String {
	return reservedPrefixValidator{}
}

func (r *ngsiemlookupResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config ngsiemlookupResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Content.IsUnknown() && !config.ContentSHA256.IsUnknown() {
		hash := sha256.Sum256([]byte(config.Content.ValueString()))
		computed := hex.EncodeToString(hash[:])
		if config.ContentSHA256.ValueString() != computed {
			resp.Diagnostics.AddAttributeError(
				path.Root("content_sha256"),
				"Content SHA256 mismatch",
				fmt.Sprintf("The provided content_sha256 %q does not match the SHA256 of the content %q.", config.ContentSHA256.ValueString(), computed),
			)
		}
	}
}

// namedReader wraps bytes.Reader to implement runtime.NamedReadCloser.
type namedReader struct {
	name   string
	reader *bytes.Reader
}

func (n *namedReader) Read(p []byte) (int, error) {
	return n.reader.Read(p)
}

func (n *namedReader) Close() error {
	return nil
}

func (n *namedReader) Name() string {
	return n.name
}

func newNamedReader(name string, data []byte) runtime.NamedReadCloser {
	return &namedReader{
		name:   name,
		reader: bytes.NewReader(data),
	}
}

// wrap transforms API response values to their terraform model values.
func (d *ngsiemlookupResourceModel) wrap(
	id string,
	fileContent []byte,
) diag.Diagnostics {
	var diags diag.Diagnostics

	repository, filename, err := parseResourceID(id)
	if err != nil {
		diags.AddError("Invalid Resource ID", err.Error())
		return diags
	}

	d.ID = types.StringValue(id)
	d.Filename = types.StringValue(filename)
	d.Repository = types.StringValue(repository)

	if fileContent != nil {
		hash := sha256.Sum256(fileContent)
		d.ContentSHA256 = types.StringValue(hex.EncodeToString(hash[:]))
	}

	return diags
}

func buildResourceID(repository, filename string) string {
	return repository + ":" + filename
}

func parseResourceID(id string) (repository, filename string, err error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid resource ID format %q, expected repository:filename", id)
	}
	return parts[0], parts[1], nil
}

func (r *ngsiemlookupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	tflog.Trace(ctx, "Starting NGSIEM lookup file create")

	var plan ngsiemlookupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var contentVal types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("content"), &contentVal)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filename := plan.Filename.ValueString()
	repository := plan.Repository.ValueString()
	content := []byte(contentVal.ValueString())

	params := &ngsiem.CreateLookupFileParams{
		Context:      ctx,
		File:         newNamedReader(filename, content),
		Filename:     &filename,
		SearchDomain: &repository,
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to create NGSIEM lookup file")
	res, err := r.client.Ngsiem.CreateLookupFile(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(
			tferrors.Create,
			err,
			apiScopesReadWrite,
		))
		return
	}

	if res == nil || res.Payload == nil {
		resp.Diagnostics.Append(tferrors.NewEmptyResponseError(tferrors.Create))
		return
	}

	plan.ID = types.StringValue(buildResourceID(repository, filename))
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully created NGSIEM lookup file", map[string]any{
		"filename":   filename,
		"repository": repository,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ngsiemlookupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	tflog.Trace(ctx, "Starting NGSIEM lookup file read")

	var state ngsiemlookupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	repository, filename, err := parseResourceID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Resource ID", err.Error())
		return
	}

	var fileContent []byte

	if state.AssumeUnchanged.ValueBool() {
		tflog.Debug(ctx, "Checking NGSIEM lookup file existence (skipping content download)")
		// We only got matching to work with the :~ operator.
		filter := fmt.Sprintf("name:~'%s'", filename)
		listParams := &ngsiem.ListLookupFilesParams{
			Context:      ctx,
			Filter:       &filter,
			SearchDomain: &repository,
		}
		listRes, err := r.client.Ngsiem.ListLookupFiles(listParams)
		if err != nil {
			resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesRead))
			return
		}
		if listRes == nil || listRes.Payload == nil || len(listRes.Payload.Resources) == 0 {
			resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
			resp.State.RemoveResource(ctx)
			return
		}
	} else {
		tflog.Debug(ctx, "Downloading NGSIEM lookup file for drift detection")
		params := &ngsiem.GetLookupFileParams{
			Context:      ctx,
			Filename:     &filename,
			SearchDomain: &repository,
		}
		reader := &lookupFileReader{}
		_, err = r.client.Ngsiem.GetLookupFile(params, func(op *runtime.ClientOperation) {
			op.Reader = reader
		})
		if err != nil {
			d := tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, apiScopesReadWrite)
			if d.Summary() == tferrors.NotFoundErrorSummary {
				resp.Diagnostics.Append(tferrors.NewResourceNotFoundWarningDiagnostic())
				resp.State.RemoveResource(ctx)
				return
			}
			resp.Diagnostics.Append(d)
			return
		}

		fileContent = reader.buf.Bytes()
	}

	resp.Diagnostics.Append(state.wrap(state.ID.ValueString(), fileContent)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully read NGSIEM lookup file", map[string]any{
		"filename":   filename,
		"repository": repository,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ngsiemlookupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	tflog.Trace(ctx, "Starting NGSIEM lookup file update")

	var plan ngsiemlookupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var contentVal types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("content"), &contentVal)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filename := plan.Filename.ValueString()
	repository := plan.Repository.ValueString()
	content := []byte(contentVal.ValueString())

	params := &ngsiem.UpdateLookupFileParams{
		Context:      ctx,
		File:         newNamedReader(filename, content),
		Filename:     &filename,
		SearchDomain: &repository,
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to update NGSIEM lookup file")
	_, err := r.client.Ngsiem.UpdateLookupFile(params)
	if err != nil {
		resp.Diagnostics.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Update, err, apiScopesReadWrite))
		return
	}

	plan.ID = types.StringValue(buildResourceID(repository, filename))

	tflog.Info(ctx, "Successfully updated NGSIEM lookup file", map[string]any{
		"filename":   filename,
		"repository": repository,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ngsiemlookupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Trace(ctx, "Starting NGSIEM lookup file delete")

	var state ngsiemlookupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	repository, filename, err := parseResourceID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Resource ID", err.Error())
		return
	}

	params := &ngsiem.DeleteLookupFileParams{
		Context:      ctx,
		Filename:     &filename,
		SearchDomain: &repository,
	}

	tflog.Debug(ctx, "Calling CrowdStrike API to delete NGSIEM lookup file")
	_, err = r.client.Ngsiem.DeleteLookupFile(params)
	if err != nil {
		diag := tferrors.NewDiagnosticFromAPIError(tferrors.Delete, err, apiScopesReadWrite)
		if diag.Summary() == tferrors.NotFoundErrorSummary {
			return
		}
		resp.Diagnostics.Append(diag)
		return
	}

	tflog.Info(ctx, "Successfully deleted NGSIEM lookup file", map[string]any{
		"filename":   filename,
		"repository": repository,
	})
}

func (r *ngsiemlookupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	repository, filename, err := parseResourceID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format repository:filename, got: %s", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("repository"), repository)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("filename"), filename)...)
}
