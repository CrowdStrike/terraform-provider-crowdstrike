package selfserviceioaexclusion

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestExpandCreateRequestUsesAllRegexFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"host-group-id"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	plan := SelfServiceIOAExclusionResourceModel{
		Name:                types.StringValue("example"),
		Description:         types.StringValue("example description"),
		PatternID:           types.StringValue("12345"),
		PatternName:         types.StringValue("Example Pattern"),
		ClRegex:             types.StringValue(".*--child.*"),
		IfnRegex:            types.StringValue(".*child\\.exe"),
		ParentClRegex:       types.StringValue(".*--parent.*"),
		ParentIfnRegex:      types.StringValue(".*parent\\.exe"),
		GrandparentClRegex:  types.StringValue(".*--grandparent.*"),
		GrandparentIfnRegex: types.StringValue(".*grandparent\\.exe"),
		DetectionJSON:       types.StringValue(`{"key":"value"}`),
		Groups:              groups,
		Comment:             types.StringValue("created by test"),
	}

	req, reqDiags := expandCreateRequest(ctx, plan)
	if reqDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", reqDiags)
	}

	if req.Name == nil || *req.Name != "example" {
		t.Fatalf("expected name to be set, got %#v", req.Name)
	}
	if req.ClRegex == nil || *req.ClRegex != ".*--child.*" {
		t.Fatalf("expected cl_regex to be set, got %#v", req.ClRegex)
	}
	if req.IfnRegex == nil || *req.IfnRegex != ".*child\\.exe" {
		t.Fatalf("expected ifn_regex to be set, got %#v", req.IfnRegex)
	}
	if req.ParentClRegex != ".*--parent.*" {
		t.Fatalf("expected parent_cl_regex to be set, got %q", req.ParentClRegex)
	}
	if req.ParentIfnRegex != ".*parent\\.exe" {
		t.Fatalf("expected parent_ifn_regex to be set, got %q", req.ParentIfnRegex)
	}
	if req.GrandparentClRegex != ".*--grandparent.*" {
		t.Fatalf("expected grandparent_cl_regex to be set, got %q", req.GrandparentClRegex)
	}
	if req.GrandparentIfnRegex != ".*grandparent\\.exe" {
		t.Fatalf("expected grandparent_ifn_regex to be set, got %q", req.GrandparentIfnRegex)
	}
	if req.DetectionJSON != `{"key":"value"}` {
		t.Fatalf("expected detection_json to be set, got %q", req.DetectionJSON)
	}
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "host-group-id" {
		t.Fatalf("expected host groups to contain host-group-id, got %#v", req.HostGroups)
	}
	if req.Comment != "created by test" {
		t.Fatalf("expected comment to be set, got %q", req.Comment)
	}
}

func TestExpandCreateRequestAllowsOmittedHostGroups(t *testing.T) {
	t.Parallel()

	req, diags := expandCreateRequest(context.Background(), SelfServiceIOAExclusionResourceModel{
		Name:      types.StringValue("example"),
		PatternID: types.StringValue("12345"),
		ClRegex:   types.StringValue(".*"),
		IfnRegex:  types.StringValue(".*"),
		Groups:    types.SetNull(types.StringType),
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if req.HostGroups != nil {
		t.Fatalf("expected omitted host_groups to remain nil, got %#v", req.HostGroups)
	}
}

func TestExpandCreateRequestDoesNotCompileRegexLocally(t *testing.T) {
	t.Parallel()

	req, diags := expandCreateRequest(context.Background(), SelfServiceIOAExclusionResourceModel{
		Name:      types.StringValue("example"),
		PatternID: types.StringValue("12345"),
		ClRegex:   types.StringValue("["),
		IfnRegex:  types.StringValue("("),
		Groups:    types.SetNull(types.StringType),
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics for syntactically invalid Go regex: %v", diags)
	}

	if req.ClRegex == nil || *req.ClRegex != "[" {
		t.Fatalf("expected cl_regex to pass through unchanged, got %#v", req.ClRegex)
	}
	if req.IfnRegex == nil || *req.IfnRegex != "(" {
		t.Fatalf("expected ifn_regex to pass through unchanged, got %#v", req.IfnRegex)
	}
}

func TestExpandUpdateRequestUsesAllRegexFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"all"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	plan := SelfServiceIOAExclusionResourceModel{
		ID:                  types.StringValue("exclusion-id"),
		Name:                types.StringValue("example"),
		Description:         types.StringValue("example description"),
		PatternID:           types.StringValue("12345"),
		PatternName:         types.StringValue("Example Pattern"),
		ClRegex:             types.StringValue(".*--child.*"),
		IfnRegex:            types.StringValue(".*child\\.exe"),
		ParentClRegex:       types.StringValue(".*--parent.*"),
		ParentIfnRegex:      types.StringValue(".*parent\\.exe"),
		GrandparentClRegex:  types.StringValue(".*--grandparent.*"),
		GrandparentIfnRegex: types.StringValue(".*grandparent\\.exe"),
		DetectionJSON:       types.StringValue(`{"key":"value"}`),
		Groups:              groups,
		Comment:             types.StringValue("updated by test"),
	}

	req, reqDiags := expandUpdateRequest(ctx, plan)
	if reqDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", reqDiags)
	}

	if req.ID == nil || *req.ID != "exclusion-id" {
		t.Fatalf("expected id to be set, got %#v", req.ID)
	}
	if req.ParentClRegex != ".*--parent.*" {
		t.Fatalf("expected parent_cl_regex to be set, got %q", req.ParentClRegex)
	}
	if req.ParentIfnRegex != ".*parent\\.exe" {
		t.Fatalf("expected parent_ifn_regex to be set, got %q", req.ParentIfnRegex)
	}
	if req.GrandparentClRegex != ".*--grandparent.*" {
		t.Fatalf("expected grandparent_cl_regex to be set, got %q", req.GrandparentClRegex)
	}
	if req.GrandparentIfnRegex != ".*grandparent\\.exe" {
		t.Fatalf("expected grandparent_ifn_regex to be set, got %q", req.GrandparentIfnRegex)
	}
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "all" {
		t.Fatalf("expected host groups to contain all, got %#v", req.HostGroups)
	}
}

func TestWrapPreservesWriteOnlyCommentAndNormalizesGlobalGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := strfmtDateTime(t, "2026-03-20T12:00:00Z")
	model := SelfServiceIOAExclusionResourceModel{
		Comment:     types.StringValue("keep me"),
		PatternName: types.StringValue("Configured Pattern"),
	}

	exclusion := &models.DomainSsIoaExclusionsV2{
		ID:              utils.Addr("ioa-id"),
		Name:            "example",
		Description:     "example description",
		PatternID:       "12345",
		PatternName:     "",
		ClRegex:         ".*",
		IfnRegex:        ".*",
		AppliedGlobally: true,
		CreatedBy:       "creator",
		CreatedOn:       now,
		ModifiedBy:      "modifier",
		LastModified:    now,
	}

	diags := model.wrap(ctx, exclusion)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Comment.IsNull() || model.Comment.ValueString() != "keep me" {
		t.Fatalf("expected comment to be preserved, got %v", model.Comment)
	}
	if model.PatternName.IsNull() || model.PatternName.ValueString() != "Configured Pattern" {
		t.Fatalf("expected configured pattern name to be preserved, got %v", model.PatternName)
	}
	if !model.AppliedGlobally.ValueBool() {
		t.Fatalf("expected applied_globally to be true")
	}
	if model.Groups.IsNull() || model.Groups.IsUnknown() {
		t.Fatal("expected groups to be known")
	}

	var groups []string
	diags = model.Groups.ElementsAs(ctx, &groups, false)
	if diags.HasError() {
		t.Fatalf("unexpected group diagnostics: %v", diags)
	}
	if len(groups) != 1 || groups[0] != "all" {
		t.Fatalf("expected groups to contain only all, got %#v", groups)
	}
	if model.CreatedOn.IsNull() || model.LastModified.IsNull() {
		t.Fatal("expected timestamps to be set")
	}
}

func TestWrapUsesReturnedCommentAndHostGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	model := SelfServiceIOAExclusionResourceModel{}

	exclusion := &models.DomainSsIoaExclusionsV2{
		ID:              utils.Addr("ioa-id"),
		Name:            "example",
		PatternID:       "12345",
		ClRegex:         ".*",
		IfnRegex:        ".*",
		HostGroups:      []string{"host-group-id"},
		Comment:         "returned comment",
		AppliedGlobally: false,
	}

	diags := model.wrap(ctx, exclusion)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Comment.IsNull() || model.Comment.ValueString() != "returned comment" {
		t.Fatalf("expected returned comment, got %v", model.Comment)
	}

	var groups []string
	diags = model.Groups.ElementsAs(ctx, &groups, false)
	if diags.HasError() {
		t.Fatalf("unexpected group diagnostics: %v", diags)
	}
	if len(groups) != 1 || groups[0] != "host-group-id" {
		t.Fatalf("expected host groups to contain host-group-id, got %#v", groups)
	}
}

func strfmtDateTime(t *testing.T, value string) strfmt.DateTime {
	t.Helper()

	parsed, err := strfmt.ParseDateTime(value)
	if err != nil {
		t.Fatalf("failed to parse time: %v", err)
	}

	return parsed
}
