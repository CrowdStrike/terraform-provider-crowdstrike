package ioaexclusion

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		groups  []string
		wantErr bool
	}{
		{
			name:    "global_only",
			groups:  []string{"all"},
			wantErr: false,
		},
		{
			name:    "host_groups_only",
			groups:  []string{"abc123", "def456"},
			wantErr: false,
		},
		{
			name:    "all_mixed_with_host_group",
			groups:  []string{"all", "abc123"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateGroups(tc.groups)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestExpandCreateRequestUsesProcessTreeFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"host-group-id"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	plan := IOAExclusionResourceModel{
		Name:                types.StringValue("example"),
		Description:         types.StringValue("example description"),
		PatternID:           types.StringValue("12345"),
		PatternName:         types.StringNull(),
		ClRegex:             types.StringValue(".*--child.*"),
		IfnRegex:            types.StringValue(".*child\\.exe"),
		ParentClRegex:       types.StringValue(".*--parent.*"),
		ParentIfnRegex:      types.StringValue(".*parent\\.exe"),
		GrandparentClRegex:  types.StringValue(".*--grandparent.*"),
		GrandparentIfnRegex: types.StringValue(".*grandparent\\.exe"),
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
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "host-group-id" {
		t.Fatalf("expected host groups to contain host-group-id, got %#v", req.HostGroups)
	}
	if req.Comment != "created by test" {
		t.Fatalf("expected comment to be set, got %q", req.Comment)
	}
}

func TestExpandCreateRequestPreservesLegacyConfiguration(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"all"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	req, reqDiags := expandCreateRequest(ctx, IOAExclusionResourceModel{
		Name:        types.StringValue("example"),
		PatternID:   types.StringValue("12345"),
		ClRegex:     types.StringValue(".*"),
		IfnRegex:    types.StringValue(".*"),
		Groups:      groups,
		Description: types.StringNull(),
		Comment:     types.StringNull(),
	})
	if reqDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", reqDiags)
	}

	if req.ParentClRegex != "" || req.ParentIfnRegex != "" ||
		req.GrandparentClRegex != "" || req.GrandparentIfnRegex != "" {
		t.Fatalf("expected omitted process tree fields to remain empty, got %#v", req)
	}
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "all" {
		t.Fatalf("expected host_groups to preserve all sentinel, got %#v", req.HostGroups)
	}
}

func TestExpandUpdateRequestUsesProcessTreeFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"all"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	plan := IOAExclusionResourceModel{
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
	if req.ParentClRegex != ".*--parent.*" || req.ParentIfnRegex != ".*parent\\.exe" {
		t.Fatalf("expected parent fields to be set, got %#v", req)
	}
	if req.GrandparentClRegex != ".*--grandparent.*" || req.GrandparentIfnRegex != ".*grandparent\\.exe" {
		t.Fatalf("expected grandparent fields to be set, got %#v", req)
	}
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "all" {
		t.Fatalf("expected host_groups to preserve all sentinel, got %#v", req.HostGroups)
	}
}

func TestExpandUpdateRequestClearsOptionalFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"host-group-id"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	req, reqDiags := expandUpdateRequest(ctx, IOAExclusionResourceModel{
		ID:                  types.StringValue("exclusion-id"),
		Name:                types.StringValue("example"),
		PatternID:           types.StringValue("12345"),
		ClRegex:             types.StringValue(".*"),
		IfnRegex:            types.StringValue(".*"),
		Description:         types.StringNull(),
		ParentClRegex:       types.StringNull(),
		ParentIfnRegex:      types.StringNull(),
		GrandparentClRegex:  types.StringNull(),
		GrandparentIfnRegex: types.StringNull(),
		Groups:              groups,
		Comment:             types.StringNull(),
	})
	if reqDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", reqDiags)
	}

	if req.Description != "" || req.Comment != "" ||
		req.ParentClRegex != "" || req.ParentIfnRegex != "" ||
		req.GrandparentClRegex != "" || req.GrandparentIfnRegex != "" {
		t.Fatalf("expected removed optional fields to expand to empty values, got %#v", req)
	}
	if len(req.HostGroups) != 1 || req.HostGroups[0] != "host-group-id" {
		t.Fatalf("expected host_groups to contain host-group-id, got %#v", req.HostGroups)
	}
}

func TestWrapUsesV2ResponseFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	now := strfmtDateTime(t, "2026-03-20T12:00:00Z")
	model := IOAExclusionResourceModel{}

	exclusion := &models.DomainSsIoaExclusionsV2{
		ID:                  utils.Addr("ioa-id"),
		Name:                "example",
		Description:         "example description",
		PatternID:           "12345",
		PatternName:         "Example Pattern",
		ClRegex:             ".*--child.*",
		IfnRegex:            ".*child\\.exe",
		ParentClRegex:       ".*--parent.*",
		ParentIfnRegex:      ".*parent\\.exe",
		GrandparentClRegex:  ".*--grandparent.*",
		GrandparentIfnRegex: ".*grandparent\\.exe",
		HostGroups:          []string{"host-group-id"},
		Comment:             "returned comment",
		AppliedGlobally:     false,
		CreatedBy:           "creator",
		CreatedOn:           now,
		ModifiedBy:          "modifier",
		LastModified:        now,
	}

	diags := model.wrap(ctx, exclusion)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Comment.IsNull() || model.Comment.ValueString() != "returned comment" {
		t.Fatalf("expected returned comment, got %v", model.Comment)
	}
	if model.ParentClRegex.ValueString() != ".*--parent.*" || model.ParentIfnRegex.ValueString() != ".*parent\\.exe" {
		t.Fatalf("expected parent fields in state, got %#v", model)
	}
	if model.GrandparentClRegex.ValueString() != ".*--grandparent.*" || model.GrandparentIfnRegex.ValueString() != ".*grandparent\\.exe" {
		t.Fatalf("expected grandparent fields in state, got %#v", model)
	}

	var groups []string
	diags = model.Groups.ElementsAs(ctx, &groups, false)
	if diags.HasError() {
		t.Fatalf("unexpected group diagnostics: %v", diags)
	}
	if len(groups) != 1 || groups[0] != "host-group-id" {
		t.Fatalf("expected host groups to contain host-group-id, got %#v", groups)
	}
	if model.CreatedOn.IsNull() || model.LastModified.IsNull() {
		t.Fatal("expected timestamps to be set")
	}
}

func TestWrapNormalizesGlobalAndOmittedProcessTreeFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	model := IOAExclusionResourceModel{}
	exclusion := &models.DomainSsIoaExclusionsV2{
		ID:              utils.Addr("ioa-id"),
		Name:            "example",
		PatternID:       "12345",
		ClRegex:         ".*",
		IfnRegex:        ".*",
		AppliedGlobally: true,
	}

	diags := model.wrap(ctx, exclusion)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if !model.ParentClRegex.IsNull() || !model.ParentIfnRegex.IsNull() ||
		!model.GrandparentClRegex.IsNull() || !model.GrandparentIfnRegex.IsNull() {
		t.Fatalf("expected omitted process tree fields to be null, got %#v", model)
	}

	var groups []string
	diags = model.Groups.ElementsAs(ctx, &groups, false)
	if diags.HasError() {
		t.Fatalf("unexpected group diagnostics: %v", diags)
	}
	if len(groups) != 1 || groups[0] != "all" {
		t.Fatalf("expected groups to contain only all, got %#v", groups)
	}
}

func TestExtractIOAExclusionFromV2Payload(t *testing.T) {
	t.Parallel()

	wanted := &models.DomainSsIoaExclusionsV2{ID: utils.Addr("wanted")}
	other := &models.DomainSsIoaExclusionsV2{ID: utils.Addr("other")}

	got, diags := extractIOAExclusionFromPayload(tferrors.Read, &models.DomainSsIoaExclusionsRespV2{
		Resources: []*models.DomainSsIoaExclusionsV2{nil, other, wanted},
	}, "wanted")
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if got != wanted {
		t.Fatalf("expected requested exclusion, got %#v", got)
	}
}

func TestExtractIOAExclusionFromV2PayloadErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		payload      *models.DomainSsIoaExclusionsRespV2
		id           string
		wantNotFound bool
	}{
		{
			name:    "nil payload",
			payload: nil,
		},
		{
			name: "not found payload error",
			payload: &models.DomainSsIoaExclusionsRespV2{Errors: []*models.MsaAPIError{
				{Code: utils.Addr(int32(404)), Message: utils.Addr("not found")},
			}},
			id:           "missing",
			wantNotFound: true,
		},
		{
			name:         "missing requested resource",
			payload:      &models.DomainSsIoaExclusionsRespV2{},
			id:           "missing",
			wantNotFound: true,
		},
		{
			name: "non-not-found payload error",
			payload: &models.DomainSsIoaExclusionsRespV2{Errors: []*models.MsaAPIError{
				{Code: utils.Addr(int32(400)), Message: utils.Addr("invalid request")},
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, diags := extractIOAExclusionFromPayload(tferrors.Read, tc.payload, tc.id)
			if got != nil {
				t.Fatalf("expected no exclusion, got %#v", got)
			}
			if !diags.HasError() {
				t.Fatal("expected error diagnostics")
			}
			if gotNotFound := tferrors.HasNotFoundError(diags); gotNotFound != tc.wantNotFound {
				t.Fatalf("expected not-found=%t, got %t: %v", tc.wantNotFound, gotNotFound, diags)
			}
		})
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
