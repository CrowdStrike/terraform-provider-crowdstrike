package ioaexclusion

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
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

func TestExpandCreateRequestUsesOptionalFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	groups, diags := types.SetValueFrom(ctx, types.StringType, []string{"all"})
	if diags.HasError() {
		t.Fatalf("failed to create set: %v", diags)
	}

	plan := IOAExclusionResourceModel{
		Name:        types.StringValue("example"),
		Description: types.StringValue("example description"),
		PatternID:   types.StringValue("12345"),
		PatternName: types.StringNull(),
		ClRegex:     types.StringValue(".*"),
		IfnRegex:    types.StringValue(".*"),
		Groups:      groups,
		Comment:     types.StringNull(),
	}

	req, reqDiags := expandCreateRequest(ctx, plan)
	if reqDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", reqDiags)
	}

	if req.PatternName == nil {
		t.Fatal("expected pattern name pointer to be set")
	}
	if *req.PatternName != "" {
		t.Fatalf("expected empty pattern name, got %q", *req.PatternName)
	}
	if req.DetectionJSON == nil {
		t.Fatal("expected detection_json pointer to be set")
	}
	if *req.DetectionJSON != "" {
		t.Fatalf("expected empty detection_json, got %q", *req.DetectionJSON)
	}
	if len(req.Groups) != 1 || req.Groups[0] != "all" {
		t.Fatalf("expected groups to contain only all, got %#v", req.Groups)
	}
	if req.Comment != "" {
		t.Fatalf("expected empty comment, got %q", req.Comment)
	}
}

func TestWrapPreservesWriteOnlyCommentAndNormalizesGlobalGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := strfmtDateTime(t, "2026-03-20T12:00:00Z")
	model := IOAExclusionResourceModel{
		Comment: types.StringValue("keep me"),
	}

	exclusion := &models.IoaExclusionsIoaExclusionRespV1{
		ID:              utils.Addr("ioa-id"),
		Name:            utils.Addr("example"),
		Description:     utils.Addr("example description"),
		PatternID:       utils.Addr("12345"),
		PatternName:     utils.Addr(""),
		ClRegex:         utils.Addr(".*"),
		IfnRegex:        utils.Addr(".*"),
		AppliedGlobally: utils.Addr(true),
		CreatedBy:       utils.Addr("creator"),
		CreatedOn:       &now,
		ModifiedBy:      utils.Addr("modifier"),
		LastModified:    &now,
	}

	diags := model.wrap(ctx, exclusion)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if model.Comment.IsNull() || model.Comment.ValueString() != "keep me" {
		t.Fatalf("expected comment to be preserved, got %v", model.Comment)
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
}

func strfmtDateTime(t *testing.T, value string) strfmt.DateTime {
	t.Helper()

	parsed, err := strfmt.ParseDateTime(value)
	if err != nil {
		t.Fatalf("failed to parse time: %v", err)
	}

	return parsed
}
