package mlcertificateexclusion

import (
	"context"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestHasGlobalHostGroup(t *testing.T) {
	testCases := []struct {
		name       string
		hostGroups []string
		want       bool
	}{
		{name: "global", hostGroups: []string{"all"}, want: true},
		{name: "global_case_insensitive", hostGroups: []string{"ALL"}, want: true},
		{name: "targeted", hostGroups: []string{"hg-1", "hg-2"}, want: false},
		{name: "empty", hostGroups: nil, want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasGlobalHostGroup(tc.hostGroups); got != tc.want {
				t.Fatalf("hasGlobalHostGroup(%v) = %v, want %v", tc.hostGroups, got, tc.want)
			}
		})
	}
}

func TestExpandCertificateRequest(t *testing.T) {
	ctx := context.Background()
	certificateObject := types.ObjectValueMust(
		certificateModel{}.AttributeTypes(),
		map[string]attr.Value{
			"issuer":     types.StringValue("CN=Issuer,O=Example Corp,C=US"),
			"serial":     types.StringValue("1234567890"),
			"subject":    types.StringValue("CN=Subject,O=Example Corp,C=US"),
			"thumbprint": types.StringValue("thumbprint-1234"),
			"valid_from": timetypes.NewRFC3339TimeValue(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)),
			"valid_to":   timetypes.NewRFC3339TimeValue(time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)),
		},
	)

	request, diags := expandCertificateRequest(ctx, certificateObject)
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
	if request == nil {
		t.Fatal("expected request, got nil")
	}
	if got := request.ValidFrom.String(); got != "2024-01-01T00:00:00.000Z" {
		t.Fatalf("unexpected valid_from: %s", got)
	}
	if got := request.ValidTo.String(); got != "2025-01-01T00:00:00.000Z" {
		t.Fatalf("unexpected valid_to: %s", got)
	}
}

func TestWrapPreservesOptionalNullsAndFlattensCertificate(t *testing.T) {
	ctx := context.Background()
	validFrom := strfmt.DateTime(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))
	validTo := strfmt.DateTime(time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC))
	createdOn := strfmt.DateTime(time.Date(2024, time.January, 2, 0, 0, 0, 0, time.UTC))
	modifiedOn := strfmt.DateTime(time.Date(2024, time.January, 3, 0, 0, 0, 0, time.UTC))

	model := mlCertificateExclusionResourceModel{
		Description: types.StringNull(),
		Comment:     types.StringNull(),
		HostGroups:  types.SetNull(types.StringType),
		Certificate: types.ObjectValueMust(
			certificateModel{}.AttributeTypes(),
			map[string]attr.Value{
				"issuer":     types.StringValue("CN=Issuer,O=Example Corp,C=US"),
				"serial":     types.StringValue("1234567890"),
				"subject":    types.StringValue("CN=Subject,O=Example Corp,C=US"),
				"thumbprint": types.StringValue("thumbprint-1234"),
				"valid_from": timetypes.NewRFC3339TimeValue(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)),
				"valid_to":   timetypes.NewRFC3339TimeValue(time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)),
			},
		),
	}

	diags := model.wrap(ctx, &models.APICertBasedExclusionV1{
		ID:              utils.Addr("test-id"),
		Name:            "test-name",
		Description:     "",
		Comment:         "",
		Status:          "enabled",
		AppliedGlobally: true,
		CreatedBy:       "creator@example.com",
		CreatedOn:       createdOn,
		ModifiedBy:      "modifier@example.com",
		ModifiedOn:      modifiedOn,
		Certificate: &models.APICertificateV1{
			Issuer:     utils.Addr("CN=Issuer,O=Example Corp,C=US"),
			Serial:     utils.Addr("1234567890"),
			Subject:    utils.Addr("CN=Subject,O=Example Corp,C=US"),
			Thumbprint: utils.Addr("thumbprint-1234"),
			ValidFrom:  &validFrom,
			ValidTo:    &validTo,
		},
	})
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
	if !model.Description.IsNull() {
		t.Fatalf("expected description to remain null, got %s", model.Description.ValueString())
	}
	if !model.Comment.IsNull() {
		t.Fatalf("expected comment to remain null, got %s", model.Comment.ValueString())
	}

	var hostGroups []string
	diags = model.HostGroups.ElementsAs(ctx, &hostGroups, false)
	if diags.HasError() {
		t.Fatalf("expected host_groups to decode, got %v", diags)
	}
	if len(hostGroups) != 1 || hostGroups[0] != "all" {
		t.Fatalf("expected host_groups to be [\"all\"] for global exclusion, got %v", hostGroups)
	}

	var certificate certificateModel
	diags = model.Certificate.As(ctx, &certificate, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		t.Fatalf("expected certificate object to decode, got %v", diags)
	}

	wantFrom := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	gotFrom, fromDiags := certificate.ValidFrom.ValueRFC3339Time()
	if fromDiags.HasError() {
		t.Fatalf("expected valid_from to parse, got %v", fromDiags)
	}
	if !gotFrom.Equal(wantFrom) {
		t.Fatalf("unexpected flattened valid_from: got %v, want %v", gotFrom, wantFrom)
	}

	wantTo := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	gotTo, toDiags := certificate.ValidTo.ValueRFC3339Time()
	if toDiags.HasError() {
		t.Fatalf("expected valid_to to parse, got %v", toDiags)
	}
	if !gotTo.Equal(wantTo) {
		t.Fatalf("unexpected flattened valid_to: got %v, want %v", gotTo, wantTo)
	}
}
