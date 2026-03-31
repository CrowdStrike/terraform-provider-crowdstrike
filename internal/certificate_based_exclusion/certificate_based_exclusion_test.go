package certificatebasedexclusion

import (
	"context"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidateTargetingMode(t *testing.T) {
	testCases := []struct {
		name            string
		appliedGlobally bool
		hostGroupCount  int
		wantErr         bool
	}{
		{name: "global", appliedGlobally: true, hostGroupCount: 0, wantErr: false},
		{name: "targeted", appliedGlobally: false, hostGroupCount: 1, wantErr: false},
		{name: "both", appliedGlobally: true, hostGroupCount: 1, wantErr: true},
		{name: "neither", appliedGlobally: false, hostGroupCount: 0, wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTargetingMode(tc.appliedGlobally, tc.hostGroupCount)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
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
			"valid_from": types.StringValue("2024-01-01T00:00:00Z"),
			"valid_to":   types.StringValue("2025-01-01T00:00:00Z"),
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

	model := CertificateBasedExclusionResourceModel{
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
				"valid_from": types.StringValue("2024-01-01T00:00:00Z"),
				"valid_to":   types.StringValue("2025-01-01T00:00:00Z"),
			},
		),
	}

	diags := model.wrap(ctx, &models.APICertBasedExclusionV1{
		ID:              utils.Addr("test-id"),
		Name:            "test-name",
		Description:     "",
		Comment:         "",
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
	if !model.HostGroups.IsNull() {
		t.Fatalf("expected host_groups to remain null for a global exclusion")
	}

	var certificate certificateModel
	diags = model.Certificate.As(ctx, &certificate, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		t.Fatalf("expected certificate object to decode, got %v", diags)
	}
	if certificate.ValidFrom.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected flattened valid_from: %s", certificate.ValidFrom.ValueString())
	}
	if certificate.ValidTo.ValueString() != "2025-01-01T00:00:00Z" {
		t.Fatalf("unexpected flattened valid_to: %s", certificate.ValidTo.ValueString())
	}
}

func TestPlanAwareDateTimeValueFallsBackToNormalizedAPIValue(t *testing.T) {
	apiValue := strfmt.DateTime(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))

	got := planAwareDateTimeValue(types.StringValue("2024-01-02T00:00:00Z"), &apiValue)

	if got.ValueString() != "2024-01-01T00:00:00.000Z" {
		t.Fatalf("expected normalized API value, got %s", got.ValueString())
	}
}
