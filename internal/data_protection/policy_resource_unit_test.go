package dataprotection

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestDataProtectionPolicyResourceModelWrapAndExpand(t *testing.T) {
	ctx := context.Background()
	enableContentInspection := true

	policy := &models.PolicymanagerExternalPolicy{
		ID:           utils.Addr("policy-id"),
		Cid:          utils.Addr("cid-123"),
		Name:         utils.Addr("policy-name"),
		Description:  utils.Addr("policy-description"),
		PlatformName: utils.Addr("win"),
		IsEnabled:    utils.Addr(false),
		IsDefault:    utils.Addr(false),
		PolicyType:   utils.Addr("data-protection"),
		Precedence:   utils.Addr(int32(1)),
		CreatedAt:    utils.Addr("2026-02-28T00:00:00Z"),
		CreatedBy:    utils.Addr("tester@example.com"),
		ModifiedAt:   utils.Addr("2026-02-28T00:10:00Z"),
		ModifiedBy:   utils.Addr("tester@example.com"),
		HostGroups:   []string{"host-group-1"},
		PolicyProperties: &models.PolicymanagerPolicyProperties{
			Classifications:         []string{"classification-1", "classification-2"},
			EnableContentInspection: &enableContentInspection,
			MinConfidenceLevel:      "medium",
			SimilarityDetection:     true,
			SimilarityThreshold:     "80",
			EujDropdownOptions: &models.PolicymanagerEUJDropdownOptions{
				Justifications: []*models.PolicymanagerEUJOption{
					{
						Default:       utils.Addr(true),
						ID:            utils.Addr("business"),
						Justification: utils.Addr("Business purposes"),
						Selected:      utils.Addr(true),
					},
				},
			},
			EujHeaderText: &models.PolicymanagerEUJHeaderText{
				Headers: []*models.PolicymanagerEUJHeader{
					{
						Default:  utils.Addr(true),
						Header:   utils.Addr("Provide a justification"),
						Selected: utils.Addr(true),
					},
				},
			},
		},
	}

	var model dataProtectionPolicyResourceModel
	diags := model.wrap(ctx, policy)
	if diags.HasError() {
		t.Fatalf("unexpected wrap diagnostics: %v", diags)
	}

	if model.ID.ValueString() != "policy-id" {
		t.Fatalf("expected id to be policy-id, got %q", model.ID.ValueString())
	}
	if model.PlatformName.ValueString() != "win" {
		t.Fatalf("expected platform_name to be win, got %q", model.PlatformName.ValueString())
	}
	if model.Precedence.ValueInt32() != 1 {
		t.Fatalf("expected precedence to be 1, got %d", model.Precedence.ValueInt32())
	}
	if model.HostGroups.IsNull() {
		t.Fatal("expected host_groups to be populated")
	}

	var properties dataProtectionPolicyPropertiesModel
	diags = model.PolicyProperties.As(ctx, &properties, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		t.Fatalf("unexpected policy_properties diagnostics: %v", diags)
	}

	if properties.MinConfidenceLevel.ValueString() != "medium" {
		t.Fatalf("expected min_confidence_level to be medium, got %q", properties.MinConfidenceLevel.ValueString())
	}
	if !properties.SimilarityDetection.ValueBool() {
		t.Fatal("expected similarity_detection to be true")
	}

	var expandDiags diag.Diagnostics
	expanded := expandDataProtectionPolicyProperties(ctx, model.PolicyProperties, &expandDiags)
	if expandDiags.HasError() {
		t.Fatalf("unexpected expand diagnostics: %v", expandDiags)
	}
	if expanded == nil {
		t.Fatal("expected expanded policy properties")
	}
	if expanded.MinConfidenceLevel != "medium" {
		t.Fatalf("expected expanded min_confidence_level to be medium, got %q", expanded.MinConfidenceLevel)
	}
	if expanded.SimilarityThreshold != "80" {
		t.Fatalf("expected expanded similarity_threshold to be 80, got %q", expanded.SimilarityThreshold)
	}
	if expanded.EujDropdownOptions == nil || len(expanded.EujDropdownOptions.Justifications) != 1 {
		t.Fatal("expected one expanded justification option")
	}
	if expanded.EujHeaderText == nil || len(expanded.EujHeaderText.Headers) != 1 {
		t.Fatal("expected one expanded header entry")
	}
}
