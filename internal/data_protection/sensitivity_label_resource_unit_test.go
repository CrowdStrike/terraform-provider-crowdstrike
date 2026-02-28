package dataprotection

import (
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestDataProtectionSensitivityLabelResourceModelWrap(t *testing.T) {
	created := strfmt.DateTime(time.Date(2026, time.February, 27, 12, 0, 0, 0, time.UTC))
	updated := strfmt.DateTime(time.Date(2026, time.February, 27, 12, 15, 0, 0, time.UTC))

	label := models.APISensitivityLabelV2{
		ID:                     utils.Addr("label-id"),
		Cid:                    utils.Addr("cid-123"),
		Name:                   utils.Addr("confidential"),
		DisplayName:            utils.Addr("Confidential"),
		ExternalID:             utils.Addr("external-123"),
		LabelProvider:          utils.Addr("microsoft"),
		PluginsConfigurationID: utils.Addr("plugin-config-id"),
		CoAuthoring:            utils.Addr(true),
		Synced:                 utils.Addr(true),
		Created:                &created,
		LastUpdated:            &updated,
	}

	var model dataProtectionSensitivityLabelResourceModel
	model.wrap(label)

	if model.ID.ValueString() != "label-id" {
		t.Fatalf("expected id to be label-id, got %q", model.ID.ValueString())
	}

	if model.CID.ValueString() != "cid-123" {
		t.Fatalf("expected cid to be cid-123, got %q", model.CID.ValueString())
	}

	if model.Name.ValueString() != "confidential" {
		t.Fatalf("expected name to be confidential, got %q", model.Name.ValueString())
	}

	if model.DisplayName.ValueString() != "Confidential" {
		t.Fatalf("expected display_name to be Confidential, got %q", model.DisplayName.ValueString())
	}

	if model.ExternalID.ValueString() != "external-123" {
		t.Fatalf("expected external_id to be external-123, got %q", model.ExternalID.ValueString())
	}

	if model.LabelProvider.ValueString() != "microsoft" {
		t.Fatalf("expected label_provider to be microsoft, got %q", model.LabelProvider.ValueString())
	}

	if model.PluginsConfigurationID.ValueString() != "plugin-config-id" {
		t.Fatalf("expected plugins_configuration_id to be plugin-config-id, got %q", model.PluginsConfigurationID.ValueString())
	}

	if !model.CoAuthoring.ValueBool() {
		t.Fatalf("expected co_authoring to be true")
	}

	if !model.Synced.ValueBool() {
		t.Fatalf("expected synced to be true")
	}

	if model.CreatedAt.ValueString() != created.String() {
		t.Fatalf("expected created_at to be %q, got %q", created.String(), model.CreatedAt.ValueString())
	}

	if model.LastUpdated.ValueString() != updated.String() {
		t.Fatalf("expected last_updated to be %q, got %q", updated.String(), model.LastUpdated.ValueString())
	}
}

func TestBuildSensitivityLabelCreateRequest(t *testing.T) {
	plan := dataProtectionSensitivityLabelResourceModel{
		Name:                   types.StringValue("confidential"),
		LabelProvider:          types.StringValue("microsoft"),
		DisplayName:            types.StringNull(),
		ExternalID:             types.StringNull(),
		PluginsConfigurationID: types.StringNull(),
		CoAuthoring:            types.BoolNull(),
		Synced:                 types.BoolValue(false),
	}

	request := buildSensitivityLabelCreateRequest(plan)
	if request == nil {
		t.Fatal("expected create request to be non-nil")
	}

	if request.Name == nil || *request.Name != "confidential" {
		t.Fatalf("expected name to be %q, got %v", "confidential", request.Name)
	}

	if request.LabelProvider == nil || *request.LabelProvider != "microsoft" {
		t.Fatalf("expected provider to be %q, got %v", "microsoft", request.LabelProvider)
	}

	if request.DisplayName == nil || *request.DisplayName != "" {
		t.Fatalf("expected display_name to default to empty string, got %v", request.DisplayName)
	}

	if request.ExternalID == nil || *request.ExternalID != "" {
		t.Fatalf("expected external_id to default to empty string, got %v", request.ExternalID)
	}

	if request.PluginsConfigurationID == nil || *request.PluginsConfigurationID != "" {
		t.Fatalf("expected plugins_configuration_id to default to empty string, got %v", request.PluginsConfigurationID)
	}

	if request.CoAuthoring == nil || *request.CoAuthoring {
		t.Fatalf("expected co_authoring to default to false, got %v", request.CoAuthoring)
	}

	if request.Synced == nil || *request.Synced {
		t.Fatalf("expected synced to be false, got %v", request.Synced)
	}
}

func TestValidateSensitivityLabelConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        dataProtectionSensitivityLabelResourceModel
		expectedDiags int
	}{
		{
			name: "synced label requires connector fields",
			config: dataProtectionSensitivityLabelResourceModel{
				Synced:                 types.BoolValue(true),
				ExternalID:             types.StringNull(),
				PluginsConfigurationID: types.StringNull(),
				CoAuthoring:            types.BoolNull(),
			},
			expectedDiags: 2,
		},
		{
			name: "synced label allows optional co_authoring",
			config: dataProtectionSensitivityLabelResourceModel{
				Synced:                 types.BoolValue(true),
				ExternalID:             types.StringValue("external-123"),
				PluginsConfigurationID: types.StringValue("plugin-123"),
				CoAuthoring:            types.BoolNull(),
			},
			expectedDiags: 0,
		},
		{
			name: "standard label forbids connector fields and co_authoring",
			config: dataProtectionSensitivityLabelResourceModel{
				Synced:                 types.BoolValue(false),
				ExternalID:             types.StringValue("external-123"),
				PluginsConfigurationID: types.StringValue("plugin-123"),
				CoAuthoring:            types.BoolValue(false),
			},
			expectedDiags: 3,
		},
		{
			name: "unknown synced bypasses validation",
			config: dataProtectionSensitivityLabelResourceModel{
				Synced:                 types.BoolUnknown(),
				ExternalID:             types.StringNull(),
				PluginsConfigurationID: types.StringNull(),
				CoAuthoring:            types.BoolNull(),
			},
			expectedDiags: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diags := validateSensitivityLabelConfig(tt.config)
			if len(diags) != tt.expectedDiags {
				t.Fatalf("expected %d diagnostics, got %d", tt.expectedDiags, len(diags))
			}
		})
	}
}
