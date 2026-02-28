package dataprotection

import (
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
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
