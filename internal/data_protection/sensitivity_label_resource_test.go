package dataprotection_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	dataprotection "github.com/crowdstrike/terraform-provider-crowdstrike/internal/data_protection"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccDataProtectionSensitivityLabel_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_sensitivity_label.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensitivityLabelStandardConfig(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("label_provider"), knownvalue.StringExact("microsoft")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("synced"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("co_authoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDataProtectionSensitivityLabel_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_sensitivity_label.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensitivityLabelStandardConfig(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("label_provider"), knownvalue.StringExact("microsoft")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("synced"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("co_authoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("external_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("plugins_configuration_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccSensitivityLabelStandardConfig(rName + "-updated"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("label_provider"), knownvalue.StringExact("microsoft")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("synced"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("co_authoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("external_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("plugins_configuration_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccDataProtectionSensitivityLabel_synced(t *testing.T) {
	rName := acctest.RandomResourceName()
	pluginConfigID := acctest.RandomResourceName()
	resourceName := "crowdstrike_data_protection_sensitivity_label.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccSensitivityLabelSyncedConfig(rName, pluginConfigID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("label_provider"), knownvalue.StringExact("microsoft")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("synced"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("co_authoring"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("external_id"), knownvalue.StringExact(rName+"-external")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("plugins_configuration_id"), knownvalue.StringExact(pluginConfigID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccSensitivityLabelStandardConfig(name string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_sensitivity_label" "test" {
  name           = %[1]q
  label_provider = "microsoft"
}
`, name)
}

func testAccSensitivityLabelSyncedConfig(name, pluginConfigID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_sensitivity_label" "test" {
  name                     = %[1]q
  external_id              = %[3]q
  label_provider           = "microsoft"
  plugins_configuration_id = %[2]q
}
`, name, pluginConfigID, name+"-external")
}

func TestDataProtectionSensitivityLabelWrap(t *testing.T) {
	created := strfmt.DateTime(time.Date(2026, time.February, 27, 12, 0, 0, 0, time.UTC))
	updated := strfmt.DateTime(time.Date(2026, time.February, 27, 12, 15, 0, 0, time.UTC))

	tests := map[string]struct {
		label               models.APISensitivityLabelV2
		wantID              types.String
		wantCID             types.String
		wantName            types.String
		wantExternalID      types.String
		wantLabelProvider   types.String
		wantPluginsConfigID types.String
		wantCoAuthoring     types.Bool
		wantSynced          types.Bool
		wantCreatedAt       types.String
		wantLastUpdated     types.String
	}{
		"standard": {
			label: models.APISensitivityLabelV2{
				ID:                     utils.Addr("label-id"),
				Cid:                    utils.Addr("cid-123"),
				Name:                   utils.Addr("Confidential"),
				DisplayName:            utils.Addr("Confidential"),
				ExternalID:             utils.Addr(""),
				LabelProvider:          utils.Addr("microsoft"),
				PluginsConfigurationID: utils.Addr(""),
				CoAuthoring:            utils.Addr(false),
				Synced:                 utils.Addr(false),
				Created:                &created,
				LastUpdated:            &updated,
			},
			wantID:              types.StringValue("label-id"),
			wantCID:             types.StringValue("cid-123"),
			wantName:            types.StringValue("Confidential"),
			wantExternalID:      types.StringNull(),
			wantLabelProvider:   types.StringValue("microsoft"),
			wantPluginsConfigID: types.StringNull(),
			wantCoAuthoring:     types.BoolValue(false),
			wantSynced:          types.BoolValue(false),
			wantCreatedAt:       types.StringValue(created.String()),
			wantLastUpdated:     types.StringValue(updated.String()),
		},
		"synced": {
			label: models.APISensitivityLabelV2{
				ID:                     utils.Addr("label-id"),
				Cid:                    utils.Addr("cid-123"),
				Name:                   utils.Addr("external-123"),
				DisplayName:            utils.Addr("Confidential"),
				ExternalID:             utils.Addr("external-123"),
				LabelProvider:          utils.Addr("microsoft"),
				PluginsConfigurationID: utils.Addr("plugin-config-id"),
				CoAuthoring:            utils.Addr(false),
				Synced:                 utils.Addr(true),
				Created:                &created,
				LastUpdated:            &updated,
			},
			wantID:              types.StringValue("label-id"),
			wantCID:             types.StringValue("cid-123"),
			wantName:            types.StringValue("Confidential"),
			wantExternalID:      types.StringValue("external-123"),
			wantLabelProvider:   types.StringValue("microsoft"),
			wantPluginsConfigID: types.StringValue("plugin-config-id"),
			wantCoAuthoring:     types.BoolValue(false),
			wantSynced:          types.BoolValue(true),
			wantCreatedAt:       types.StringValue(created.String()),
			wantLastUpdated:     types.StringValue(updated.String()),
		},
		"nil_fields": {
			label: models.APISensitivityLabelV2{
				ID:            utils.Addr("label-id"),
				Cid:           utils.Addr("cid-123"),
				DisplayName:   utils.Addr("Confidential"),
				LabelProvider: utils.Addr("microsoft"),
			},
			wantID:              types.StringValue("label-id"),
			wantCID:             types.StringValue("cid-123"),
			wantName:            types.StringValue("Confidential"),
			wantExternalID:      types.StringNull(),
			wantLabelProvider:   types.StringValue("microsoft"),
			wantPluginsConfigID: types.StringNull(),
			wantCoAuthoring:     types.BoolNull(),
			wantSynced:          types.BoolNull(),
			wantCreatedAt:       types.StringNull(),
			wantLastUpdated:     types.StringNull(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var model dataprotection.DataProtectionSensitivityLabelResourceModel
			model.Wrap(tc.label)

			assert.Equal(t, tc.wantID, model.ID, "id")
			assert.Equal(t, tc.wantCID, model.CID, "cid")
			assert.Equal(t, tc.wantName, model.Name, "name")
			assert.Equal(t, tc.wantExternalID, model.ExternalID, "external_id")
			assert.Equal(t, tc.wantLabelProvider, model.LabelProvider, "label_provider")
			assert.Equal(t, tc.wantPluginsConfigID, model.PluginsConfigurationID, "plugins_configuration_id")
			assert.Equal(t, tc.wantCoAuthoring, model.CoAuthoring, "co_authoring")
			assert.Equal(t, tc.wantSynced, model.Synced, "synced")
			assert.Equal(t, tc.wantCreatedAt, model.CreatedAt, "created_at")
			assert.Equal(t, tc.wantLastUpdated, model.LastUpdated, "last_updated")
		})
	}
}

func TestDataProtectionBuildSensitivityLabelCreateRequest(t *testing.T) {
	tests := map[string]struct {
		model               dataprotection.DataProtectionSensitivityLabelResourceModel
		wantName            string
		wantDisplayName     string
		wantExternalID      string
		wantPluginsConfigID string
		wantSynced          bool
		wantLabelProvider   string
	}{
		"standard": {
			model: dataprotection.DataProtectionSensitivityLabelResourceModel{
				Name:                   types.StringValue("Confidential"),
				LabelProvider:          types.StringValue("microsoft"),
				ExternalID:             types.StringNull(),
				PluginsConfigurationID: types.StringNull(),
			},
			wantName:            "Confidential",
			wantDisplayName:     "",
			wantExternalID:      "",
			wantPluginsConfigID: "",
			wantSynced:          false,
			wantLabelProvider:   "microsoft",
		},
		"synced": {
			model: dataprotection.DataProtectionSensitivityLabelResourceModel{
				Name:                   types.StringValue("Confidential"),
				LabelProvider:          types.StringValue("microsoft"),
				ExternalID:             types.StringValue("external-123"),
				PluginsConfigurationID: types.StringValue("plugin-config-id"),
			},
			wantName:            "external-123",
			wantDisplayName:     "Confidential",
			wantExternalID:      "external-123",
			wantPluginsConfigID: "plugin-config-id",
			wantSynced:          true,
			wantLabelProvider:   "microsoft",
		},
		"partial_external_id_only": {
			model: dataprotection.DataProtectionSensitivityLabelResourceModel{
				Name:                   types.StringValue("Confidential"),
				LabelProvider:          types.StringValue("microsoft"),
				ExternalID:             types.StringValue("external-123"),
				PluginsConfigurationID: types.StringNull(),
			},
			wantName:            "Confidential",
			wantDisplayName:     "external-123",
			wantExternalID:      "external-123",
			wantPluginsConfigID: "",
			wantSynced:          false,
			wantLabelProvider:   "microsoft",
		},
		"partial_plugin_config_only": {
			model: dataprotection.DataProtectionSensitivityLabelResourceModel{
				Name:                   types.StringValue("Confidential"),
				LabelProvider:          types.StringValue("microsoft"),
				ExternalID:             types.StringNull(),
				PluginsConfigurationID: types.StringValue("plugin-config-id"),
			},
			wantName:            "Confidential",
			wantDisplayName:     "",
			wantExternalID:      "",
			wantPluginsConfigID: "plugin-config-id",
			wantSynced:          false,
			wantLabelProvider:   "microsoft",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := dataprotection.BuildSensitivityLabelCreateRequest(tc.model)
			require.NotNil(t, req)

			assert.Equal(t, tc.wantName, *req.Name, "name")
			assert.Equal(t, tc.wantDisplayName, *req.DisplayName, "display_name")
			assert.Equal(t, tc.wantExternalID, *req.ExternalID, "external_id")
			assert.Equal(t, tc.wantPluginsConfigID, *req.PluginsConfigurationID, "plugins_configuration_id")
			assert.Equal(t, tc.wantSynced, *req.Synced, "synced")
			assert.Equal(t, tc.wantLabelProvider, *req.LabelProvider, "label_provider")
		})
	}
}
