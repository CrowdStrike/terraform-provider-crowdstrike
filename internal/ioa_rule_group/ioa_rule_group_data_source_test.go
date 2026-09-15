package ioarulegroup_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/require"
)

func TestAccIOARuleGroupDataSource(t *testing.T) {
	for _, platform := range []string{"Linux", "Mac", "Windows"} {
		t.Run(platform, func(t *testing.T) {
			name := acctest.RandomResourceName()
			checks := []statecheck.StateCheck{}
			for _, attribute := range []string{"id", "name", "platform", "description", "enabled", "created_by", "created_on", "modified_by", "modified_on", "committed_on", "cid", "deleted"} {
				checks = append(checks, statecheck.CompareValuePairs(
					"crowdstrike_ioa_rule_group.test", tfjsonpath.New(attribute),
					"data.crowdstrike_ioa_rule_group.test", tfjsonpath.New(attribute), compare.ValuesSame(),
				))
			}
			for _, attribute := range []string{"instance_id", "name", "description", "pattern_severity", "type", "action", "enabled", "image_filename"} {
				field := tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey(attribute)
				checks = append(checks, statecheck.CompareValuePairs("crowdstrike_ioa_rule_group.test", field, "data.crowdstrike_ioa_rule_group.test", field, compare.ValuesSame()))
			}
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{Config: testAccIOARuleGroupDataSourceConfig(name, platform, true), ConfigStateChecks: checks},
					{Config: testAccIOARuleGroupDataSourceConfig(name, platform, false), ConfigStateChecks: checks},
					{Config: testAccIOARuleGroupDataSourceConfig(name+"-renamed", platform, false), ConfigStateChecks: checks},
				},
			})
		})
	}
}

func testAccIOARuleGroupDataSourceConfig(name, platform string, byID bool) string {
	lookup := "name = crowdstrike_ioa_rule_group.test.name\nplatform = crowdstrike_ioa_rule_group.test.platform"
	if byID {
		lookup = "id = crowdstrike_ioa_rule_group.test.id"
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
 name        = %[1]q
 platform    = %[2]q
 description = "Synthetic group for data source acceptance tests"
 enabled     = false
 rules = [{
  name             = "Example process rule"
  description      = "Synthetic process match"
  pattern_severity = "low"
  type             = "Process Creation"
  action           = "Detect"
  enabled          = false
  image_filename   = { include = ".*example-test-process.*" }
 }]
}

data "crowdstrike_ioa_rule_group" "test" {
 %[3]s
 depends_on = [crowdstrike_ioa_rule_group.test]
}
`, name, platform, lookup)
}

func TestIOARuleGroupDataSourceConfigValidation(t *testing.T) {
	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	require.NoError(t, err)
	schema, err := server.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	objectType, ok := schema.DataSourceSchemas["crowdstrike_ioa_rule_group"].ValueType().(tftypes.Object)
	require.True(t, ok)
	tests := map[string]struct {
		values    map[string]any
		wantError bool
	}{
		"by id":                {values: map[string]any{"id": "11111111111111111111111111111111"}},
		"by name":              {values: map[string]any{"name": "Example IOAs"}},
		"by name and platform": {values: map[string]any{"name": "Example IOAs", "platform": "Linux"}},
		"unknown id":           {values: map[string]any{"id": tftypes.UnknownValue}},
		"unknown name":         {values: map[string]any{"name": tftypes.UnknownValue}},
		"unknown platform":     {values: map[string]any{"name": "Example IOAs", "platform": tftypes.UnknownValue}},
		"neither":              {wantError: true},
		"both":                 {values: map[string]any{"id": "11111111111111111111111111111111", "name": "Example IOAs"}, wantError: true},
		"short id":             {values: map[string]any{"id": "short"}, wantError: true},
		"empty name":           {values: map[string]any{"name": ""}, wantError: true},
		"whitespace name":      {values: map[string]any{"name": "  "}, wantError: true},
		"invalid platform":     {values: map[string]any{"name": "Example IOAs", "platform": "other"}, wantError: true},
		"computed field":       {values: map[string]any{"name": "Example IOAs", "enabled": true}, wantError: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			values := map[string]tftypes.Value{}
			for key, typ := range objectType.AttributeTypes {
				values[key] = tftypes.NewValue(typ, tc.values[key])
			}
			config, err := tfprotov6.NewDynamicValue(objectType, tftypes.NewValue(objectType, values))
			require.NoError(t, err)
			response, err := server.ValidateDataResourceConfig(t.Context(), &tfprotov6.ValidateDataResourceConfigRequest{TypeName: "crowdstrike_ioa_rule_group", Config: &config})
			require.NoError(t, err)
			hasError := false
			for _, diagnostic := range response.Diagnostics {
				if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
					hasError = true
				}
			}
			require.Equal(t, tc.wantError, hasError, "%v", response.Diagnostics)
		})
	}
}
