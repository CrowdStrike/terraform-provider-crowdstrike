package customioc_test

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

func TestAccCustomIOCDataSource(t *testing.T) {
	name := acctest.RandomResourceName()
	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	require.NoError(t, err)
	schemas, err := server.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	checks := []statecheck.StateCheck{}
	for _, attribute := range schemas.DataSourceSchemas["crowdstrike_custom_ioc"].Block.Attributes {
		name := attribute.Name
		checks = append(checks, statecheck.CompareValuePairs("crowdstrike_custom_ioc.test", tfjsonpath.New(name), "data.crowdstrike_custom_ioc.test", tfjsonpath.New(name), compare.ValuesSame()))
	}
	base := testAccCustomIOCConfig_basic(name)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{Config: base + testAccCustomIOCDataSourceLookup(true), ConfigStateChecks: checks},
			{Config: base + testAccCustomIOCDataSourceLookup(false), ConfigStateChecks: checks},
		},
	})
}

func testAccCustomIOCDataSourceLookup(byID bool) string {
	lookup := `type = crowdstrike_custom_ioc.test.type
value = crowdstrike_custom_ioc.test.value`
	if byID {
		lookup = "id = crowdstrike_custom_ioc.test.id"
	}
	return fmt.Sprintf(`
data "crowdstrike_custom_ioc" "test" {
%s
depends_on = [crowdstrike_custom_ioc.test]
}
`, lookup)
}

func TestCustomIOCDataSourceConfigValidation(t *testing.T) {
	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	require.NoError(t, err)
	schemas, err := server.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	objectType, ok := schemas.DataSourceSchemas["crowdstrike_custom_ioc"].ValueType().(tftypes.Object)
	require.True(t, ok)
	tests := map[string]struct {
		values    map[string]any
		wantError bool
	}{
		"id":              {values: map[string]any{"id": "11111111111111111111111111111111"}, wantError: false},
		"lookup":          {values: map[string]any{"type": "domain", "value": "sample.example.com"}, wantError: false},
		"unknown id":      {values: map[string]any{"id": tftypes.UnknownValue}, wantError: false},
		"unknown lookup":  {values: map[string]any{"type": "domain", "value": tftypes.UnknownValue}, wantError: false},
		"neither":         {values: map[string]any{}, wantError: true},
		"both":            {values: map[string]any{"id": "11111111111111111111111111111111", "type": "domain", "value": "sample.example.com"}, wantError: true},
		"empty id":        {values: map[string]any{"id": ""}, wantError: true},
		"blank lookup":    {values: map[string]any{"type": "domain", "value": "  "}, wantError: true},
		"computed output": {values: map[string]any{"id": "11111111111111111111111111111111", "applied_globally": true}, wantError: true},
		"type only":       {values: map[string]any{"type": "domain"}, wantError: true},
		"value only":      {values: map[string]any{"value": "sample.example.com"}, wantError: true},
		"invalid type":    {values: map[string]any{"type": "bad", "value": "sample.example.com"}, wantError: true},
		"id and type":     {values: map[string]any{"id": "11111111111111111111111111111111", "type": "domain"}, wantError: true},
		"id and value":    {values: map[string]any{"id": "11111111111111111111111111111111", "value": "sample.example.com"}, wantError: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			values := map[string]tftypes.Value{}
			for key, typ := range objectType.AttributeTypes {
				values[key] = tftypes.NewValue(typ, tc.values[key])
			}
			config, err := tfprotov6.NewDynamicValue(objectType, tftypes.NewValue(objectType, values))
			require.NoError(t, err)
			response, err := server.ValidateDataResourceConfig(t.Context(), &tfprotov6.ValidateDataResourceConfigRequest{TypeName: "crowdstrike_custom_ioc", Config: &config})
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
