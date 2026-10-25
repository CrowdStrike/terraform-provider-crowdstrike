package mlfilepathexclusion_test

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

func TestAccMLFilePathExclusionDataSource(t *testing.T) {
	name := acctest.RandomResourceName()
	pattern := "/tmp/" + name + "/*"
	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	require.NoError(t, err)
	schemas, err := server.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	checks := []statecheck.StateCheck{}
	for _, attribute := range schemas.DataSourceSchemas["crowdstrike_ml_file_path_exclusion"].Block.Attributes {
		name := attribute.Name
		if name == "last_updated" || name == "comment" {
			continue
		}
		checks = append(checks, statecheck.CompareValuePairs("crowdstrike_ml_file_path_exclusion.test", tfjsonpath.New(name), "data.crowdstrike_ml_file_path_exclusion.test", tfjsonpath.New(name), compare.ValuesSame()))
	}
	base := testAccMLFilePathExclusionConfig_basic(pattern, name)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{Config: base + testAccMLFilePathExclusionDataSourceLookup(true), ConfigStateChecks: checks},
			{Config: base + testAccMLFilePathExclusionDataSourceLookup(false), ConfigStateChecks: checks},
		},
	})
}

func testAccMLFilePathExclusionDataSourceLookup(byID bool) string {
	lookup := `pattern = crowdstrike_ml_file_path_exclusion.test.pattern`
	if byID {
		lookup = "id = crowdstrike_ml_file_path_exclusion.test.id"
	}
	return fmt.Sprintf(`
data "crowdstrike_ml_file_path_exclusion" "test" {
%s
depends_on = [crowdstrike_ml_file_path_exclusion.test]
}
`, lookup)
}

func TestMLFilePathExclusionDataSourceConfigValidation(t *testing.T) {
	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	require.NoError(t, err)
	schemas, err := server.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	require.NoError(t, err)
	objectType, ok := schemas.DataSourceSchemas["crowdstrike_ml_file_path_exclusion"].ValueType().(tftypes.Object)
	require.True(t, ok)
	tests := map[string]struct {
		values    map[string]any
		wantError bool
	}{
		"id":              {values: map[string]any{"id": "11111111111111111111111111111111"}, wantError: false},
		"lookup":          {values: map[string]any{"pattern": "/opt/example/cache/*"}, wantError: false},
		"unknown id":      {values: map[string]any{"id": tftypes.UnknownValue}, wantError: false},
		"unknown lookup":  {values: map[string]any{"pattern": tftypes.UnknownValue}, wantError: false},
		"neither":         {values: map[string]any{}, wantError: true},
		"both":            {values: map[string]any{"id": "11111111111111111111111111111111", "pattern": "/opt/example/cache/*"}, wantError: true},
		"empty id":        {values: map[string]any{"id": ""}, wantError: true},
		"blank lookup":    {values: map[string]any{"pattern": "  "}, wantError: true},
		"computed output": {values: map[string]any{"id": "11111111111111111111111111111111", "applied_globally": true}, wantError: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			values := map[string]tftypes.Value{}
			for key, typ := range objectType.AttributeTypes {
				values[key] = tftypes.NewValue(typ, tc.values[key])
			}
			config, err := tfprotov6.NewDynamicValue(objectType, tftypes.NewValue(objectType, values))
			require.NoError(t, err)
			response, err := server.ValidateDataResourceConfig(t.Context(), &tfprotov6.ValidateDataResourceConfigRequest{TypeName: "crowdstrike_ml_file_path_exclusion", Config: &config})
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
