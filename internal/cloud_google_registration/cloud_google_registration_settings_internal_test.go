package cloudgoogleregistration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func testAgentlessScanningSettingsObject(t *testing.T, dspm types.Object) types.Object {
	t.Helper()
	ctx := context.Background()

	regions, diags := types.SetValueFrom(ctx, types.StringType, []string{"us-central1"})
	if diags.HasError() {
		t.Fatalf("building regions: %v", diags)
	}

	settings := agentlessScanningSettingsModel{
		WIFPrincipal:             types.StringValue("principal://test"),
		DeploymentVersion:        types.StringValue("1.4.0"),
		Regions:                  regions,
		HostProjectID:            types.StringNull(),
		OrgID:                    types.StringNull(),
		NetworkConfigurationType: types.StringValue("managed"),
		CustomNetwork:            types.ObjectNull((&networkConfigModel{}).AttributeTypes()),
		Infra:                    types.MapNull(types.ObjectType{AttrTypes: (&infraProjectModel{}).AttributeTypes()}),
		DSPMSettings:             dspm,
	}

	obj, diags := settings.ToObject(ctx)
	if diags.HasError() {
		t.Fatalf("building settings object: %v", diags)
	}

	return obj
}

func readDSPMSettings(t *testing.T, dspmSettings *models.GcpAgentlessScanningSettings) types.Object {
	t.Helper()
	ctx := context.Background()

	var state cloudGoogleRegistrationSettingsModel
	diags := state.wrapAgentlessScanningSettings(ctx, dspmSettings, dspmSettings)
	if diags.HasError() {
		t.Fatalf("wrapAgentlessScanningSettings: %v", diags)
	}

	var settings agentlessScanningSettingsModel
	diags = settings.FromObject(ctx, state.AgentlessScanningSettings)
	if diags.HasError() {
		t.Fatalf("reading settings object: %v", diags)
	}

	return settings.DSPMSettings
}

func TestMarshalAgentlessScanningSettingsDSPMSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dspm, diags := (&dspmSettingsModel{
		GCSAccess:      types.BoolValue(false),
		BigQueryAccess: types.BoolValue(true),
		CloudSQLAccess: types.BoolNull(),
		DiskAccess:     types.BoolValue(true),
	}).ToObject(ctx)
	if diags.HasError() {
		t.Fatalf("building dspm_settings: %v", diags)
	}

	req := &models.DtoUpdateGCPRegistrationRequest{}
	diags = marshalAgentlessScanningSettings(ctx, testAgentlessScanningSettingsObject(t, dspm), req)
	if diags.HasError() {
		t.Fatalf("marshalAgentlessScanningSettings: %v", diags)
	}

	dspmJSON, err := json.Marshal(req.DspmSettings.UserInputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"gcs_access":false`, `"bigquery_access":true`, `"disk_access":true`, `"regions":["us-central1"]`} {
		if !strings.Contains(string(dspmJSON), want) {
			t.Errorf("dspm user inputs missing %s: %s", want, dspmJSON)
		}
	}
	if strings.Contains(string(dspmJSON), "cloudsql_access") {
		t.Errorf("dspm user inputs carry unset cloudsql_access: %s", dspmJSON)
	}

	vulnJSON, err := json.Marshal(req.VulnerabilityScanningSettings.UserInputs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(vulnJSON), "_access") {
		t.Errorf("vulnerability scanning user inputs carry access values: %s", vulnJSON)
	}
	if !strings.Contains(string(vulnJSON), `"regions":["us-central1"]`) {
		t.Errorf("vulnerability scanning user inputs missing shared fields: %s", vulnJSON)
	}

	got := readDSPMSettings(t, req.DspmSettings)
	if !got.Equal(dspm) {
		t.Errorf("dspm_settings round trip: got %v, want %v", got, dspm)
	}
}

func TestMarshalAgentlessScanningSettingsWithoutDSPMSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	req := &models.DtoUpdateGCPRegistrationRequest{}
	diags := marshalAgentlessScanningSettings(ctx, testAgentlessScanningSettingsObject(t, types.ObjectNull((&dspmSettingsModel{}).AttributeTypes())), req)
	if diags.HasError() {
		t.Fatalf("marshalAgentlessScanningSettings: %v", diags)
	}

	dspmJSON, err := json.Marshal(req.DspmSettings.UserInputs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dspmJSON), "_access") {
		t.Errorf("dspm user inputs carry access values: %s", dspmJSON)
	}

	got := readDSPMSettings(t, req.DspmSettings)
	if !got.IsNull() {
		t.Errorf("expected null dspm_settings, got %v", got)
	}
}

func TestFlattenDSPMSettingsNull(t *testing.T) {
	t.Parallel()

	for name, settings := range map[string]*models.GcpAgentlessScanningSettings{
		"no settings":    nil,
		"no user inputs": {},
		"no values":      {UserInputs: &models.GcpAgentlessScanningUserInputs{Regions: []string{"us-central1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, diags := flattenDSPMSettings(context.Background(), settings)
			if diags.HasError() {
				t.Fatalf("flattenDSPMSettings: %v", diags)
			}
			if !got.IsNull() {
				t.Errorf("expected null, got %v", got)
			}
		})
	}
}

func TestFlattenDSPMSettingsPartial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gcsAccess := false
	got, diags := flattenDSPMSettings(ctx, &models.GcpAgentlessScanningSettings{
		UserInputs: &models.GcpAgentlessScanningUserInputs{GcsAccess: &gcsAccess},
	})
	if diags.HasError() {
		t.Fatalf("flattenDSPMSettings: %v", diags)
	}

	want, diags := (&dspmSettingsModel{
		GCSAccess:      types.BoolValue(false),
		BigQueryAccess: types.BoolNull(),
		CloudSQLAccess: types.BoolNull(),
		DiskAccess:     types.BoolNull(),
	}).ToObject(ctx)
	if diags.HasError() {
		t.Fatalf("building expected object: %v", diags)
	}
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestValidateDSPMSettingsFeature(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dspm, diags := (&dspmSettingsModel{
		GCSAccess:      types.BoolValue(false),
		BigQueryAccess: types.BoolNull(),
		CloudSQLAccess: types.BoolNull(),
		DiskAccess:     types.BoolNull(),
	}).ToObject(ctx)
	if diags.HasError() {
		t.Fatalf("building dspm_settings: %v", diags)
	}
	nullDSPM := types.ObjectNull((&dspmSettingsModel{}).AttributeTypes())

	cspm := "cspm"
	registration := func(features ...string) *models.DtoGCPRegistration {
		return &models.DtoGCPRegistration{Products: []*models.DomainProductFeatures{{Product: &cspm, Features: features}}}
	}

	for name, tc := range map[string]struct {
		dspm         types.Object
		registration *models.DtoGCPRegistration
		wantErr      bool
	}{
		"vulnerability scanning only": {dspm: dspm, registration: registration(featureVulnerabilityScanning), wantErr: true},
		"dspm enabled":                {dspm: dspm, registration: registration(featureDSPM)},
		"no dspm_settings":            {dspm: nullDSPM, registration: registration(featureVulnerabilityScanning)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data := cloudGoogleRegistrationSettingsModel{
				RegistrationID:            types.StringValue("reg-1"),
				AgentlessScanningSettings: testAgentlessScanningSettingsObject(t, tc.dspm),
			}
			diags := validateDSPMSettingsFeature(&data, tc.registration)
			if diags.HasError() != tc.wantErr {
				t.Fatalf("HasError() = %v, want %v: %v", diags.HasError(), tc.wantErr, diags)
			}
			if tc.wantErr && !strings.Contains(diags[0].Detail(), "dspm_settings requires DSPM to be enabled") {
				t.Errorf("unexpected detail: %s", diags[0].Detail())
			}
		})
	}
}

func TestDSPMSettingsSchemaRejectsEmptyObject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	(&cloudGoogleRegistrationSettingsResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	agentless := schemaResp.Schema.Attributes["agentless_scanning_settings"].(schema.SingleNestedAttribute)
	dspmAttr := agentless.Attributes["dspm_settings"].(schema.SingleNestedAttribute)

	validate := func(m dspmSettingsModel) bool {
		obj, diags := m.ToObject(ctx)
		if diags.HasError() {
			t.Fatalf("building dspm_settings: %v", diags)
		}
		var resp validator.ObjectResponse
		for _, v := range dspmAttr.Validators {
			v.ValidateObject(ctx, validator.ObjectRequest{
				Path:        path.Root("agentless_scanning_settings").AtName("dspm_settings"),
				ConfigValue: obj,
			}, &resp)
		}
		return resp.Diagnostics.HasError()
	}

	empty := dspmSettingsModel{
		GCSAccess:      types.BoolNull(),
		BigQueryAccess: types.BoolNull(),
		CloudSQLAccess: types.BoolNull(),
		DiskAccess:     types.BoolNull(),
	}
	if !validate(empty) {
		t.Error("expected an error for dspm_settings = {}")
	}

	oneFalse := empty
	oneFalse.DiskAccess = types.BoolValue(false)
	if validate(oneFalse) {
		t.Error("expected no error with disk_access = false")
	}
}
