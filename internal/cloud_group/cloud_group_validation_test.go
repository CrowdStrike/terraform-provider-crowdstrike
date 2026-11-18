package cloudgroup_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestCloudGroupResourceFiltersValidation runs configurations through the
// provider's ValidateResourceConfig, the check Terraform makes during plan, so
// it needs neither Falcon credentials nor the Terraform CLI.
//
// An empty filters object used to pass plan and then fail apply with "Provider
// produced inconsistent result after apply": the API returns no filters for it,
// so the provider reads filters back as null.
func TestCloudGroupResourceFiltersValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// config is the resource configuration as JSON. Omitted attributes are null.
		config string
		// wantErrorAt is the attribute the only error must point at, or nil when
		// the configuration is valid.
		wantErrorAt *tftypes.AttributePath
	}{
		{
			name:        "empty aws filters are rejected",
			config:      `{"name": "example", "aws": {"account_ids": ["123456789012"], "filters": {}}}`,
			wantErrorAt: filtersRegionPath("aws"),
		},
		{
			name:        "empty azure filters are rejected",
			config:      `{"name": "example", "azure": {"filters": {}}}`,
			wantErrorAt: filtersRegionPath("azure"),
		},
		{
			name:        "empty gcp filters are rejected",
			config:      `{"name": "example", "gcp": {"filters": {}}}`,
			wantErrorAt: filtersRegionPath("gcp"),
		},
		{
			name:   "aws filters with only region are accepted",
			config: `{"name": "example", "aws": {"filters": {"region": ["us-east-1"]}}}`,
		},
		{
			name:   "aws filters with only tags are accepted",
			config: `{"name": "example", "aws": {"filters": {"tags": ["env=prod"]}}}`,
		},
		{
			name:   "azure filters with only region are accepted",
			config: `{"name": "example", "azure": {"filters": {"region": ["eastus"]}}}`,
		},
		{
			name:   "azure filters with only tags are accepted",
			config: `{"name": "example", "azure": {"filters": {"tags": ["env=dev"]}}}`,
		},
		{
			name:   "gcp filters with region are accepted",
			config: `{"name": "example", "gcp": {"filters": {"region": ["us-central1"]}}}`,
		},
		{
			name:   "providers without filters are accepted",
			config: `{"name": "example", "aws": {}, "azure": {}, "gcp": {}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			errs := validateCloudGroupConfig(t, tt.config)

			if tt.wantErrorAt == nil {
				if len(errs) != 0 {
					t.Fatalf("expected no errors, got: %s", describeDiagnostics(errs))
				}
				return
			}

			if len(errs) != 1 || !errs[0].Attribute.Equal(tt.wantErrorAt) {
				t.Fatalf("expected one error at %s, got: %s", tt.wantErrorAt, describeDiagnostics(errs))
			}
		})
	}
}

// filtersRegionPath returns the path of region in the given provider's filters.
func filtersRegionPath(cloudProvider string) *tftypes.AttributePath {
	return tftypes.NewAttributePath().
		WithAttributeName(cloudProvider).
		WithAttributeName("filters").
		WithAttributeName("region")
}

// validateCloudGroupConfig validates a crowdstrike_cloud_group configuration
// given as JSON and returns its error diagnostics.
func validateCloudGroupConfig(t *testing.T, config string) []*tfprotov6.Diagnostic {
	t.Helper()

	server, err := acctest.ProtoV6ProviderFactories["crowdstrike"]()
	if err != nil {
		t.Fatalf("creating provider server: %s", err)
	}

	resp, err := server.ValidateResourceConfig(t.Context(), &tfprotov6.ValidateResourceConfigRequest{
		TypeName: "crowdstrike_cloud_group",
		Config:   &tfprotov6.DynamicValue{JSON: []byte(config)},
	})
	if err != nil {
		t.Fatalf("validating config: %s", err)
	}

	var errs []*tfprotov6.Diagnostic
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			errs = append(errs, d)
		}
	}

	return errs
}

// describeDiagnostics formats diagnostics for a test failure message.
func describeDiagnostics(diags []*tfprotov6.Diagnostic) string {
	if len(diags) == 0 {
		return "none"
	}

	var b strings.Builder
	for _, d := range diags {
		fmt.Fprintf(&b, "\n  %s: %s: %s", d.Attribute, d.Summary, d.Detail)
	}

	return b.String()
}
