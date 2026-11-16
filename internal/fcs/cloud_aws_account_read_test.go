package fcs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// readWithAPIResponse runs Read for a registered account against a fake API that answers the
// account lookup with the given status code and body.
func readWithAPIResponse(t *testing.T, statusCode int, body string) resource.ReadResponse {
	t.Helper()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/cloud-security-registration-aws/entities/account/v1" {
			t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := &cloudAWSAccountResource{
		client: client.New(httptransport.New(serverURL.Host, "/", []string{"http"}), strfmt.Default),
	}

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("schema: %v", schemaResp.Diagnostics)
	}

	state := tfsdk.State{
		Schema: schemaResp.Schema,
		Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil),
	}
	diags := state.SetAttribute(ctx, path.Root("account_id"), "123456789012")
	if diags.HasError() {
		t.Fatalf("state: %v", diags)
	}

	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	return resp
}

func hasDiagnostic(diags diag.Diagnostics, summary string) bool {
	for _, d := range diags {
		if d.Summary() == summary {
			return true
		}
	}
	return false
}

func TestCloudAWSAccountReadRemovesAccountMissingFromAPI(t *testing.T) {
	tests := map[string]struct {
		statusCode int
		body       string
	}{
		// What the API returns for an account deregistered outside Terraform (issue #499).
		"empty resources": {
			statusCode: http.StatusOK,
			body:       `{"meta":{"query_time":0.01,"trace_id":"t"},"resources":[],"errors":[]}`,
		},
		"null resources": {
			statusCode: http.StatusOK,
			body:       `{"meta":{"query_time":0.01,"trace_id":"t"},"resources":null,"errors":[]}`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resp := readWithAPIResponse(t, tc.statusCode, tc.body)

			if resp.Diagnostics.HasError() {
				t.Fatalf("expected no errors, got %v", resp.Diagnostics)
			}
			if !resp.State.Raw.IsNull() {
				t.Error("expected the account to be removed from state")
			}
			warning := tferrors.NewResourceNotFoundWarningDiagnostic()
			if !hasDiagnostic(resp.Diagnostics.Warnings(), warning.Summary()) {
				t.Errorf("expected a %q warning, got %v", warning.Summary(), resp.Diagnostics)
			}
		})
	}
}

func TestCloudAWSAccountReadKeepsStateOnAPIError(t *testing.T) {
	resp := readWithAPIResponse(t, http.StatusInternalServerError,
		`{"meta":{"query_time":0.01,"trace_id":"t"},"resources":[],"errors":[{"code":500,"message":"boom"}]}`)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error for a failed API call")
	}
	if resp.State.Raw.IsNull() {
		t.Error("expected the account to stay in state when the API call fails")
	}
}
