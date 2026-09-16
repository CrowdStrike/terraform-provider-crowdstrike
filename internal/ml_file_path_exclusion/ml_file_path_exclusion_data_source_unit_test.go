package mlfilepathexclusion

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"
)

type mlFilePathExclusionDataSourceTransport func(*runtime.ClientOperation) (any, error)

func (f mlFilePathExclusionDataSourceTransport) Submit(op *runtime.ClientOperation) (any, error) {
	return f(op)
}

func TestMLFilePathExclusionDataSourceSchema(t *testing.T) {
	var rs resource.SchemaResponse
	(&mlFilePathExclusionResource{}).Schema(t.Context(), resource.SchemaRequest{}, &rs)
	var ds datasource.SchemaResponse
	(&mlFilePathExclusionDataSource{}).Schema(t.Context(), datasource.SchemaRequest{}, &ds)
	require.Equal(t, rs.Schema.Type().TerraformType(t.Context()), ds.Schema.Type().TerraformType(t.Context()))
	for name, attribute := range ds.Schema.Attributes {
		require.True(t, attribute.IsComputed(), name)
		require.Equal(t, name == "id" || name == "pattern", attribute.IsOptional(), name)
	}
}

func TestMLFilePathExclusionDataSourceLookupByID(t *testing.T) {
	const id = "11111111111111111111111111111111"
	value := "/opt/example/cache/*"
	result := &models.ExclusionsExclusionV1{ID: swag.String(id), Value: swag.String(value)}
	wrongID := &models.ExclusionsExclusionV1{ID: swag.String("22222222222222222222222222222222")}
	tests := map[string]struct {
		payload   *models.ExclusionsRespV1
		err       error
		wantError string
	}{
		"found":          {payload: &models.ExclusionsRespV1{Resources: []*models.ExclusionsExclusionV1{result}}},
		"missing":        {payload: &models.ExclusionsRespV1{}, wantError: "No "},
		"nil resource":   {payload: &models.ExclusionsRespV1{Resources: []*models.ExclusionsExclusionV1{nil}}, wantError: "No "},
		"wrong id":       {payload: &models.ExclusionsRespV1{Resources: []*models.ExclusionsExclusionV1{wrongID}}, wantError: "No "},
		"nil payload":    {wantError: "returned no data"},
		"http forbidden": {err: runtime.NewAPIError("lookup", nil, 403), wantError: "read"},
		"http not found": {err: runtime.NewAPIError("lookup", nil, 404), wantError: "Not Found"},
		"payload error":  {payload: &models.ExclusionsRespV1{Resources: []*models.ExclusionsExclusionV1{result}, Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("synthetic API error")}}}, wantError: "synthetic API error"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := mlFilePathExclusionDataSource{client: client.New(mlFilePathExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				params, ok := op.Params.(*ml_exclusions.GetMLExclusionsV1Params)
				require.True(t, ok)
				require.Equal(t, []string{id}, params.Ids)
				require.Equal(t, t.Context(), params.Context)
				if tc.err != nil {
					return nil, tc.err
				}
				return &ml_exclusions.GetMLExclusionsV1OK{Payload: tc.payload}, nil
			}), strfmt.Default)}
			got, diags := d.lookup(t.Context(), id, "")
			if tc.wantError != "" {
				require.Nil(t, got)
				require.True(t, diags.HasError())
				require.Contains(t, fmt.Sprint(diags), tc.wantError)
				if name == "http forbidden" {
					require.NotContains(t, fmt.Sprint(diags), "write")
				}
			} else {
				require.False(t, diags.HasError(), "%v", diags)
				require.Equal(t, result, got)
			}
		})
	}
}

func TestMLFilePathExclusionDataSourceLookupByPattern(t *testing.T) {
	const id = "11111111111111111111111111111111"
	const otherID = "22222222222222222222222222222222"
	tests := map[string]struct {
		value     string
		pages     [][]string
		values    map[string]string
		wantError string
	}{
		"exact":                         {value: "/opt/example/cache/*", pages: [][]string{{id}}, values: map[string]string{id: "/opt/example/cache/*"}},
		"later page":                    {value: "/opt/example/cache/*", pages: [][]string{{otherID}, {id}}, values: map[string]string{otherID: "unrelated", id: "/opt/example/cache/*"}},
		"ambiguous across pages":        {value: "/opt/example/cache/*", pages: [][]string{{otherID}, {id}}, values: map[string]string{otherID: "/opt/example/cache/*", id: "/opt/example/cache/*"}, wantError: "More than one"},
		"case sensitive":                {value: "EXAMPLE", pages: [][]string{{id}}, values: map[string]string{id: "example"}, wantError: "No "},
		"partial match":                 {value: "example", pages: [][]string{{id}}, values: map[string]string{id: "example extra"}, wantError: "No "},
		"literal wildcard":              {value: "example*", pages: [][]string{{id}}, values: map[string]string{id: "example-expanded"}, wantError: "No "},
		"quoted input":                  {value: `example's \path`, pages: [][]string{{id}}, values: map[string]string{id: `example's \path`}},
		"none":                          {value: "example", pages: [][]string{{}}, wantError: "No "},
		"deleted between query and get": {value: "example", pages: [][]string{{id}}, wantError: "could not be retrieved"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var page, offset int
			var total int64
			for _, ids := range tc.pages {
				total += int64(len(ids))
			}
			d := mlFilePathExclusionDataSource{client: client.New(mlFilePathExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				switch params := op.Params.(type) {
				case *ml_exclusions.QueryMLExclusionsV1Params:
					require.Equal(t, t.Context(), params.Context)
					require.Equal(t, int64(offset), *params.Offset)
					require.Equal(t, int64(100), *params.Limit)
					if name == "quoted input" {
						require.Equal(t, `value:'example\'s \\path'`, *params.Filter)
					} else {
						require.Equal(t, fmt.Sprintf("value:'%s'", tc.value), *params.Filter)
					}
					require.Less(t, page, len(tc.pages))
					ids := tc.pages[page]
					page++
					offset += len(ids)
					return &ml_exclusions.QueryMLExclusionsV1OK{Payload: &models.MsaspecQueryResponse{Resources: ids, Meta: &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total}}}}, nil
				case *ml_exclusions.GetMLExclusionsV1Params:
					results := []*models.ExclusionsExclusionV1{}
					for _, candidateID := range params.Ids {
						if v, ok := tc.values[candidateID]; ok {
							results = append(results, &models.ExclusionsExclusionV1{ID: swag.String(candidateID), Value: swag.String(v)})
						}
					}
					return &ml_exclusions.GetMLExclusionsV1OK{Payload: &models.ExclusionsRespV1{Resources: results}}, nil
				default:
					t.Fatalf("unexpected operation %s", op.ID)
					return nil, nil
				}
			}), strfmt.Default)}
			value := tc.value
			got, diags := d.lookup(t.Context(), "", value)
			if tc.wantError != "" {
				require.Nil(t, got)
				require.True(t, diags.HasError())
				require.Contains(t, fmt.Sprint(diags), tc.wantError)
			} else {
				require.False(t, diags.HasError(), "%v", diags)
				require.Equal(t, id, *got.ID)
			}
			require.Equal(t, len(tc.pages), page)
		})
	}
}

func TestMLFilePathExclusionDataSourceQueryErrors(t *testing.T) {
	for _, kind := range []string{"forbidden", "nil payload", "payload error", "incomplete pagination"} {
		t.Run(kind, func(t *testing.T) {
			d := mlFilePathExclusionDataSource{client: client.New(mlFilePathExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				_, ok := op.Params.(*ml_exclusions.QueryMLExclusionsV1Params)
				require.True(t, ok)
				if kind == "forbidden" {
					return nil, runtime.NewAPIError("lookup", nil, 403)
				}
				var payload *models.MsaspecQueryResponse
				if kind == "payload error" {
					payload = &models.MsaspecQueryResponse{Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("synthetic error")}}}
				}
				if kind == "incomplete pagination" {
					payload = &models.MsaspecQueryResponse{Meta: &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: swag.Int64(1)}}}
				}
				return &ml_exclusions.QueryMLExclusionsV1OK{Payload: payload}, nil
			}), strfmt.Default)}
			got, diags := d.lookup(t.Context(), "", "example")
			require.Nil(t, got)
			require.True(t, diags.HasError())
			if kind == "forbidden" {
				require.Contains(t, fmt.Sprint(diags), "read")
				require.NotContains(t, fmt.Sprint(diags), "write")
			}
		})
	}
}

func TestMLFilePathExclusionDataSourceRead(t *testing.T) {
	const id = "11111111111111111111111111111111"
	result := &models.ExclusionsExclusionV1{ID: swag.String(id), Value: swag.String("/opt/example/cache/*"), AppliedGlobally: swag.Bool(true), ExcludedFrom: []string{"blocking", "extraction"}}
	d := mlFilePathExclusionDataSource{client: client.New(mlFilePathExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
		_, ok := op.Params.(*ml_exclusions.GetMLExclusionsV1Params)
		require.True(t, ok)
		return &ml_exclusions.GetMLExclusionsV1OK{Payload: &models.ExclusionsRespV1{Resources: []*models.ExclusionsExclusionV1{result}}}, nil
	}), strfmt.Default)}
	var ds datasource.SchemaResponse
	d.Schema(t.Context(), datasource.SchemaRequest{}, &ds)
	objectType, ok := ds.Schema.Type().TerraformType(t.Context()).(tftypes.Object)
	require.True(t, ok)
	values := map[string]tftypes.Value{}
	for key, typ := range objectType.AttributeTypes {
		values[key] = tftypes.NewValue(typ, nil)
	}
	values["id"] = tftypes.NewValue(tftypes.String, id)
	req := datasource.ReadRequest{Config: tfsdk.Config{Schema: ds.Schema, Raw: tftypes.NewValue(objectType, values)}}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: ds.Schema}}
	d.Read(t.Context(), req, &resp)
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var state mlFilePathExclusionResourceModel
	require.False(t, resp.State.Get(t.Context(), &state).HasError())
	require.Equal(t, types.StringValue(id), state.ID)
	require.Equal(t, types.StringValue("/opt/example/cache/*"), state.Pattern)
	require.Equal(t, types.BoolValue(true), state.AppliedGlobally)
	groups, diags := types.SetValueFrom(t.Context(), types.StringType, []string{"all"})
	require.False(t, diags.HasError())
	require.True(t, groups.Equal(state.HostGroups))
	require.Equal(t, types.BoolValue(true), state.ExcludeDetections)
	require.Equal(t, types.BoolValue(true), state.ExcludeUploads)
	require.True(t, state.Comment.IsNull())
	require.True(t, state.LastUpdated.IsNull())
}
