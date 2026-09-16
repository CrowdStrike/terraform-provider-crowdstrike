package ioaexclusion

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
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

type ioaExclusionDataSourceTransport func(*runtime.ClientOperation) (any, error)

func (f ioaExclusionDataSourceTransport) Submit(op *runtime.ClientOperation) (any, error) {
	return f(op)
}

func TestIOAExclusionDataSourceSchema(t *testing.T) {
	var rs resource.SchemaResponse
	(&ioaExclusionResource{}).Schema(t.Context(), resource.SchemaRequest{}, &rs)
	var ds datasource.SchemaResponse
	(&ioaExclusionDataSource{}).Schema(t.Context(), datasource.SchemaRequest{}, &ds)
	require.Equal(t, rs.Schema.Type().TerraformType(t.Context()), ds.Schema.Type().TerraformType(t.Context()))
	for name, attribute := range ds.Schema.Attributes {
		require.True(t, attribute.IsComputed(), name)
		require.Equal(t, name == "id" || name == "name", attribute.IsOptional(), name)
	}
}

func TestIOAExclusionDataSourceLookupByID(t *testing.T) {
	const id = "11111111111111111111111111111111"
	value := "Example exclusion"
	result := &models.DomainSsIoaExclusionsV2{ID: swag.String(id), Name: swag.String(value)}
	wrongID := &models.DomainSsIoaExclusionsV2{ID: swag.String("22222222222222222222222222222222")}
	tests := map[string]struct {
		payload   *models.DomainSsIoaExclusionsRespV2
		err       error
		wantError string
	}{
		"found":          {payload: &models.DomainSsIoaExclusionsRespV2{Resources: []*models.DomainSsIoaExclusionsV2{result}}},
		"missing":        {payload: &models.DomainSsIoaExclusionsRespV2{}, wantError: "No "},
		"nil resource":   {payload: &models.DomainSsIoaExclusionsRespV2{Resources: []*models.DomainSsIoaExclusionsV2{nil}}, wantError: "No "},
		"wrong id":       {payload: &models.DomainSsIoaExclusionsRespV2{Resources: []*models.DomainSsIoaExclusionsV2{wrongID}}, wantError: "No "},
		"nil payload":    {wantError: "returned no data"},
		"http forbidden": {err: runtime.NewAPIError("lookup", nil, 403), wantError: "read"},
		"http not found": {err: runtime.NewAPIError("lookup", nil, 404), wantError: "Not Found"},
		"payload error":  {payload: &models.DomainSsIoaExclusionsRespV2{Resources: []*models.DomainSsIoaExclusionsV2{result}, Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("synthetic API error")}}}, wantError: "synthetic API error"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := ioaExclusionDataSource{client: client.New(ioaExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				params, ok := op.Params.(*ioa_exclusions.SsIoaExclusionsGetV2Params)
				require.True(t, ok)
				require.Equal(t, []string{id}, params.Ids)
				require.Equal(t, t.Context(), params.Context)
				if tc.err != nil {
					return nil, tc.err
				}
				return &ioa_exclusions.SsIoaExclusionsGetV2OK{Payload: tc.payload}, nil
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

func TestIOAExclusionDataSourceLookupByName(t *testing.T) {
	const id = "11111111111111111111111111111111"
	const otherID = "22222222222222222222222222222222"
	tests := map[string]struct {
		value     string
		pages     [][]string
		values    map[string]string
		wantError string
	}{
		"exact":                         {value: "Example exclusion", pages: [][]string{{id}}, values: map[string]string{id: "Example exclusion"}},
		"later page":                    {value: "Example exclusion", pages: [][]string{{otherID}, {id}}, values: map[string]string{otherID: "unrelated", id: "Example exclusion"}},
		"ambiguous across pages":        {value: "Example exclusion", pages: [][]string{{otherID}, {id}}, values: map[string]string{otherID: "Example exclusion", id: "Example exclusion"}, wantError: "More than one"},
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
			d := ioaExclusionDataSource{client: client.New(ioaExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				switch params := op.Params.(type) {
				case *ioa_exclusions.SsIoaExclusionsSearchV2Params:
					require.Equal(t, t.Context(), params.Context)
					require.Equal(t, int64(offset), *params.Offset)
					require.Equal(t, int64(100), *params.Limit)
					if name == "quoted input" {
						require.Equal(t, `name:'example\'s \\path'`, *params.Filter)
					} else {
						require.Equal(t, fmt.Sprintf("name:'%s'", tc.value), *params.Filter)
					}
					require.Less(t, page, len(tc.pages))
					ids := tc.pages[page]
					page++
					offset += len(ids)
					return &ioa_exclusions.SsIoaExclusionsSearchV2OK{Payload: &models.MsaspecQueryResponse{Resources: ids, Meta: &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total}}}}, nil
				case *ioa_exclusions.SsIoaExclusionsGetV2Params:
					results := []*models.DomainSsIoaExclusionsV2{}
					for _, candidateID := range params.Ids {
						if v, ok := tc.values[candidateID]; ok {
							results = append(results, &models.DomainSsIoaExclusionsV2{ID: swag.String(candidateID), Name: swag.String(v)})
						}
					}
					return &ioa_exclusions.SsIoaExclusionsGetV2OK{Payload: &models.DomainSsIoaExclusionsRespV2{Resources: results}}, nil
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

func TestIOAExclusionDataSourceQueryErrors(t *testing.T) {
	for _, kind := range []string{"forbidden", "nil payload", "payload error", "incomplete pagination"} {
		t.Run(kind, func(t *testing.T) {
			d := ioaExclusionDataSource{client: client.New(ioaExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				_, ok := op.Params.(*ioa_exclusions.SsIoaExclusionsSearchV2Params)
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
				return &ioa_exclusions.SsIoaExclusionsSearchV2OK{Payload: payload}, nil
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

func TestIOAExclusionDataSourceRead(t *testing.T) {
	const id = "11111111111111111111111111111111"
	result := &models.DomainSsIoaExclusionsV2{ID: swag.String(id), Name: swag.String("Example exclusion"), PatternID: swag.String("99999"), PatternName: swag.String("Synthetic pattern"), ClRegex: swag.String(".*example.*"), IfnRegex: swag.String(".*example.*"), AppliedGlobally: swag.Bool(true)}
	d := ioaExclusionDataSource{client: client.New(ioaExclusionDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
		_, ok := op.Params.(*ioa_exclusions.SsIoaExclusionsGetV2Params)
		require.True(t, ok)
		return &ioa_exclusions.SsIoaExclusionsGetV2OK{Payload: &models.DomainSsIoaExclusionsRespV2{Resources: []*models.DomainSsIoaExclusionsV2{result}}}, nil
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
	var state IOAExclusionResourceModel
	require.False(t, resp.State.Get(t.Context(), &state).HasError())
	require.Equal(t, types.StringValue(id), state.ID)
	require.Equal(t, types.StringValue("Example exclusion"), state.Name)
	require.Equal(t, types.BoolValue(true), state.AppliedGlobally)
	groups, diags := types.SetValueFrom(t.Context(), types.StringType, []string{"all"})
	require.False(t, diags.HasError())
	require.True(t, groups.Equal(state.Groups))
	require.Equal(t, types.StringValue("99999"), state.PatternID)
	require.True(t, state.ParentClRegex.IsNull())
	require.True(t, state.LastUpdated.IsNull())
	require.True(t, state.CreatedOn.IsNull())
}
