package customioc

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
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

type customIOCDataSourceTransport func(*runtime.ClientOperation) (any, error)

func (f customIOCDataSourceTransport) Submit(op *runtime.ClientOperation) (any, error) { return f(op) }

func TestCustomIOCDataSourceSchema(t *testing.T) {
	var rs resource.SchemaResponse
	(&customIOCResource{}).Schema(t.Context(), resource.SchemaRequest{}, &rs)
	var ds datasource.SchemaResponse
	(&customIOCDataSource{}).Schema(t.Context(), datasource.SchemaRequest{}, &ds)
	require.Equal(t, rs.Schema.Type().TerraformType(t.Context()), ds.Schema.Type().TerraformType(t.Context()))
	for name, attribute := range ds.Schema.Attributes {
		require.True(t, attribute.IsComputed(), name)
		require.Equal(t, name == "id" || name == "value" || name == "type", attribute.IsOptional(), name)
	}
}

func TestCustomIOCDataSourceLookupByID(t *testing.T) {
	const id = "11111111111111111111111111111111"
	value := "sample.example.com"
	result := &models.APIIndicatorV1{ID: id, Type: "domain", Value: value, Platforms: []string{"windows"}, Action: "detect"}
	wrongID := &models.APIIndicatorV1{ID: "22222222222222222222222222222222"}
	deleted := &models.APIIndicatorV1{ID: id, Deleted: true}
	tests := map[string]struct {
		payload   *models.APIIndicatorRespV1
		err       error
		wantError string
	}{
		"found":          {payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{result}}},
		"deleted":        {payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{deleted}}, wantError: "No "},
		"missing":        {payload: &models.APIIndicatorRespV1{}, wantError: "No "},
		"nil resource":   {payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{nil}}, wantError: "No "},
		"wrong id":       {payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{wrongID}}, wantError: "No "},
		"nil payload":    {wantError: "returned no data"},
		"http forbidden": {err: runtime.NewAPIError("lookup", nil, 403), wantError: "read"},
		"http not found": {err: runtime.NewAPIError("lookup", nil, 404), wantError: "Not Found"},
		"payload error":  {payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{result}, Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("synthetic API error")}}}, wantError: "synthetic API error"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := customIOCDataSource{client: client.New(customIOCDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				params, ok := op.Params.(*ioc.IndicatorGetV1Params)
				require.True(t, ok)
				require.Equal(t, []string{id}, params.Ids)
				require.Equal(t, t.Context(), params.Context)
				if tc.err != nil {
					return nil, tc.err
				}
				return &ioc.IndicatorGetV1OK{Payload: tc.payload}, nil
			}), strfmt.Default)}
			got, diags := d.lookup(t.Context(), id, "", "")
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

func TestCustomIOCDataSourceLookupByValue(t *testing.T) {
	const id = "11111111111111111111111111111111"
	indicator := func(id, typ, value string) *models.APIIndicatorV1 {
		return &models.APIIndicatorV1{ID: id, Type: typ, Value: value}
	}
	deleted := indicator("deleted", "domain", "sample.example.com")
	deleted.Deleted = true
	tests := map[string]struct {
		pages     [][]*models.APIIndicatorV1
		wantError string
	}{
		"exact":                {pages: [][]*models.APIIndicatorV1{{indicator(id, "domain", "sample.example.com")}}},
		"later page":           {pages: [][]*models.APIIndicatorV1{{indicator("other", "domain", "other.example.com")}, {indicator(id, "domain", "sample.example.com")}}},
		"ambiguous":            {pages: [][]*models.APIIndicatorV1{{indicator(id, "domain", "sample.example.com")}, {indicator("other", "domain", "sample.example.com")}}, wantError: "More than one"},
		"skip nil and deleted": {pages: [][]*models.APIIndicatorV1{{nil, deleted, indicator(id, "domain", "sample.example.com")}}},
		"wrong type":           {pages: [][]*models.APIIndicatorV1{{indicator(id, "all_subdomains", "sample.example.com")}}, wantError: "No "},
		"case sensitive":       {pages: [][]*models.APIIndicatorV1{{indicator(id, "domain", "SAMPLE.EXAMPLE.COM")}}, wantError: "No "},
		"partial value":        {pages: [][]*models.APIIndicatorV1{{indicator(id, "domain", "sample.example.com.extra")}}, wantError: "No "},
		"empty id":             {pages: [][]*models.APIIndicatorV1{{indicator("", "domain", "sample.example.com")}}, wantError: "returned no data"},
		"none":                 {pages: [][]*models.APIIndicatorV1{{}}, wantError: "No "},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			page := 0
			d := customIOCDataSource{client: client.New(customIOCDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Equal(t, "GET", op.Method)
				params, ok := op.Params.(*ioc.IndicatorCombinedV1Params)
				require.True(t, ok)
				require.Equal(t, t.Context(), params.Context)
				require.Nil(t, params.Offset)
				require.Equal(t, int64(100), *params.Limit)
				require.Equal(t, "type:'domain'+value:'sample.example.com'", *params.Filter)
				if page == 0 {
					require.Nil(t, params.After)
				} else {
					require.Equal(t, fmt.Sprint(page), *params.After)
				}
				require.Less(t, page, len(tc.pages))
				payload := &models.APIIndicatorRespV1{Resources: tc.pages[page]}
				page++
				if page < len(tc.pages) {
					payload.Meta = &models.APIIndicatorsQueryMeta{Pagination: &models.APIIndicatorsQueryPaging{After: fmt.Sprint(page)}}
				}
				return &ioc.IndicatorCombinedV1OK{Payload: payload}, nil
			}), strfmt.Default)}
			got, diags := d.lookup(t.Context(), "", "domain", "sample.example.com")
			if tc.wantError != "" {
				require.Nil(t, got)
				require.True(t, diags.HasError())
				require.Contains(t, fmt.Sprint(diags), tc.wantError)
			} else {
				require.False(t, diags.HasError(), "%v", diags)
				require.Equal(t, id, got.ID)
			}
			require.Equal(t, len(tc.pages), page)
		})
	}
}

func TestCustomIOCDataSourceQueryErrors(t *testing.T) {
	for _, kind := range []string{"forbidden", "nil payload", "payload error", "repeated cursor", "missing cursor", "short incomplete page"} {
		t.Run(kind, func(t *testing.T) {
			d := customIOCDataSource{client: client.New(customIOCDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				_, ok := op.Params.(*ioc.IndicatorCombinedV1Params)
				require.True(t, ok)
				if kind == "forbidden" {
					return nil, runtime.NewAPIError("lookup", nil, 403)
				}
				var payload *models.APIIndicatorRespV1
				if kind == "payload error" {
					payload = &models.APIIndicatorRespV1{Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("synthetic error")}}}
				}
				if kind == "repeated cursor" {
					payload = &models.APIIndicatorRespV1{Meta: &models.APIIndicatorsQueryMeta{Pagination: &models.APIIndicatorsQueryPaging{After: "same"}}}
				}
				if kind == "missing cursor" {
					payload = &models.APIIndicatorRespV1{Resources: make([]*models.APIIndicatorV1, 100)}
				}
				if kind == "short incomplete page" {
					payload = &models.APIIndicatorRespV1{Meta: &models.APIIndicatorsQueryMeta{Pagination: &models.APIIndicatorsQueryPaging{Total: swag.Int64(1)}}}
				}
				return &ioc.IndicatorCombinedV1OK{Payload: payload}, nil
			}), strfmt.Default)}
			got, diags := d.lookup(t.Context(), "", "domain", "sample.example.com")
			require.Nil(t, got)
			require.True(t, diags.HasError())
			if kind == "forbidden" {
				require.Contains(t, fmt.Sprint(diags), "read")
				require.NotContains(t, fmt.Sprint(diags), "write")
			}
		})
	}
}

func TestCustomIOCDataSourceRead(t *testing.T) {
	const id = "11111111111111111111111111111111"
	result := &models.APIIndicatorV1{ID: id, Type: "domain", Value: "sample.example.com", Action: "detect", MobileAction: "no_action", Platforms: []string{"windows"}, AppliedGlobally: true}
	d := customIOCDataSource{client: client.New(customIOCDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
		_, ok := op.Params.(*ioc.IndicatorGetV1Params)
		require.True(t, ok)
		return &ioc.IndicatorGetV1OK{Payload: &models.APIIndicatorRespV1{Resources: []*models.APIIndicatorV1{result}}}, nil
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
	var state customIOCResourceModel
	require.False(t, resp.State.Get(t.Context(), &state).HasError())
	require.Equal(t, types.StringValue(id), state.ID)
	require.Equal(t, types.StringValue("sample.example.com"), state.Value)
	require.Equal(t, types.BoolValue(true), state.AppliedGlobally)
	groups, diags := types.SetValueFrom(t.Context(), types.StringType, []string{"all"})
	require.False(t, diags.HasError())
	require.True(t, groups.Equal(state.HostGroups))
	require.Equal(t, types.StringValue("detect"), state.Action)
	require.True(t, state.MobileAction.IsNull())
	require.True(t, state.Tags.IsNull())
	require.True(t, state.Expiration.IsNull())
}
