package ioarulegroup

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"
)

type ioaDataSourceTransport func(*runtime.ClientOperation) (any, error)

func (f ioaDataSourceTransport) Submit(op *runtime.ClientOperation) (any, error) { return f(op) }

func TestIOARuleGroupDataSourceLookup(t *testing.T) {
	const id = "11111111111111111111111111111111"
	const otherID = "22222222222222222222222222222222"
	group := func(id, name, platform string) *models.APIRuleGroupV1 {
		return &models.APIRuleGroupV1{ID: swag.String(id), Name: swag.String(name), Platform: swag.String(platform)}
	}
	deleted := group(otherID, "Example IOAs", "linux")
	deleted.Deleted = swag.Bool(true)
	tests := map[string]struct {
		id, name, platform, filter string
		pages                      [][]*models.APIRuleGroupV1
		wantError                  string
	}{
		"id":                        {id: id, pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs", "linux")}}},
		"id missing":                {id: id, pages: [][]*models.APIRuleGroupV1{{}}, wantError: "No IOA rule group found with ID"},
		"id mismatch":               {id: id, pages: [][]*models.APIRuleGroupV1{{group(otherID, "Example IOAs", "linux")}}, wantError: "No IOA rule group found"},
		"id platform mismatch":      {id: id, platform: "Windows", pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs", "linux")}}, wantError: "restricted to platform"},
		"deleted id":                {id: otherID, pages: [][]*models.APIRuleGroupV1{{deleted}}, wantError: "No IOA rule group found"},
		"exact name on later page":  {name: "Example IOAs", filter: "name:'Example IOAs'", pages: [][]*models.APIRuleGroupV1{{group(otherID, "Example IOAs extra", "linux")}, {group(id, "Example IOAs", "linux")}}},
		"platform":                  {name: "Example IOAs", platform: "Linux", filter: "name:'Example IOAs'+platform:'linux'", pages: [][]*models.APIRuleGroupV1{{group(otherID, "Example IOAs", "windows"), group(id, "Example IOAs", "LINUX")}}},
		"duplicate across pages":    {name: "Example IOAs", filter: "name:'Example IOAs'", pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs", "linux")}, {group(otherID, "Example IOAs", "mac")}}, wantError: "More than one IOA rule group"},
		"duplicate within platform": {name: "Example IOAs", platform: "Linux", filter: "name:'Example IOAs'+platform:'linux'", pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs", "linux"), group(otherID, "Example IOAs", "linux")}}, wantError: "More than one IOA rule group"},
		"skip deleted and nil":      {name: "Example IOAs", filter: "name:'Example IOAs'", pages: [][]*models.APIRuleGroupV1{{nil, deleted, group(id, "Example IOAs", "linux")}}},
		"case sensitive":            {name: "example ioas", filter: "name:'example ioas'", pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs", "linux")}}, wantError: "No IOA rule group found"},
		"partial only":              {name: "Example IOAs", filter: "name:'Example IOAs'", pages: [][]*models.APIRuleGroupV1{{group(id, "Example IOAs extra", "linux")}}, wantError: "No IOA rule group found"},
		"no matches":                {name: "Example IOAs", filter: "name:'Example IOAs'", pages: [][]*models.APIRuleGroupV1{{}}, wantError: "No IOA rule group found"},
		"quote and backslash":       {name: `Example's \ IOAs`, filter: `name:'Example\'s \\ IOAs'`, pages: [][]*models.APIRuleGroupV1{{group(id, `Example's \ IOAs`, "linux")}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var calls, offset int
			var total int64
			for _, page := range tc.pages {
				total += int64(len(page))
			}
			transport := ioaDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				require.Less(t, calls, len(tc.pages), "unexpected extra API call")
				payload := &models.APIRuleGroupsResponse{Resources: tc.pages[calls], Meta: &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total}}}
				calls++
				if tc.id != "" {
					params, ok := op.Params.(*custom_ioa.GetRuleGroupsMixin0Params)
					require.True(t, ok)
					require.Equal(t, []string{tc.id}, params.Ids)
					require.Equal(t, t.Context(), params.Context)
					return &custom_ioa.GetRuleGroupsMixin0OK{Payload: payload}, nil
				}
				params, ok := op.Params.(*custom_ioa.QueryRuleGroupsFullParams)
				require.True(t, ok)
				require.Equal(t, tc.filter, *params.Filter)
				require.Equal(t, fmt.Sprint(offset), *params.Offset)
				require.Equal(t, int64(100), *params.Limit)
				require.Equal(t, t.Context(), params.Context)
				offset += len(payload.Resources)
				return &custom_ioa.QueryRuleGroupsFullOK{Payload: payload}, nil
			})
			d := ioaRuleGroupDataSource{client: client.New(transport, strfmt.Default)}
			result, diags := d.lookup(t.Context(), tc.id, tc.name, tc.platform)
			if tc.wantError != "" {
				require.True(t, diags.HasError())
				require.Contains(t, fmt.Sprint(diags), tc.wantError)
				require.Nil(t, result)
			} else {
				require.False(t, diags.HasError(), "%v", diags)
				require.NotNil(t, result)
				require.Equal(t, id, *result.ID)
			}
			require.Equal(t, len(tc.pages), calls)
		})
	}
}

func TestIOARuleGroupDataSourceAPIErrors(t *testing.T) {
	for _, byID := range []bool{false, true} {
		for _, kind := range []string{"forbidden", "payload error", "nil payload", "incomplete pagination"} {
			t.Run(fmt.Sprintf("id=%t/%s", byID, kind), func(t *testing.T) {
				if byID && kind == "incomplete pagination" {
					t.Skip("query pagination only")
				}
				transport := ioaDataSourceTransport(func(_ *runtime.ClientOperation) (any, error) {
					if kind == "forbidden" {
						return nil, runtime.NewAPIError("lookup", nil, 403)
					}
					var payload *models.APIRuleGroupsResponse
					if kind == "payload error" {
						payload = &models.APIRuleGroupsResponse{Errors: []*models.MsaAPIError{{Code: swag.Int32(400), Message: swag.String("example API error")}}}
					}
					if kind == "incomplete pagination" {
						payload = &models.APIRuleGroupsResponse{Meta: &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: swag.Int64(1)}}}
					}
					if byID {
						return &custom_ioa.GetRuleGroupsMixin0OK{Payload: payload}, nil
					}
					return &custom_ioa.QueryRuleGroupsFullOK{Payload: payload}, nil
				})
				d := ioaRuleGroupDataSource{client: client.New(transport, strfmt.Default)}
				id, name := "", "Example IOAs"
				if byID {
					id, name = "11111111111111111111111111111111", ""
				}
				result, diags := d.lookup(t.Context(), id, name, "")
				require.Nil(t, result)
				require.True(t, diags.HasError())
				if kind == "forbidden" {
					require.Contains(t, fmt.Sprint(diags), "Custom IOA Rules")
					require.NotContains(t, fmt.Sprint(diags), "write")
				}
				if kind == "payload error" {
					require.Contains(t, fmt.Sprint(diags), "example API error")
				}
			})
		}
	}
}

func TestIOARuleGroupDataSourceSchema(t *testing.T) {
	var resourceResponse resourceschema.SchemaResponse
	(&ioaRuleGroupResource{}).Schema(t.Context(), resourceschema.SchemaRequest{}, &resourceResponse)
	var dataResponse datasource.SchemaResponse
	(&ioaRuleGroupDataSource{}).Schema(t.Context(), datasource.SchemaRequest{}, &dataResponse)
	require.Equal(t, resourceResponse.Schema.Type().TerraformType(t.Context()), dataResponse.Schema.Type().TerraformType(t.Context()))
	for name, attribute := range dataResponse.Schema.Attributes {
		require.True(t, attribute.IsComputed(), name)
		if name != "id" && name != "name" && name != "platform" {
			require.False(t, attribute.IsOptional(), name)
		}
	}
}

func TestIOARuleGroupDataSourceWrap(t *testing.T) {
	rule := func(id string) *models.APIRuleV1 {
		return &models.APIRuleV1{
			InstanceID: swag.String(id), Name: swag.String("Example duplicate name"), Description: swag.String("Synthetic rule"),
			RuletypeName: swag.String("Process Creation"), DispositionID: swag.Int32(20), PatternSeverity: swag.String("low"),
			Comment: swag.String("Example audit comment"), Enabled: swag.Bool(true),
		}
	}
	deleted := rule("c")
	deleted.Deleted = swag.Bool(true)
	group := models.APIRuleGroupV1{
		ID: swag.String("11111111111111111111111111111111"), Name: swag.String("Example IOAs"), Platform: swag.String("linux"),
		Enabled: swag.Bool(true), Deleted: swag.Bool(false), Rules: []*models.APIRuleV1{rule("b"), nil, deleted, rule("a")},
	}
	var first, second ioaRuleGroupDataSourceModel
	require.False(t, first.wrap(t.Context(), group).HasError())
	group.Rules = []*models.APIRuleV1{rule("a"), rule("b")}
	require.False(t, second.wrap(t.Context(), group).HasError())
	require.True(t, first.Rules.Equal(second.Rules))
	require.Len(t, first.Rules.Elements(), 2)
	require.Equal(t, types.StringValue("Linux"), first.Platform)
	require.True(t, first.Description.IsNull())
	object, ok := first.Rules.Elements()[0].(types.Object)
	require.True(t, ok)
	require.Equal(t, types.StringValue("a"), object.Attributes()["instance_id"])
	require.Equal(t, types.StringValue("Example audit comment"), object.Attributes()["comment"])
}

// Keep the transport stub independent of credentials and real Falcon endpoints.
var _ runtime.ClientTransport = ioaDataSourceTransport(nil)

func TestIOARuleGroupDataSourceRead(t *testing.T) {
	for _, byID := range []bool{false, true} {
		t.Run(fmt.Sprint(byID), func(t *testing.T) {
			group := &models.APIRuleGroupV1{
				ID: swag.String("11111111111111111111111111111111"), Name: swag.String("Example IOAs"), Platform: swag.String("linux"),
				Enabled: swag.Bool(false), Deleted: swag.Bool(false),
			}
			d := ioaRuleGroupDataSource{client: client.New(ioaDataSourceTransport(func(op *runtime.ClientOperation) (any, error) {
				payload := &models.APIRuleGroupsResponse{Resources: []*models.APIRuleGroupV1{group}}
				if byID {
					_, ok := op.Params.(*custom_ioa.GetRuleGroupsMixin0Params)
					require.True(t, ok)
					return &custom_ioa.GetRuleGroupsMixin0OK{Payload: payload}, nil
				}
				_, ok := op.Params.(*custom_ioa.QueryRuleGroupsFullParams)
				require.True(t, ok)
				return &custom_ioa.QueryRuleGroupsFullOK{Payload: payload}, nil
			}), strfmt.Default)}
			var schema datasource.SchemaResponse
			d.Schema(t.Context(), datasource.SchemaRequest{}, &schema)
			objectType, ok := schema.Schema.Type().TerraformType(t.Context()).(tftypes.Object)
			require.True(t, ok)
			values := map[string]tftypes.Value{}
			for key, typ := range objectType.AttributeTypes {
				values[key] = tftypes.NewValue(typ, nil)
			}
			if byID {
				values["id"] = tftypes.NewValue(tftypes.String, *group.ID)
			} else {
				values["name"] = tftypes.NewValue(tftypes.String, *group.Name)
			}
			req := datasource.ReadRequest{Config: tfsdk.Config{Schema: schema.Schema, Raw: tftypes.NewValue(objectType, values)}}
			resp := datasource.ReadResponse{State: tfsdk.State{Schema: schema.Schema}}
			d.Read(t.Context(), req, &resp)
			require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			var state ioaRuleGroupDataSourceModel
			require.False(t, resp.State.Get(t.Context(), &state).HasError())
			require.Equal(t, types.StringValue(*group.ID), state.ID)
			require.Equal(t, types.StringValue(*group.Name), state.Name)
			require.Equal(t, types.StringValue("Linux"), state.Platform)
			require.True(t, state.Rules.IsNull())
			require.True(t, state.CreatedOn.IsNull())
		})
	}
}
