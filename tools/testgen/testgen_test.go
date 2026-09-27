package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"
	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureSchema exercises every rule the generator applies.
func fixtureSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":           schema.StringAttribute{Computed: true},
		"last_updated": schema.StringAttribute{Computed: true},
		"name":         schema.StringAttribute{Required: true},
		"platform": schema.StringAttribute{
			Required:      true,
			Validators:    []validator.String{stringvalidator.OneOf("Windows", "Linux")},
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"description": schema.StringAttribute{Optional: true},
		"enabled": schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Default:  booldefault.StaticBool(false),
		},
		"limit": schema.Int64Attribute{
			Optional:   true,
			Validators: []validator.Int64{int64validator.Between(1, 10)},
		},
		"ratio": schema.Float64Attribute{
			Optional:   true,
			Validators: []validator.Float64{float64validator.Between(0, 1), float64validator.NoneOf(0)},
		},
		"retries": schema.Int64Attribute{Optional: true},
		"tags": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
		},
		"steps": schema.ListAttribute{
			Optional:    true,
			ElementType: types.StringType,
			Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
		},
		"schedule": schema.SingleNestedAttribute{
			Optional: true,
			Attributes: map[string]schema.Attribute{
				"interval": schema.StringAttribute{
					Required:   true,
					Validators: []validator.String{stringvalidator.OneOf("hourly", "daily")},
				},
				"next_run": schema.StringAttribute{Computed: true},
				"timezone": schema.StringAttribute{
					Optional:   true,
					Validators: []validator.String{stringvalidator.OneOf("UTC", "EST")},
				},
			},
		},
		"labels": schema.MapAttribute{Optional: true, ElementType: types.StringType},
		"legacy": schema.StringAttribute{Optional: true, DeprecationMessage: "Use name."},
	}
}

func fixtureResource(t *testing.T, spec testgen.Resource) *resourceInfo {
	t.Helper()
	ctx := context.Background()
	s := schema.Schema{Attributes: fixtureSchema()}
	attrs, err := buildAttributes(ctx, s.Attributes, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &resourceInfo{
		typeName:    "crowdstrike_widget",
		testPrefix:  "TestAccWidgetResource",
		dir:         "internal/widget",
		pkgName:     "widget",
		testPackage: "widget_test",
		constructor: "NewWidgetResource",
		importable:  true,
		attrs:       attrs,
		schemaType:  s.Type().TerraformType(ctx).(tftypes.Object), //nolint:forcetypeassert // schemas are objects
		handWritten: map[string]bool{},
		spec:        spec,
	}
}

// acceptAll is a validator server that accepts every config.
type acceptAll struct{}

func (acceptAll) ValidateResourceConfig(context.Context, *tfprotov6.ValidateResourceConfigRequest) (*tfprotov6.ValidateResourceConfigResponse, error) {
	return &tfprotov6.ValidateResourceConfigResponse{}, nil
}

var fixtureSpec = testgen.Resource{
	Attributes: map[string]testgen.Attribute{
		"retries": {Values: []any{1, 2}},
		"steps":   {Values: []any{"first", "second", "third"}},
	},
	Skip:         map[string]string{"labels": "testgen: maps are not supported yet"},
	ImportIgnore: []string{"last_updated"},
}

func TestGenerateGolden(t *testing.T) {
	r := fixtureResource(t, fixtureSpec)
	files, err := generateResource(context.Background(), acceptAll{}, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no files generated")
	}
	for path, got := range files {
		golden := filepath.Join("testdata", "golden", strings.TrimPrefix(path, "internal/widget/"))
		if *update {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%s: %v (run with -update to create)", golden, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from golden; run go test ./tools/testgen -update and review the diff", golden)
		}
	}
}

func TestGenerateReportsMissingValues(t *testing.T) {
	r := fixtureResource(t, testgen.Resource{})
	_, err := generateResource(context.Background(), acceptAll{}, r)
	if err == nil || !strings.Contains(err.Error(), "no test values for [retries]") {
		t.Fatalf("want missing-values error for retries, got %v", err)
	}
}

func TestSweepAttribute(t *testing.T) {
	r := fixtureResource(t, testgen.Resource{SweepAttribute: "description"})
	p := newPools(r)
	desc, err := p.pool(r.attrs["description"])
	if err != nil || len(desc) == 0 || !desc[0].rName {
		t.Fatalf("want description to get the random name, got %v %v", desc, err)
	}
	name, err := p.pool(r.attrs["name"])
	if err != nil || len(name) == 0 || name[0].rName || name[0].str != "testgen name 1" {
		t.Fatalf("want name to get a placeholder, got %v %v", name, err)
	}
}

func TestGenerateRejectsUnknownSpecEntries(t *testing.T) {
	tests := map[string]testgen.Resource{
		"attribute": {Attributes: map[string]testgen.Attribute{"nope": {Values: []any{"x"}}}},
		"skip":      {Skip: map[string]string{"nope": "why"}},
		"import":    {ImportIgnore: []string{"nope"}},
		"base":      {Base: map[string]any{"nope": "x"}},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			spec.Attributes = mergeAttrs(fixtureSpec.Attributes, spec.Attributes)
			r := fixtureResource(t, spec)
			if _, err := generateResource(context.Background(), acceptAll{}, r); err == nil || !strings.Contains(err.Error(), "nope") {
				t.Fatalf("want error naming %q, got %v", "nope", err)
			}
		})
	}
}

func TestRequiresResolvesValues(t *testing.T) {
	spec := fixtureSpec
	spec.Attributes = mergeAttrs(fixtureSpec.Attributes, map[string]testgen.Attribute{
		"description": {Requires: []string{"limit", "steps", "tags"}},
	})
	spec.Base = map[string]any{"limit": 7}
	cases, err := buildCases(fixtureResource(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(cases, func(c testCase) bool { return c.suffix == "description" })
	if i < 0 {
		t.Fatal("no description case")
	}
	for n, s := range cases[i].steps {
		if s.importState {
			continue
		}
		if got := s.values["limit"]; got.prim != int64(7) {
			t.Errorf("step %d: limit = %v, want the Base value 7", n+1, got.prim)
		}
		if got := s.values["steps"]; len(got.elems) != 1 || got.elems[0].str != "first" {
			t.Errorf("step %d: steps = %v, want the first spec value", n+1, got.elems)
		}
		if got := s.values["tags"]; len(got.elems) != 1 || got.elems[0].str != "testgen tags 1" {
			t.Errorf("step %d: tags = %v, want the first placeholder", n+1, got.elems)
		}
	}
}

func TestRequiresRejectsInvalidEntries(t *testing.T) {
	tests := map[string]struct {
		attr testgen.Attribute
		want string
	}{
		"self":         {testgen.Attribute{Requires: []string{"description"}}, "names the attribute itself"},
		"self set":     {testgen.Attribute{Set: map[string]any{"description": "x"}}, "names the attribute itself"},
		"unknown":      {testgen.Attribute{Requires: []string{"nope"}}, `unknown or unsettable attribute "nope"`},
		"computed":     {testgen.Attribute{Requires: []string{"id"}}, `unknown or unsettable attribute "id"`},
		"requires+set": {testgen.Attribute{Requires: []string{"limit"}, Set: map[string]any{"limit": 2}}, `"limit" in both Requires and Set`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			spec := fixtureSpec
			spec.Attributes = mergeAttrs(fixtureSpec.Attributes, map[string]testgen.Attribute{"description": tt.attr})
			if _, err := buildCases(fixtureResource(t, spec)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestNoDisappearsRejectsSkip(t *testing.T) {
	spec := fixtureSpec
	spec.NoDisappears = true
	spec.Skip = map[string]string{"disappears": "why"}
	_, err := generateResource(context.Background(), acceptAll{}, fixtureResource(t, spec))
	if err == nil || !strings.Contains(err.Error(), "unknown test suffix") {
		t.Fatalf("want unknown test suffix error, got %v", err)
	}
}

func TestNoDisappearsLeavesOutTest(t *testing.T) {
	spec := fixtureSpec
	spec.NoDisappears = true
	files, err := generateResource(context.Background(), acceptAll{}, fixtureResource(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	src := string(files["internal/widget/widget_resource_gen_test.go"])
	if strings.Contains(src, "_disappears") {
		t.Fatal("NoDisappears still generated a _disappears test")
	}
	if !strings.Contains(src, "TestAccWidgetResource_basic") {
		t.Fatal("NoDisappears dropped other tests")
	}
}

func mergeAttrs(a, b map[string]testgen.Attribute) map[string]testgen.Attribute {
	out := map[string]testgen.Attribute{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func TestHandWrittenTestOverrides(t *testing.T) {
	r := fixtureResource(t, fixtureSpec)
	r.handWritten = map[string]bool{"testaccwidgetresource_basic": true}
	files, err := generateResource(context.Background(), acceptAll{}, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files["internal/widget/widget_resource_gen_test.go"]), "TestAccWidgetResource_basic(") {
		t.Error("generated _basic despite a hand-written test with the same name")
	}
}

// rejectNull rejects configs where attr is null, like a provider
// ValidateConfig that makes an optional attribute conditionally required.
type rejectNull struct {
	typ  tftypes.Object
	attr string
}

func (v rejectNull) ValidateResourceConfig(_ context.Context, req *tfprotov6.ValidateResourceConfigRequest) (*tfprotov6.ValidateResourceConfigResponse, error) {
	raw, err := req.Config.Unmarshal(v.typ)
	if err != nil {
		return nil, err
	}
	var fields map[string]tftypes.Value
	if err := raw.As(&fields); err != nil {
		return nil, err
	}
	resp := &tfprotov6.ValidateResourceConfigResponse{}
	if fields[v.attr].IsNull() {
		resp.Diagnostics = append(resp.Diagnostics, &tfprotov6.Diagnostic{
			Severity: tfprotov6.DiagnosticSeverityError,
			Summary:  v.attr + " is required here",
		})
	}
	return resp, nil
}

func TestRejectedOmitStepIsDropped(t *testing.T) {
	r := fixtureResource(t, fixtureSpec)
	c := testCase{name: "TestAccWidgetResource_description", suffix: "description", attr: "description", steps: []step{
		{values: map[string]value{"description": {str: "x"}}},
		{values: map[string]value{}, omit: true},
		{importState: true},
	}}
	got, err := validateCase(context.Background(), rejectNull{typ: r.schemaType, attr: "description"}, r, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.steps) != 2 || !got.steps[1].importState {
		t.Fatalf("want the omit step dropped and import kept, got %d steps", len(got.steps))
	}
	if got.steps[1].values["description"].str != "x" {
		t.Error("import step should verify the last applied config")
	}
	if !strings.Contains(got.note, "no omit step") {
		t.Errorf("note = %q", got.note)
	}

	c.steps[0].values = map[string]value{}
	if _, err := validateCase(context.Background(), rejectNull{typ: r.schemaType, attr: "description"}, r, c); err == nil {
		t.Error("an invalid non-omit step must be an error")
	}
}

func TestValidatorFacts(t *testing.T) {
	ctx := context.Background()
	attrs, err := buildAttributes(ctx, fixtureSchema(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := attrs["platform"].enum; strings.Join(got, ",") != "Windows,Linux" {
		t.Errorf("platform enum = %v", got)
	}
	if attrs["platform"].replace != replaceAlways {
		t.Error("platform RequiresReplace not detected")
	}
	if l := attrs["limit"]; *l.lo != 1 || *l.hi != 10 {
		t.Errorf("limit bounds = %v..%v", *l.lo, *l.hi)
	}
	if lo, hi, _ := bounds(attrs["ratio"], 1); lo != 1 || hi != 1 {
		t.Errorf("ratio bounds skipping NoneOf(0) = %v..%v, want 1..1", lo, hi)
	}
	if attrs["steps"].minSize != 1 {
		t.Errorf("steps minSize = %d", attrs["steps"].minSize)
	}
	if d := attrs["enabled"].defaults; d == nil || d.prim != false {
		t.Errorf("enabled default = %+v", d)
	}
	if attrs["labels"].kind != kindUnsupported {
		t.Error("map attribute should be unsupported")
	}

	conditional := schema.StringAttribute{
		Optional: true,
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(
			func(context.Context, planmodifier.StringRequest, *stringplanmodifier.RequiresReplaceIfFuncResponse) {},
			"Replace when cleared.", "Replace when cleared.",
		)},
	}
	m, err := buildAttribute(ctx, "x", conditional, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.replace != replaceConditional {
		t.Error("RequiresReplaceIf should be conditional")
	}

	sized, err := buildAttribute(ctx, "s", schema.SetAttribute{
		Optional:    true,
		ElementType: types.StringType,
		Validators: []validator.Set{
			setvalidator.SizeBetween(2, 3),
			setvalidator.ValueStringsAre(stringvalidator.OneOf("x", "y", "z")),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sized.minSize != 2 || sized.maxSize != 3 || strings.Join(sized.elem.enum, ",") != "x,y,z" {
		t.Errorf("set facts = min %d max %d enum %v", sized.minSize, sized.maxSize, sized.elem.enum)
	}
}

func TestLifecycle(t *testing.T) {
	pool := []value{{str: "a"}, {str: "b"}, {str: "c"}}
	render := func(vs []value) string {
		var out []string
		for _, v := range vs {
			var e []string
			for _, x := range v.elems {
				e = append(e, x.str)
			}
			out = append(out, "["+strings.Join(e, ",")+"]")
		}
		return strings.Join(out, " ")
	}
	tests := map[string]struct {
		a    attribute
		pool []value
		want string
	}{
		"three":     {attribute{}, pool, "[a,b] [a,b,c] [c,a,b] [c,b]"},
		"two":       {attribute{}, pool[:2], "[a] [a,b] [b,a] [b]"},
		"max two":   {attribute{maxSize: 2}, pool, "[a] [a,b] [b,a] [b]"},
		"min two":   {attribute{minSize: 2}, pool, "[a,b] [a,b,c] [c,a,b] [c,b]"},
		"min three": {attribute{minSize: 3}, pool, "[a,b,c] [c,a,b]"},
		"one":       {attribute{}, pool[:1], "[a]"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := render(lifecycle(&tt.a, tt.pool)); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestChange(t *testing.T) {
	set := &attribute{kind: kindSet, elem: &attribute{kind: kindString}}
	list := &attribute{kind: kindList, elem: &attribute{kind: kindString}}
	ab := value{elems: []value{{str: "a"}, {str: "b"}}}
	ba := value{elems: []value{{str: "b"}, {str: "a"}}}
	if change(set, ab, ba) != actionNone {
		t.Error("set reorder should be no change")
	}
	if change(list, ab, ba) != actionUpdate {
		t.Error("list reorder should be an update")
	}
	replaced := &attribute{kind: kindString, replace: replaceAlways}
	if change(replaced, value{str: "a"}, value{str: "b"}) != actionReplace {
		t.Error("RequiresReplace change should replace")
	}
	cond := &attribute{kind: kindString, replace: replaceConditional}
	if change(cond, value{str: "a"}, value{str: "b"}) != actionUnknown {
		t.Error("conditional replace should be unknown")
	}
}

func TestRenderEdgeCases(t *testing.T) {
	set := &attribute{kind: kindSet, elem: &attribute{kind: kindString}}
	if got := goVariable(set, value{elems: []value{}}); got != "config.SetVariable([]config.Variable{}...)" {
		t.Errorf("empty set variable = %s", got)
	}
	f := &attribute{kind: kindFloat64}
	if got := goVariable(f, value{prim: 1.0}); got != "config.FloatVariable(1.0)" {
		t.Errorf("integral float variable = %s", got)
	}
	if got := goString(value{rName: true, str: "-updated"}); got != `rName + "-updated"` {
		t.Errorf("rName string = %s", got)
	}
}
