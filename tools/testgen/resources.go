package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// modulePath is the provider's module path, read from the build info so it
// always matches go.mod.
var modulePath = func() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("testgen: no build info")
	}
	return bi.Main.Path
}()

type validatorServer interface {
	ValidateResourceConfig(context.Context, *tfprotov6.ValidateResourceConfigRequest) (*tfprotov6.ValidateResourceConfigResponse, error)
}

// resourceInfo is everything the generator knows about one resource type.
type resourceInfo struct {
	typeName    string // crowdstrike_cid_group
	testPrefix  string // TestAccCIDGroupResource
	dir         string // internal/cid_group, relative to the module root
	pkgName     string // cidgroup
	constructor string // NewCIDGroupResource
	importable  bool
	attrs       map[string]*attribute
	schemaType  tftypes.Object
	handWritten map[string]bool // lowercased test function names in hand-written test files
	spec        testgen.Resource
}

// loadResources returns the registered resources, in name order, with their
// specs attached. It returns every error found rather than stopping at the
// first one.
func loadResources(ctx context.Context, p fwprovider.Provider, root string) ([]*resourceInfo, error) {
	specs := map[string]testgen.Resource{}
	for _, name := range testgen.Registered() {
		specs[name], _ = testgen.Lookup(name)
	}
	byName := map[string]*resourceInfo{}
	scans := map[string]*scan{}
	var errs []error
	for _, newResource := range p.Resources(ctx) {
		res := newResource()
		var md resource.MetadataResponse
		res.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "crowdstrike"}, &md)
		spec, ok := specs[md.TypeName]
		if !ok {
			continue
		}
		delete(specs, md.TypeName)
		r, err := describeResource(ctx, newResource, res, md, root, scans)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.spec = spec
		byName[r.typeName] = r
	}
	for name := range specs {
		errs = append(errs, fmt.Errorf("%s is registered but is not a provider resource", name))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	out := make([]*resourceInfo, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		out = append(out, byName[name])
	}
	return out, nil
}

// scan is the cached result of scanPackage for one directory.
type scan struct {
	pkg         string
	handWritten map[string]bool
}

func describeResource(ctx context.Context, newResource func() resource.Resource, res resource.Resource, md resource.MetadataResponse, root string, scans map[string]*scan) (*resourceInfo, error) {
	var sr resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &sr)
	if sr.Diagnostics.HasError() {
		return nil, fmt.Errorf("%s: schema: %v", md.TypeName, sr.Diagnostics)
	}
	_, importable := res.(resource.ResourceWithImportState)

	r := &resourceInfo{typeName: md.TypeName, importable: importable}
	if len(sr.Schema.Blocks) > 0 {
		return nil, fmt.Errorf("%s: schemas with blocks are not supported", md.TypeName)
	}

	attrs, err := buildAttributes(ctx, sr.Schema.Attributes, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", md.TypeName, err)
	}
	r.attrs = attrs
	r.schemaType = sr.Schema.Type().TerraformType(ctx).(tftypes.Object) //nolint:forcetypeassert // resource schemas are objects

	// The constructor name gives both the package and the test name prefix:
	// .../internal/cid_group.NewCIDGroupResource -> TestAccCIDGroupResource.
	fn := runtime.FuncForPC(reflect.ValueOf(newResource).Pointer()).Name()
	i := strings.LastIndex(fn, ".")
	pkgPath, name := fn[:i], fn[i+1:]
	if !strings.HasPrefix(name, "New") || !strings.HasPrefix(pkgPath, modulePath+"/") {
		return nil, fmt.Errorf("%s: constructor %s must be a package-level New* function", md.TypeName, fn)
	}
	r.testPrefix = "TestAcc" + strings.TrimPrefix(name, "New")
	r.constructor = name
	r.dir = strings.TrimPrefix(pkgPath, modulePath+"/")

	sc, ok := scans[r.dir]
	if !ok {
		pkg, handWritten, err := scanPackage(filepath.Join(root, r.dir))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", md.TypeName, err)
		}
		sc = &scan{pkg: pkg, handWritten: handWritten}
		scans[r.dir] = sc
	}
	r.pkgName = sc.pkg
	r.handWritten = sc.handWritten
	return r, nil
}

// scanPackage returns the package name and the lowercased names of test
// functions in hand-written test files.
func scanPackage(dir string) (string, map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}
	var pkg string
	funcs := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", nil, err
		}
		if isGenerated(src, goHeader) {
			continue
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			return "", nil, err
		}
		if !strings.HasSuffix(name, "_test.go") {
			pkg = f.Name.Name
			continue
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[strings.ToLower(fd.Name.Name)] = true
			}
		}
	}
	if pkg == "" {
		return "", nil, fmt.Errorf("no package found in %s", dir)
	}
	return pkg, funcs, nil
}

func isGenerated(src []byte, header string) bool {
	return bytes.HasPrefix(src, []byte(header+"\n"))
}

// generateResource returns the generated files for one resource, keyed by
// path relative to the module root.
func generateResource(ctx context.Context, srv validatorServer, r *resourceInfo) (map[string][]byte, error) {
	if err := checkSpec(r); err != nil {
		return nil, err
	}
	all, err := buildCases(r)
	if err != nil {
		return nil, err
	}

	var cases []testCase
	var errs []error
	for _, c := range all {
		if r.handWritten[strings.ToLower(c.name)] {
			continue
		}
		c, err := validateCase(ctx, srv, r, c)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cases = append(cases, c)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(cases) == 0 {
		return nil, nil
	}

	files := map[string][]byte{}
	src, err := renderGo(r, cases)
	if err != nil {
		return nil, err
	}
	files[filepath.Join(r.dir, strings.TrimPrefix(r.typeName, "crowdstrike_")+"_resource_gen_test.go")] = src
	for _, c := range cases {
		if c.skip == "" {
			files[filepath.Join(r.dir, configDir(r), "main.tf")] = renderHCL(r)
			break
		}
	}
	return files, nil
}

// validateCase runs provider validation on every step of a case. An omit
// step the provider rejects is dropped, since the provider has declared that
// omitting the attribute is not allowed in that configuration; any other
// invalid step is an error.
func validateCase(ctx context.Context, srv validatorServer, r *resourceInfo, c testCase) (testCase, error) {
	var steps []step
	var errs []error
	for i, s := range c.steps {
		if s.importState {
			if len(steps) == 0 {
				continue
			}
			// Import verifies the state left by the step before it.
			s.values = steps[len(steps)-1].values
			steps = append(steps, s)
			continue
		}
		err := validateConfig(ctx, srv, r, s.values)
		switch {
		case err == nil:
			steps = append(steps, s)
		case s.omit:
			c.note = fmt.Sprintf("%s has no omit step because provider validation rejects omitting %s in this configuration: %v", c.name, c.attr, err)
		default:
			errs = append(errs, fmt.Errorf("%s step %d: generated config is invalid; set Attributes values in %s/testgen.go: %w", c.name, i+1, r.dir, err))
		}
	}
	c.steps = steps
	if c.skip == "" && len(c.steps) == 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("%s: generated no steps", c.name))
	}
	return c, errors.Join(errs...)
}

// checkSpec rejects spec entries that do not match the schema, so typos fail
// loudly instead of being ignored.
func checkSpec(r *resourceInfo) error {
	var errs []error
	for path := range r.spec.Attributes {
		if lookupPath(r.attrs, path) == nil {
			errs = append(errs, fmt.Errorf("%s: Attributes names unknown attribute %q", r.typeName, path))
		}
	}
	for _, name := range r.spec.ImportIgnore {
		if _, ok := r.attrs[name]; !ok {
			errs = append(errs, fmt.Errorf("%s: ImportIgnore names unknown attribute %q", r.typeName, name))
		}
	}
	if s := r.spec.SweepAttribute; s != "" {
		if a := lookupPath(r.attrs, s); a == nil || a.kind != kindString {
			errs = append(errs, fmt.Errorf("%s: SweepAttribute %q is not a string attribute", r.typeName, s))
		}
	}
	if len(r.spec.ImportIgnore) > 0 && !r.importable {
		errs = append(errs, fmt.Errorf("%s: ImportIgnore is set but the resource does not support import", r.typeName))
	}
	return errors.Join(errs...)
}

func lookupPath(attrs map[string]*attribute, dotted string) *attribute {
	var cur *attribute
	for i, part := range strings.Split(dotted, ".") {
		if i > 0 {
			if cur.elem != nil {
				cur = cur.elem
			}
			attrs = cur.children
		}
		next, ok := attrs[part]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// writeFiles writes the generated files and deletes generated files that are
// no longer produced. Files without the generated header are never touched.
func writeFiles(root string, files map[string][]byte) error {
	for path, b := range files {
		full := filepath.Join(root, path)
		if old, err := os.ReadFile(full); err == nil && bytes.Equal(old, b) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			return err
		}
	}

	var stale []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		header := ""
		switch {
		case strings.HasSuffix(path, "_gen_test.go"):
			header = goHeader
		case d.Name() == "main.tf" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "testdata":
			header = hclHeader
		default:
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if _, ok := files[rel]; ok {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isGenerated(src, header) {
			stale = append(stale, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(stale)
	for _, path := range stale {
		if err := os.Remove(path); err != nil {
			return err
		}
		// Remove the resource testdata directory when it is now empty.
		if filepath.Base(path) == "main.tf" {
			_ = os.Remove(filepath.Dir(path))
		}
	}
	return nil
}
