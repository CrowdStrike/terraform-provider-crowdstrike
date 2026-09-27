// Command testgen generates acceptance tests from resource schemas.
//
// It loads every resource from the provider, keeps the ones registered with
// internal/testgen (from build-tagged testgen.go files), and writes for each:
//
//   - internal/<pkg>/<resource>_resource_gen_test.go
//   - internal/<pkg>/testdata/<resource>/main.tf, shared by all of its tests
//
// A hand-written test with the same name (case-insensitive) replaces the
// generated one. Generated files carry a DO NOT EDIT header; files with that
// header that were not produced by this run are deleted.
//
// Run it through `make gen`, or directly with:
//
//	go run -tags testgen ./tools/testgen
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	if err := run(context.Background(), "."); err != nil {
		fmt.Fprintln(os.Stderr, "testgen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, root string) error {
	if _, err := os.Stat(root + "/go.mod"); err != nil {
		return fmt.Errorf("must run from the module root: %w", err)
	}
	p := provider.New("test")()
	resources, err := loadResources(ctx, p, root)
	if err != nil {
		return err
	}
	srv := providerserver.NewProtocol6(p)()

	files, err := generate(ctx, srv, resources)
	if err != nil {
		return err
	}
	return writeFiles(root, files)
}

// generate builds the generated files for every registered resource. It
// returns every error found rather than stopping at the first one.
func generate(ctx context.Context, srv validatorServer, resources map[string]*resourceInfo) (map[string][]byte, error) {
	files := map[string][]byte{}
	var errs []error
	for _, r := range registered(resources, &errs) {
		out, err := generateResource(ctx, srv, r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for path, b := range out {
			files[path] = b
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return files, nil
}
