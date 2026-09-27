package acctest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// CheckResourceDisappears deletes a resource outside of Terraform by calling
// its own Delete with the shared test client, so the next refresh sees it as
// gone. Delete gets a state holding the resource's top-level primitive
// attributes, such as its ID and enabled flag, copied from Terraform state;
// nested attributes and collections are null.
func CheckResourceDisappears(newResource func() fwresource.Resource, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state: %s", resourceName)
		}
		client := testconfig.GetTestClient()
		if client == nil {
			return errors.New("test client is not initialized; the test must call acctest.PreCheck")
		}

		ctx := context.Background()
		res := newResource()
		if rc, ok := res.(fwresource.ResourceWithConfigure); ok {
			var resp fwresource.ConfigureResponse
			rc.Configure(ctx, fwresource.ConfigureRequest{ProviderData: config.ProviderConfig{
				ClientId: os.Getenv("FALCON_CLIENT_ID"),
				Client:   client,
			}}, &resp)
			if err := diagErr("configure", resp.Diagnostics); err != nil {
				return err
			}
		}

		var sr fwresource.SchemaResponse
		res.Schema(ctx, fwresource.SchemaRequest{}, &sr)
		state := tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(sr.Schema.Type().TerraformType(ctx), nil)}
		for name, attr := range sr.Schema.Attributes {
			// Only top-level primitives have a flatmap key equal to their name.
			raw, ok := rs.Primary.Attributes[name]
			if !ok {
				continue
			}
			v, err := typedValue(attr.GetType().TerraformType(ctx), raw)
			if err == nil {
				err = diagErr("set", state.SetAttribute(ctx, path.Root(name), v))
			}
			if err != nil {
				log.Printf("[WARN] CheckResourceDisappears: %s = %q not copied to Delete state: %s", name, raw, err)
			}
		}

		var resp fwresource.DeleteResponse
		res.Delete(ctx, fwresource.DeleteRequest{State: state}, &resp)
		return diagErr("delete", resp.Diagnostics)
	}
}

// typedValue converts a flatmap string into the Go value SetAttribute
// accepts for a primitive attribute type.
func typedValue(t tftypes.Type, raw string) (any, error) {
	switch {
	case t.Is(tftypes.String):
		return raw, nil
	case t.Is(tftypes.Bool):
		return strconv.ParseBool(raw)
	case t.Is(tftypes.Number):
		f, _, err := big.ParseFloat(raw, 10, 512, big.ToNearestEven)
		return f, err
	}
	return nil, fmt.Errorf("type %s is not a primitive", t)
}

func diagErr(op string, diags diag.Diagnostics) error {
	var errs []error
	for _, d := range diags.Errors() {
		errs = append(errs, fmt.Errorf("%s: %s", d.Summary(), d.Detail()))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", op, errors.Join(errs...))
	}
	return nil
}
