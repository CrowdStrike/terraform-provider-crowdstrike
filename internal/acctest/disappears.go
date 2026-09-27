package acctest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

// ResourceDisappears returns a state check that deletes a resource outside of
// Terraform by calling its own Delete with the shared configured provider
// data, so the next refresh sees it as gone. Delete gets the resource's full
// state as Terraform recorded it after apply.
func ResourceDisappears(newResource func() fwresource.Resource, resourceName string) statecheck.StateCheck {
	return resourceDisappears{newResource: newResource, resourceName: resourceName}
}

type resourceDisappears struct {
	newResource  func() fwresource.Resource
	resourceName string
}

func (d resourceDisappears) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = d.deleteResource(ctx, req)
}

func (d resourceDisappears) deleteResource(ctx context.Context, req statecheck.CheckStateRequest) error {
	if req.State == nil || req.State.Values == nil || req.State.Values.RootModule == nil {
		return errors.New("state is empty")
	}
	var attrs map[string]any
	for _, r := range req.State.Values.RootModule.Resources {
		if r.Address == d.resourceName {
			attrs = r.AttributeValues
			break
		}
	}
	if attrs == nil {
		return fmt.Errorf("resource not found in state: %s", d.resourceName)
	}

	providerData, err := configuredProvider()
	if err != nil {
		return fmt.Errorf("configure provider: %w", err)
	}

	res := d.newResource()
	if rc, ok := res.(fwresource.ResourceWithConfigure); ok {
		var resp fwresource.ConfigureResponse
		rc.Configure(ctx, fwresource.ConfigureRequest{ProviderData: providerData}, &resp)
		if err := diagErr("configure", resp.Diagnostics); err != nil {
			return err
		}
	}

	var sr fwresource.SchemaResponse
	res.Schema(ctx, fwresource.SchemaRequest{}, &sr)
	b, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	raw, err := tfprotov6.RawState{JSON: b}.Unmarshal(sr.Schema.Type().TerraformType(ctx))
	if err != nil {
		return fmt.Errorf("decode state: %w", err)
	}

	var resp fwresource.DeleteResponse
	res.Delete(ctx, fwresource.DeleteRequest{State: tfsdk.State{Schema: sr.Schema, Raw: raw}}, &resp)
	return diagErr("delete", resp.Diagnostics)
}

func diagErr(op string, diags diag.Diagnostics) error {
	if !diags.HasError() {
		return nil
	}
	var errs []error
	for _, d := range diags.Errors() {
		errs = append(errs, fmt.Errorf("%s: %s", d.Summary(), d.Detail()))
	}
	return fmt.Errorf("%s: %w", op, errors.Join(errs...))
}
