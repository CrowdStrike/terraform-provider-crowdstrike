package main

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// sampleRName stands in for acctest.RandomResourceName when validating
// generated configs. It has the same prefix and maximum length.
const sampleRName = "tf-acc-test-1234567890123456789"

// validateConfig runs the provider's own ValidateResourceConfig RPC on a
// generated config, which applies attribute validators, ConfigValidators,
// and ValidateConfig exactly as terraform validate would.
func validateConfig(ctx context.Context, srv validatorServer, r *resourceInfo, values map[string]value) (err error) {
	vals := make(map[string]tftypes.Value, len(r.schemaType.AttributeTypes))
	for name, t := range r.schemaType.AttributeTypes {
		if v, ok := values[name]; ok {
			vals[name] = toTF(r.attrs[name], v, t)
		} else {
			vals[name] = tftypes.NewValue(t, nil)
		}
	}
	dv, err := tfprotov6.NewDynamicValue(r.schemaType, tftypes.NewValue(r.schemaType, vals))
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("provider panicked validating config: %v", p)
		}
	}()
	resp, err := srv.ValidateResourceConfig(ctx, &tfprotov6.ValidateResourceConfigRequest{TypeName: r.typeName, Config: &dv})
	if err != nil {
		return err
	}
	var msgs []string
	for _, d := range resp.Diagnostics {
		if d.Severity != tfprotov6.DiagnosticSeverityError {
			continue
		}
		msg := d.Summary + ": " + d.Detail
		if d.Attribute != nil {
			msg = d.Attribute.String() + ": " + msg
		}
		msgs = append(msgs, strings.ReplaceAll(msg, "\n", " "))
	}
	if len(msgs) > 0 {
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return nil
}

func toTF(a *attribute, v value, t tftypes.Type) tftypes.Value {
	if v.null {
		return tftypes.NewValue(t, nil)
	}
	switch a.kind {
	case kindString:
		s := v.str
		if v.rName {
			s = sampleRName + s
		}
		return tftypes.NewValue(t, s)
	case kindBool:
		return tftypes.NewValue(t, v.prim)
	case kindInt64, kindInt32:
		n, _ := v.prim.(int64)
		return tftypes.NewValue(t, new(big.Float).SetInt64(n))
	case kindFloat64, kindFloat32:
		f, _ := v.prim.(float64)
		return tftypes.NewValue(t, big.NewFloat(f))
	case kindList, kindSet:
		var et tftypes.Type
		if l, ok := t.(tftypes.List); ok {
			et = l.ElementType
		} else {
			et = t.(tftypes.Set).ElementType //nolint:forcetypeassert // schema type matches kind
		}
		elems := make([]tftypes.Value, len(v.elems))
		for i, e := range v.elems {
			elems[i] = toTF(a.elem, e, et)
		}
		return tftypes.NewValue(t, elems)
	case kindObject:
		ot := t.(tftypes.Object) //nolint:forcetypeassert // schema type matches kind
		fields := make(map[string]tftypes.Value, len(ot.AttributeTypes))
		for name, ft := range ot.AttributeTypes {
			if fv, ok := v.fields[name]; ok {
				fields[name] = toTF(a.children[name], fv, ft)
			} else {
				fields[name] = tftypes.NewValue(ft, nil)
			}
		}
		return tftypes.NewValue(t, fields)
	}
	panic("toTF: unsupported attribute " + a.dotted())
}
