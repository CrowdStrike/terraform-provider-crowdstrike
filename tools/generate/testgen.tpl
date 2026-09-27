//go:build testgen

package {{.PackageName}}

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

func init() {
	testgen.Register("crowdstrike_{{.SnakeCaseName}}", testgen.Resource{})
}
