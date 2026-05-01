package {{.PackageName}}

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_{{.SnakeCaseName}}", sweep{{.PascalCaseName}})
}

func sweep{{.PascalCaseName}}(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	// TODO: Implement sweep logic
	// 1. Query for resources with sweep.ResourcePrefix in their name
	// 2. For each resource, append sweep.NewSweepResource(id, name, deleteFunc)
	_ = fmt.Sprintf("name:~'%s'", sweep.ResourcePrefix)

	return sweepables, nil
}

func delete{{.PascalCaseName}}(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	// TODO: Implement delete logic
	// 1. Build delete API params with the resource ID
	// 2. Call the API
	// 3. Check sweep.ShouldIgnoreError(err) for soft failures

	return nil
}
