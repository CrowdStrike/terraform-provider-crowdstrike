package cloudsecurity

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

type KacPolicyPrecedenceResource = cloudSecurityKacPolicyPrecedenceResource

// NewKacPolicyPrecedenceResource builds a cloudSecurityKacPolicyPrecedenceResource backed by the
// given API client for tests in the external test package.
func NewKacPolicyPrecedenceResource(
	apiClient *client.CrowdStrikeAPISpecification,
) *KacPolicyPrecedenceResource {
	return &cloudSecurityKacPolicyPrecedenceResource{client: apiClient}
}

// SetKACPolicyPrecedence exposes setKACPolicyPrecedence to the external test package.
func (r *cloudSecurityKacPolicyPrecedenceResource) SetKACPolicyPrecedence(
	ctx context.Context,
	planPolicyIDs []string,
) ([]string, diag.Diagnostics) {
	return r.setKACPolicyPrecedence(ctx, planPolicyIDs)
}
