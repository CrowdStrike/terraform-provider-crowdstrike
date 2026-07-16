package preventionpolicy

type (
	PreventionPoliciesDataSource      = preventionPoliciesDataSource
	PreventionPoliciesDataSourceModel = preventionPoliciesDataSourceModel
	PolicyRef                         = policyRef
)

var (
	FilterPoliciesByIDs        = filterPoliciesByIDs
	FilterPoliciesByAttributes = filterPoliciesByAttributes

	FilterPoliciesByCID = filterPoliciesByCID
	DistinctCIDs        = distinctCIDs
	StripChecksum       = stripChecksum
)

// NewPolicyRef builds a policyRef for tests in the external test package.
func NewPolicyRef(id, cid, name string) policyRef {
	return policyRef{id: id, cid: cid, name: name}
}
