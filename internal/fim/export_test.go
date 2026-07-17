package fim

type (
	FilevantagePoliciesDataSource      = filevantagePoliciesDataSource
	FilevantagePoliciesDataSourceModel = filevantagePoliciesDataSourceModel
	PolicyRef                          = policyRef
)

var (
	FilterPoliciesByAttributes = filterPoliciesByAttributes

	FilterPoliciesByCID = filterPoliciesByCID
	DistinctCIDs        = distinctCIDs
	StripChecksum       = stripChecksum
	DefaultPolicyName   = defaultPolicyName
)

// NewPolicyRef builds a policyRef for tests in the external test package.
func NewPolicyRef(id, cid, name string) policyRef {
	return policyRef{id: id, cid: cid, name: name}
}
