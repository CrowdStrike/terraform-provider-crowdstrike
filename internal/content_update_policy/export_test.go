package contentupdatepolicy

var (
	FilterPoliciesByIDs        = filterPoliciesByIDs
	FilterPoliciesByAttributes = filterPoliciesByAttributes

	FilterPoliciesByCID = filterPoliciesByCID
	DistinctCIDs        = distinctCIDs
	StripChecksum       = stripChecksum
)

type PolicyRef = policyRef

// NewPolicyRef builds a policyRef for tests in the external test package.
func NewPolicyRef(id, cid, name string) policyRef {
	return policyRef{id: id, cid: cid, name: name}
}
