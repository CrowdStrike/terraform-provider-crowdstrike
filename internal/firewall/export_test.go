package firewall

type PolicyRef = policyRef

var (
	FilterPoliciesByCID = filterPoliciesByCID
	DistinctCIDs        = distinctCIDs
	StripChecksum       = stripChecksum
)

// NewPolicyRef builds a policyRef for tests in the external test package.
func NewPolicyRef(id, cid, name string) policyRef {
	return policyRef{id: id, cid: cid, name: name}
}
