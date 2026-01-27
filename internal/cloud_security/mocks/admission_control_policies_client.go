package mocks

import (
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/mock"
)

// MockAdmissionControlPoliciesClient implements the ClientService interface using testify/mock.
type MockAdmissionControlPoliciesClient struct {
	mock.Mock
	Policies []string // In-memory policy list to simulate API state
}

// Implement the required ClientService interface methods

// AdmissionControlQueryPolicies mocks the behavior of the client by returning the in memory list of policy IDs.
func (m *MockAdmissionControlPoliciesClient) AdmissionControlQueryPolicies(params *admission_control_policies.AdmissionControlQueryPoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlQueryPoliciesOK, error) {
	args := m.Called(params)

	// Return a copy of the in-memory policies
	resources := make([]string, len(m.Policies))
	copy(resources, m.Policies)

	response := &admission_control_policies.AdmissionControlQueryPoliciesOK{
		Payload: &models.MsaspecQueryResponse{
			Resources: resources,
		},
	}

	return response, args.Error(1)
}

// AdmissionControlUpdatePolicyPrecedence mocks the behavior of the client
// by inserting the given policy ID into the requested precedence, which is the 1-based version of the index.
func (m *MockAdmissionControlPoliciesClient) AdmissionControlUpdatePolicyPrecedence(params *admission_control_policies.AdmissionControlUpdatePolicyPrecedenceParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdatePolicyPrecedenceOK, error) {
	args := m.Called(params)

	if params.Body == nil || params.Body.ID == nil {
		return nil, args.Error(1)
	}

	policyID := *params.Body.ID
	precedence := int(params.Body.Precedence)

	// Find the policy in the current list
	currentIndex := -1
	for i, id := range m.Policies {
		if id == policyID {
			currentIndex = i
			break
		}
	}

	if currentIndex == -1 {
		return nil, args.Error(1)
	}

	// Convert 1-based precedence to 0-based index
	targetIndex := precedence - 1
	if targetIndex < 0 || targetIndex >= len(m.Policies) {
		return nil, args.Error(1)
	}

	// Remove the policy from current position
	policy := m.Policies[currentIndex]
	m.Policies = append(m.Policies[:currentIndex], m.Policies[currentIndex+1:]...)

	// Insert the policy at the new position
	m.Policies = append(m.Policies[:targetIndex], append([]string{policy}, m.Policies[targetIndex:]...)...)

	return &admission_control_policies.AdmissionControlUpdatePolicyPrecedenceOK{}, args.Error(1)
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlAddHostGroups(params *admission_control_policies.AdmissionControlAddHostGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlAddHostGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlAddHostGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlAddRuleGroupCustomRule(params *admission_control_policies.AdmissionControlAddRuleGroupCustomRuleParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlAddRuleGroupCustomRuleOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlAddRuleGroupCustomRuleOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlCreatePolicy(params *admission_control_policies.AdmissionControlCreatePolicyParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlCreatePolicyOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlCreatePolicyOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlReplaceRuleGroupSelectors(params *admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlSetRuleGroupPrecedence(params *admission_control_policies.AdmissionControlSetRuleGroupPrecedenceParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlSetRuleGroupPrecedenceOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlSetRuleGroupPrecedenceOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlCreateRuleGroups(params *admission_control_policies.AdmissionControlCreateRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlCreateRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlCreateRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlDeletePolicies(params *admission_control_policies.AdmissionControlDeletePoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlDeletePoliciesOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlDeletePoliciesOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlDeleteRuleGroups(params *admission_control_policies.AdmissionControlDeleteRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlDeleteRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlDeleteRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlGetPolicies(params *admission_control_policies.AdmissionControlGetPoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlGetPoliciesOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlGetPoliciesOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlRemoveHostGroups(params *admission_control_policies.AdmissionControlRemoveHostGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlRemoveHostGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlRemoveHostGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlRemoveRuleGroupCustomRule(params *admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlUpdatePolicy(params *admission_control_policies.AdmissionControlUpdatePolicyParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdatePolicyOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlUpdatePolicyOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) AdmissionControlUpdateRuleGroups(params *admission_control_policies.AdmissionControlUpdateRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdateRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlUpdateRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *MockAdmissionControlPoliciesClient) SetTransport(transport runtime.ClientTransport) {
	m.Called(transport)
}
