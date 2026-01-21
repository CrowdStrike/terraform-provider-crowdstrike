package cloudsecurity

import (
	"context"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSetKACPolicyPrecedence(t *testing.T) {
	tests := []struct {
		name                string
		apiPolicyIDs        []string
		planPolicyIDs       []string
		expectedResult      []string
		expectedUpdateCount int // Expected number of updateSinglePolicyPrecedence calls
		expectError         bool
		errorMessage        string
	}{
		{
			name:                "Already in correct order",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3"},
			planPolicyIDs:       []string{"policy-1", "policy-2", "policy-3"},
			expectedResult:      []string{"policy-1", "policy-2", "policy-3"},
			expectedUpdateCount: 0, // No changes needed
			expectError:         false,
		},
		{
			name:                "Simple reorder - move to back",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3", "policy-4"},
			planPolicyIDs:       []string{"policy-2", "policy-3", "policy-4", "policy-1"},
			expectedResult:      []string{"policy-2", "policy-3", "policy-4", "policy-1"},
			expectedUpdateCount: 1, // Only move policy-1 to position 4
			expectError:         false,
		},
		{
			name:                "Simple reorder - move to front",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3", "policy-4"},
			planPolicyIDs:       []string{"policy-4", "policy-1", "policy-2", "policy-3"},
			expectedResult:      []string{"policy-4", "policy-1", "policy-2", "policy-3"},
			expectedUpdateCount: 1, // Only move policy-4 to position 1
			expectError:         false,
		},
		{
			name:                "Reverse order",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3"},
			planPolicyIDs:       []string{"policy-3", "policy-2", "policy-1"},
			expectedResult:      []string{"policy-3", "policy-2", "policy-1"},
			expectedUpdateCount: 2,
			expectError:         false,
		},
		{
			name:                "Complex reordering",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3", "policy-4", "policy-5"},
			planPolicyIDs:       []string{"policy-2", "policy-4", "policy-1", "policy-5", "policy-3"},
			expectedResult:      []string{"policy-2", "policy-4", "policy-1", "policy-5", "policy-3"},
			expectedUpdateCount: 2, // Move policy-1 behind policy-4, then move policy-3 behind policy-5
			expectError:         false,
		},
		{
			name:                "Policy not found in current state",
			apiPolicyIDs:        []string{"policy-1", "policy-2"},
			planPolicyIDs:       []string{"policy-1", "policy-3"}, // policy-3 doesn't exist
			expectedResult:      nil,
			expectedUpdateCount: 0,
			expectError:         true,
			errorMessage:        "Policy ID policy-3 not found in existing policy IDs",
		},
		{
			name:                "Single policy with API policies in wrong order",
			apiPolicyIDs:        []string{"policy-3", "policy-2", "policy-1"},
			planPolicyIDs:       []string{"policy-1"},
			expectedResult:      []string{"policy-1", "policy-3", "policy-2"},
			expectedUpdateCount: 1, // Move policy-1 to the front
			expectError:         false,
		},
		{
			name:                "Policies in correct order, but not correct precedence",
			apiPolicyIDs:        []string{"policy-1", "policy-2", "policy-3", "policy-4", "policy-5", "policy-6"},
			planPolicyIDs:       []string{"policy-4", "policy-5", "policy-6"},
			expectedResult:      []string{"policy-4", "policy-5", "policy-6", "policy-1", "policy-2", "policy-3"},
			expectedUpdateCount: 3, // Move policy-4 to front, then policy-5, and lastly policy-6
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client with initial state
			mockClient := &mockAdmissionControlPoliciesClient{
				policies: make([]string, len(tt.apiPolicyIDs)),
			}
			copy(mockClient.policies, tt.apiPolicyIDs)

			// Set up mock expectations
			mockClient.On("AdmissionControlQueryPolicies", mock.AnythingOfType("*admission_control_policies.AdmissionControlQueryPoliciesParams")).Return(nil, nil).Times(tt.expectedUpdateCount + 1)

			if tt.expectedUpdateCount > 0 {
				mockClient.On("AdmissionControlUpdatePolicyPrecedence", mock.AnythingOfType("*admission_control_policies.AdmissionControlUpdatePolicyPrecedenceParams")).Return(nil, nil).Times(tt.expectedUpdateCount)
			}

			// Create real resource with mocked client
			resource := &cloudSecurityKacPolicyPrecedenceResource{
				client: &client.CrowdStrikeAPISpecification{
					AdmissionControlPolicies: mockClient,
				},
			}

			// Call the method under test
			ctx := context.Background()
			result, diags := resource.setKACPolicyPrecedence(ctx, tt.planPolicyIDs)

			// Verify error expectations
			if tt.expectError {
				assert.True(t, diags.HasError(), "Expected error but none occurred")
				if tt.errorMessage != "" {
					found := false
					for _, diagnostic := range diags {
						if strings.Contains(diagnostic.Detail(), tt.errorMessage) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message '%s', but got different errors: %v", tt.errorMessage, diags)
				}
				return
			}

			assert.False(t, diags.HasError(), "Unexpected error: %v", diags)

			// Verify result
			assert.Equal(t, tt.expectedResult, result, "Result mismatch")

			// Verify all mock expectations were met
			mockClient.AssertExpectations(t)
		})
	}
}

// mockAdmissionControlPoliciesClient implements the ClientService interface using testify/mock
type mockAdmissionControlPoliciesClient struct {
	mock.Mock
	policies []string // In-memory policy list to simulate API state
}

// Implement the required ClientService interface methods
// Mock implementation of AdmissionControlQueryPolicies with testify mock
func (m *mockAdmissionControlPoliciesClient) AdmissionControlQueryPolicies(params *admission_control_policies.AdmissionControlQueryPoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlQueryPoliciesOK, error) {
	args := m.Called(params)

	// Return a copy of the in-memory policies
	resources := make([]string, len(m.policies))
	copy(resources, m.policies)

	response := &admission_control_policies.AdmissionControlQueryPoliciesOK{
		Payload: &models.MsaspecQueryResponse{
			Resources: resources,
		},
	}

	return response, args.Error(1)
}

// Mock implementation of AdmissionControlUpdatePolicyPrecedence with testify mock and state management
func (m *mockAdmissionControlPoliciesClient) AdmissionControlUpdatePolicyPrecedence(params *admission_control_policies.AdmissionControlUpdatePolicyPrecedenceParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdatePolicyPrecedenceOK, error) {
	args := m.Called(params)

	if params.Body == nil || params.Body.ID == nil {
		return nil, args.Error(1)
	}

	policyID := *params.Body.ID
	precedence := int(params.Body.Precedence)

	// Find the policy in the current list
	currentIndex := -1
	for i, id := range m.policies {
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
	if targetIndex < 0 || targetIndex >= len(m.policies) {
		return nil, args.Error(1)
	}

	// Remove the policy from current position
	policy := m.policies[currentIndex]
	m.policies = append(m.policies[:currentIndex], m.policies[currentIndex+1:]...)

	// Insert the policy at the new position
	m.policies = append(m.policies[:targetIndex], append([]string{policy}, m.policies[targetIndex:]...)...)

	return &admission_control_policies.AdmissionControlUpdatePolicyPrecedenceOK{}, args.Error(1)
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlAddHostGroups(params *admission_control_policies.AdmissionControlAddHostGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlAddHostGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlAddHostGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlAddRuleGroupCustomRule(params *admission_control_policies.AdmissionControlAddRuleGroupCustomRuleParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlAddRuleGroupCustomRuleOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlAddRuleGroupCustomRuleOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlCreatePolicy(params *admission_control_policies.AdmissionControlCreatePolicyParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlCreatePolicyOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlCreatePolicyOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlReplaceRuleGroupSelectors(params *admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlReplaceRuleGroupSelectorsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlSetRuleGroupPrecedence(params *admission_control_policies.AdmissionControlSetRuleGroupPrecedenceParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlSetRuleGroupPrecedenceOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlSetRuleGroupPrecedenceOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlCreateRuleGroups(params *admission_control_policies.AdmissionControlCreateRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlCreateRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlCreateRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlDeletePolicies(params *admission_control_policies.AdmissionControlDeletePoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlDeletePoliciesOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlDeletePoliciesOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlDeleteRuleGroups(params *admission_control_policies.AdmissionControlDeleteRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlDeleteRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlDeleteRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlGetPolicies(params *admission_control_policies.AdmissionControlGetPoliciesParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlGetPoliciesOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlGetPoliciesOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlRemoveHostGroups(params *admission_control_policies.AdmissionControlRemoveHostGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlRemoveHostGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlRemoveHostGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlRemoveRuleGroupCustomRule(params *admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlRemoveRuleGroupCustomRuleOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlUpdatePolicy(params *admission_control_policies.AdmissionControlUpdatePolicyParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdatePolicyOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlUpdatePolicyOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) AdmissionControlUpdateRuleGroups(params *admission_control_policies.AdmissionControlUpdateRuleGroupsParams, opts ...admission_control_policies.ClientOption) (*admission_control_policies.AdmissionControlUpdateRuleGroupsOK, error) {
	args := m.Called(params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*admission_control_policies.AdmissionControlUpdateRuleGroupsOK), args.Error(1) //nolint:forcetypeassert
}

func (m *mockAdmissionControlPoliciesClient) SetTransport(transport runtime.ClientTransport) {
	m.Called(transport)
}
