package cloudsecurity_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	cloudsecurity "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_security"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_security/mocks"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type kacPolicyPrecedenceConfig struct {
	policyIds []string
}

func (c kacPolicyPrecedenceConfig) String() string {
	config := `
resource "crowdstrike_cloud_security_kac_policy_precedence" "test" {
  ids = [`

	for i, id := range c.policyIds {
		if i > 0 {
			config += ", "
		}
		config += id
	}

	config += `]
}`
	return config
}

func TestCloudSecurityKacPolicyPrecedenceResource_Comprehensive(t *testing.T) {
	resourceName := "crowdstrike_cloud_security_kac_policy_precedence.test"

	// Create 4 minimal KAC policies for testing various precedence scenarios
	policy1Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	policy2Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	policy3Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	policy4Name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	policy1ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_1"
	policy2ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_2"
	policy3ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_3"
	policy4ResourceName := "crowdstrike_cloud_security_kac_policy.test_policy_4"

	testPoliciesConfig := fmt.Sprintf(`
resource "crowdstrike_cloud_security_kac_policy" "test_policy_1" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_2" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_3" {
  name = %q
}

resource "crowdstrike_cloud_security_kac_policy" "test_policy_4" {
  name = %q
}
`, policy1Name, policy2Name, policy3Name, policy4Name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Initial order: policy_1, policy_2, policy_3, policy_4
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.0", policy1ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.1", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.2", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.3", policy4ResourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				// Completely reverse the order: policy_4, policy_3, policy_2, policy_1
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.0", policy4ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.1", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.2", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.3", policy1ResourceName, "id"),
				),
			},
			{
				// Mixed up the order: policy_1, policy_3, policy_2, policy_4
				Config: acctest.ConfigCompose(
					testPoliciesConfig,
					kacPolicyPrecedenceConfig{
						policyIds: []string{
							"crowdstrike_cloud_security_kac_policy.test_policy_1.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_3.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_2.id",
							"crowdstrike_cloud_security_kac_policy.test_policy_4.id",
						},
					}.String(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ids.#", "4"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.0", policy1ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.1", policy3ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.2", policy2ResourceName, "id"),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "ids.3", policy4ResourceName, "id"),
				),
			},
		},
	})
}

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
			mockClient := &mocks.MockAdmissionControlPoliciesClient{
				Policies: make([]string, len(tt.apiPolicyIDs)),
			}
			copy(mockClient.Policies, tt.apiPolicyIDs)

			// Set up mock expectations
			mockClient.On("AdmissionControlQueryPolicies", mock.AnythingOfType("*admission_control_policies.AdmissionControlQueryPoliciesParams")).Return(nil, nil).Times(tt.expectedUpdateCount + 1)

			if tt.expectedUpdateCount > 0 {
				mockClient.On("AdmissionControlUpdatePolicyPrecedence", mock.AnythingOfType("*admission_control_policies.AdmissionControlUpdatePolicyPrecedenceParams")).Return(nil, nil).Times(tt.expectedUpdateCount)
			}

			// Create real resource with mocked client
			precedenceResource := cloudsecurity.NewKacPolicyPrecedenceResource(
				&client.CrowdStrikeAPISpecification{
					AdmissionControlPolicies: mockClient,
				},
			)

			// Call the method under test
			ctx := context.Background()
			result, diags := precedenceResource.SetKACPolicyPrecedence(ctx, tt.planPolicyIDs)

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
