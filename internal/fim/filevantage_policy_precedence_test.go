package fim

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFilevantagePolicyPrecedenceResourceModel_wrap(t *testing.T) {
	tests := []struct {
		name          string
		policies      []string
		expectError   bool
		expectedCount int
	}{
		{
			name:          "empty policies list",
			policies:      []string{},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name:          "single policy",
			policies:      []string{"policy-1"},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name:          "multiple policies",
			policies:      []string{"policy-1", "policy-2", "policy-3"},
			expectError:   false,
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &filevantagePolicyPrecedenceResourceModel{}

			diags := model.wrap(t.Context(), tt.policies)

			if tt.expectError && !diags.HasError() {
				t.Errorf("Expected error but none occurred")
			}
			if !tt.expectError && diags.HasError() {
				t.Errorf("Unexpected error: %v", diags)
			}

			if !diags.HasError() {
				if len(model.IDs.Elements()) != tt.expectedCount {
					t.Errorf("Expected %d IDs, got %d", tt.expectedCount, len(model.IDs.Elements()))
				}

				var actualPolicies []string
				model.IDs.ElementsAs(t.Context(), &actualPolicies, false)
				if diff := cmp.Diff(tt.policies, actualPolicies); diff != "" {
					t.Errorf("Policies mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
