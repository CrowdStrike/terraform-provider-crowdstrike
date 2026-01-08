package cloudsecurity

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Simple test approach: Create a minimal tfsdk.Config for testing
func createTestConfig(t *testing.T, values map[string]interface{}) tfsdk.Config {
	// Create a minimal schema for testing
	testSchema := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional: true,
			},
			"name": schema.StringAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"logic": schema.StringAttribute{
				Optional: true,
			},
			"severity": schema.StringAttribute{
				Optional: true,
			},
			"domain": schema.StringAttribute{
				Optional: true,
			},
			"subdomain": schema.StringAttribute{
				Optional: true,
			},
			"resource_type": schema.StringAttribute{
				Optional: true,
			},
			"rule_provider": schema.StringAttribute{
				Optional: true,
			},
			"cloud_provider": schema.StringAttribute{
				Optional: true,
			},
			"rule_platform": schema.StringAttribute{
				Optional: true,
			},
			"cloud_platform": schema.StringAttribute{
				Optional: true,
			},
			"parent_rule_id": schema.StringAttribute{
				Optional: true,
			},
			"alert_info": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"remediation_info": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"controls": schema.SetNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Optional: true,
						},
						"code": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"attack_types": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}

	// Define the schema attributes for tftypes
	attributeTypes := map[string]tftypes.Type{
		"id":             tftypes.String,
		"name":           tftypes.String,
		"description":    tftypes.String,
		"logic":          tftypes.String,
		"severity":       tftypes.String,
		"domain":         tftypes.String,
		"subdomain":      tftypes.String,
		"resource_type":  tftypes.String,
		"rule_provider":  tftypes.String,
		"cloud_provider": tftypes.String,
		"rule_platform":  tftypes.String,
		"cloud_platform": tftypes.String,
		"parent_rule_id": tftypes.String,
		"alert_info":     tftypes.List{ElementType: tftypes.String},
		"controls":       tftypes.Set{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"authority": tftypes.String, "code": tftypes.String}}},
		"attack_types":   tftypes.Set{ElementType: tftypes.String},
		"remediation_info": tftypes.List{ElementType: tftypes.String},
	}

	// Create tftypes values from the input map
	tfValues := make(map[string]tftypes.Value)
	for key, value := range values {
		switch v := value.(type) {
		case string:
			tfValues[key] = tftypes.NewValue(tftypes.String, v)
		case []string:
			elements := make([]tftypes.Value, len(v))
			for i, s := range v {
				elements[i] = tftypes.NewValue(tftypes.String, s)
			}
			tfValues[key] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, elements)
		case nil:
			tfValues[key] = tftypes.NewValue(attributeTypes[key], nil)
		}
	}

	// Fill in any missing attributes with null values
	for key, attrType := range attributeTypes {
		if _, exists := tfValues[key]; !exists {
			tfValues[key] = tftypes.NewValue(attrType, nil)
		}
	}

	objectType := tftypes.Object{AttributeTypes: attributeTypes}
	configValue := tftypes.NewValue(objectType, tfValues)

	config := tfsdk.Config{
		Raw:    configValue,
		Schema: testSchema,
	}

	return config
}

// Create a test plan for plan modifier tests
func createTestPlan(t *testing.T, values map[string]interface{}) tfsdk.Plan {
	// Create a minimal schema for testing
	testSchema := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional: true,
			},
			"name": schema.StringAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"logic": schema.StringAttribute{
				Optional: true,
			},
			"severity": schema.StringAttribute{
				Optional: true,
			},
			"domain": schema.StringAttribute{
				Optional: true,
			},
			"subdomain": schema.StringAttribute{
				Optional: true,
			},
			"rule_provider": schema.StringAttribute{
				Optional: true,
			},
			"cloud_provider": schema.StringAttribute{
				Optional: true,
			},
			"rule_platform": schema.StringAttribute{
				Optional: true,
			},
			"cloud_platform": schema.StringAttribute{
				Optional: true,
			},
		},
	}

	// Define the schema attributes for tftypes
	attributeTypes := map[string]tftypes.Type{
		"id":             tftypes.String,
		"name":           tftypes.String,
		"description":    tftypes.String,
		"logic":          tftypes.String,
		"severity":       tftypes.String,
		"domain":         tftypes.String,
		"subdomain":      tftypes.String,
		"rule_provider":  tftypes.String,
		"cloud_provider": tftypes.String,
		"rule_platform":  tftypes.String,
		"cloud_platform": tftypes.String,
	}

	// Create tftypes values from the input map
	tfValues := make(map[string]tftypes.Value)
	for key, value := range values {
		switch v := value.(type) {
		case string:
			tfValues[key] = tftypes.NewValue(tftypes.String, v)
		case nil:
			tfValues[key] = tftypes.NewValue(attributeTypes[key], nil)
		}
	}

	// Fill in any missing attributes with null values
	for key, attrType := range attributeTypes {
		if _, exists := tfValues[key]; !exists {
			tfValues[key] = tftypes.NewValue(attrType, nil)
		}
	}

	objectType := tftypes.Object{AttributeTypes: attributeTypes}
	planValue := tftypes.NewValue(objectType, tfValues)

	plan := tfsdk.Plan{
		Raw:    planValue,
		Schema: testSchema,
	}

	return plan
}

// Test the CSPM/IOM validator
func TestResourceTypeRequiredForCSPMValidator(t *testing.T) {
	validator := &resourceTypeRequiredForCSPMValidator{}
	ctx := context.Background()

	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorCount  int
	}{
		{
			name: "Valid CSPM/IOM with resource_type and rule_provider",
			config: map[string]interface{}{
				"domain":        "CSPM",
				"subdomain":     "IOM",
				"resource_type": "AWS::EC2::Instance",
				"rule_provider": "AWS",
			},
			expectError: false,
		},
		{
			name: "Valid CSPM/IOM with resource_type and cloud_provider (deprecated)",
			config: map[string]interface{}{
				"domain":         "CSPM",
				"subdomain":      "IOM",
				"resource_type":  "AWS::EC2::Instance",
				"cloud_provider": "AWS",
			},
			expectError: false,
		},
		{
			name: "Missing resource_type for CSPM/IOM",
			config: map[string]interface{}{
				"domain":        "CSPM",
				"subdomain":     "IOM",
				"rule_provider": "AWS",
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "Missing provider for CSPM/IOM",
			config: map[string]interface{}{
				"domain":        "CSPM",
				"subdomain":     "IOM",
				"resource_type": "AWS::EC2::Instance",
			},
			expectError: true,
			errorCount:  1,
		},
		{
			name: "Missing both resource_type and provider for CSPM/IOM",
			config: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "IOM",
			},
			expectError: true,
			errorCount:  2,
		},
		{
			name: "Runtime domain - no validation required",
			config: map[string]interface{}{
				"domain":    "Runtime",
				"subdomain": "IOM",
			},
			expectError: false,
		},
		{
			name: "CSPM with different subdomain - no validation required",
			config: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "Other",
			},
			expectError: false,
		},
		{
			name: "Default values (CSPM/IOM) missing required fields",
			config: map[string]interface{}{
				// Using defaults: domain="CSPM", subdomain="IOM"
			},
			expectError: true,
			errorCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t, tt.config)
			req := resource.ValidateConfigRequest{
				Config: config,
			}
			resp := &resource.ValidateConfigResponse{}

			validator.ValidateResource(ctx, req, resp)

			if tt.expectError {
				if !resp.Diagnostics.HasError() {
					t.Errorf("Expected validation error but got none")
				}
				if len(resp.Diagnostics.Errors()) != tt.errorCount {
					t.Errorf("Expected %d errors, got %d", tt.errorCount, len(resp.Diagnostics.Errors()))
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no validation errors but got: %v", resp.Diagnostics.Errors())
				}
			}
		})
	}
}

// Test the Runtime/IOM fields disabled validator
func TestRuntimeIOMFieldsDisabledValidator(t *testing.T) {
	validator := &runtimeIOMFieldsDisabledValidator{}
	ctx := context.Background()

	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorField  string
	}{
		{
			name: "Valid Runtime/IOM with allowed fields only",
			config: map[string]interface{}{
				"domain":    "Runtime",
				"subdomain": "IOM",
			},
			expectError: false,
		},
		{
			name: "Runtime/IOM with alert_info - should fail",
			config: map[string]interface{}{
				"domain":     "Runtime",
				"subdomain":  "IOM",
				"alert_info": []string{"This should fail"},
			},
			expectError: true,
			errorField:  "alert_info",
		},
		{
			name: "Runtime/IOM with parent_rule_id - should fail",
			config: map[string]interface{}{
				"domain":         "Runtime",
				"subdomain":      "IOM",
				"parent_rule_id": "test-id",
			},
			expectError: true,
			errorField:  "parent_rule_id",
		},
		{
			name: "Runtime/IOM with resource_type - should fail",
			config: map[string]interface{}{
				"domain":        "Runtime",
				"subdomain":     "IOM",
				"resource_type": "AWS::EC2::Instance",
			},
			expectError: true,
			errorField:  "resource_type",
		},
		{
			name: "Runtime/IOM with remediation_info - should fail",
			config: map[string]interface{}{
				"domain":           "Runtime",
				"subdomain":        "IOM",
				"remediation_info": []string{"Step 1"},
			},
			expectError: true,
			errorField:  "remediation_info",
		},
		{
			name: "CSPM domain - no validation applied",
			config: map[string]interface{}{
				"domain":     "CSPM",
				"subdomain":  "IOM",
				"alert_info": []string{"This is allowed for CSPM"},
			},
			expectError: false,
		},
		{
			name: "Runtime with different subdomain - no validation applied",
			config: map[string]interface{}{
				"domain":     "Runtime",
				"subdomain":  "Other",
				"alert_info": []string{"This is allowed for Runtime/Other"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t, tt.config)
			req := resource.ValidateConfigRequest{
				Config: config,
			}
			resp := &resource.ValidateConfigResponse{}

			validator.ValidateResource(ctx, req, resp)

			if tt.expectError {
				if !resp.Diagnostics.HasError() {
					t.Errorf("Expected validation error but got none")
				}
				// Check that the error mentions the expected field
				found := false
				for _, err := range resp.Diagnostics.Errors() {
					if err.Summary() == "Invalid attribute configuration" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error for field %s but didn't find it", tt.errorField)
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("Expected no validation errors but got: %v", resp.Diagnostics.Errors())
				}
			}
		})
	}
}

// Test the Kubernetes default plan modifier
func TestKubernetesDefaultForRuntimeModifier(t *testing.T) {
	modifier := kubernetesDefaultForRuntimeModifier{}
	ctx := context.Background()

	tests := []struct {
		name           string
		planValues     map[string]interface{}
		configValue    *string
		expectedResult *string
	}{
		{
			name: "Runtime domain should get Kubernetes default",
			planValues: map[string]interface{}{
				"domain":    "Runtime",
				"subdomain": "IOM",
			},
			configValue:    nil,
			expectedResult: stringPtr("Kubernetes"),
		},
		{
			name: "CSPM domain should not get default",
			planValues: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "IOM",
			},
			configValue:    nil,
			expectedResult: nil,
		},
		{
			name: "Runtime with explicit config value should not be overridden",
			planValues: map[string]interface{}{
				"domain":    "Runtime",
				"subdomain": "IOM",
			},
			configValue:    stringPtr("AWS"),
			expectedResult: nil, // Should not modify when config value is set
		},
		{
			name: "Default domain/subdomain (CSPM/IOM) should not get default",
			planValues: map[string]interface{}{
				// Using defaults
			},
			configValue:    nil,
			expectedResult: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := createTestPlan(t, tt.planValues)

			var configValue types.String
			if tt.configValue != nil {
				configValue = types.StringValue(*tt.configValue)
			} else {
				configValue = types.StringNull()
			}

			req := planmodifier.StringRequest{
				Plan:        plan,
				ConfigValue: configValue,
				PlanValue:   types.StringNull(),
			}
			resp := &planmodifier.StringResponse{
				PlanValue: types.StringNull(),
			}

			modifier.PlanModifyString(ctx, req, resp)

			if tt.expectedResult != nil {
				if resp.PlanValue.IsNull() {
					t.Errorf("Expected plan value to be set to %s but it was null", *tt.expectedResult)
				} else if resp.PlanValue.ValueString() != *tt.expectedResult {
					t.Errorf("Expected plan value %s but got %s", *tt.expectedResult, resp.PlanValue.ValueString())
				}
			} else {
				if !resp.PlanValue.IsNull() {
					t.Errorf("Expected plan value to remain null but got %s", resp.PlanValue.ValueString())
				}
			}
		})
	}
}

// Test the RequireWhenCSPMIOM plan modifier
func TestRequireWhenCSPMIOMModifier(t *testing.T) {
	modifier := requireWhenCSPMIOMModifier{}
	ctx := context.Background()

	tests := []struct {
		name           string
		planValues     map[string]interface{}
		configValue    *string
		planValue      *string
		expectedResult bool // true if should set to null
	}{
		{
			name: "CSPM/IOM with no config value should set to null",
			planValues: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "IOM",
			},
			configValue:    nil,
			planValue:      nil,
			expectedResult: true,
		},
		{
			name: "CSPM/IOM with config value should not modify",
			planValues: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "IOM",
			},
			configValue:    stringPtr("AWS"),
			planValue:      stringPtr("AWS"),
			expectedResult: false,
		},
		{
			name: "Runtime domain should not modify",
			planValues: map[string]interface{}{
				"domain":    "Runtime",
				"subdomain": "IOM",
			},
			configValue:    nil,
			planValue:      nil,
			expectedResult: false,
		},
		{
			name: "CSPM with different subdomain should not modify",
			planValues: map[string]interface{}{
				"domain":    "CSPM",
				"subdomain": "Other",
			},
			configValue:    nil,
			planValue:      nil,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := createTestPlan(t, tt.planValues)

			var configValue types.String
			if tt.configValue != nil {
				configValue = types.StringValue(*tt.configValue)
			} else {
				configValue = types.StringNull()
			}

			var planValue types.String
			if tt.planValue != nil {
				planValue = types.StringValue(*tt.planValue)
			} else {
				planValue = types.StringNull()
			}

			req := planmodifier.StringRequest{
				Plan:        plan,
				ConfigValue: configValue,
				PlanValue:   planValue,
			}
			resp := &planmodifier.StringResponse{
				PlanValue: planValue,
			}

			modifier.PlanModifyString(ctx, req, resp)

			if tt.expectedResult {
				if !resp.PlanValue.IsNull() {
					t.Errorf("Expected plan value to be set to null but got %s", resp.PlanValue.ValueString())
				}
			} else {
				// Should remain unchanged
				if planValue.IsNull() && !resp.PlanValue.IsNull() {
					t.Errorf("Expected plan value to remain null but got %s", resp.PlanValue.ValueString())
				} else if !planValue.IsNull() && resp.PlanValue.ValueString() != planValue.ValueString() {
					t.Errorf("Expected plan value to remain %s but got %s", planValue.ValueString(), resp.PlanValue.ValueString())
				}
			}
		})
	}
}

// Helper function for string pointers
func stringPtr(s string) *string {
	return &s
}