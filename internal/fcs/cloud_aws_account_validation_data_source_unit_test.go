package fcs

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// and only overrides the methods we need.
type MockCloudAwsRegistration struct {
	mock.Mock
	cloud_aws_registration.ClientService
}

func (m *MockCloudAwsRegistration) CloudRegistrationAwsValidateAccounts(params *cloud_aws_registration.CloudRegistrationAwsValidateAccountsParams, opts ...cloud_aws_registration.ClientOption) (*cloud_aws_registration.CloudRegistrationAwsValidateAccountsOK, error) {
	args := m.Called(params, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	// nolint: forcetypeassert
	return args.Get(0).(*cloud_aws_registration.CloudRegistrationAwsValidateAccountsOK), args.Error(1)
}

func (m *MockCloudAwsRegistration) CloudRegistrationAwsTriggerHealthCheck(params *cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams, opts ...cloud_aws_registration.ClientOption) (*cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckOK, error) {
	args := m.Called(params, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	// nolint: forcetypeassert
	return args.Get(0).(*cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckOK), args.Error(1)
}

// Helper function to create a data source with mock client.
func newTestDataSourceWithMock(mockClient *MockCloudAwsRegistration) *cloudAwsAccountValidationDataSource {
	apiClient := &client.CrowdStrikeAPISpecification{
		CloudAwsRegistration: mockClient,
	}
	return &cloudAwsAccountValidationDataSource{
		client: apiClient,
	}
}

func TestValidateAccount_Success(t *testing.T) {
	mockClient := new(MockCloudAwsRegistration)
	ds := newTestDataSourceWithMock(mockClient)

	ctx := t.Context()
	testAccountID := "123456789012"

	// Mock successful validation response
	mockClient.On("CloudRegistrationAwsValidateAccounts",
		mock.MatchedBy(func(params *cloud_aws_registration.CloudRegistrationAwsValidateAccountsParams) bool {
			return params.Context == ctx && params.AccountID != nil && *params.AccountID == testAccountID
		}),
		mock.Anything,
	).Return(&cloud_aws_registration.CloudRegistrationAwsValidateAccountsOK{
		Payload: &models.RestAWSAccountValidationResponse{},
	}, nil)

	// Execute
	diags := ds.validateAccount(ctx, testAccountID)

	// Verify
	assert.False(t, diags.HasError())
	assert.Equal(t, 0, diags.WarningsCount())
	mockClient.AssertExpectations(t)
}

func TestValidateAccount_APIError(t *testing.T) {
	mockClient := new(MockCloudAwsRegistration)
	ds := newTestDataSourceWithMock(mockClient)

	ctx := t.Context()
	testAccountID := "123456789012"

	// Mock failed validation response
	mockClient.On("CloudRegistrationAwsValidateAccounts",
		mock.MatchedBy(func(params *cloud_aws_registration.CloudRegistrationAwsValidateAccountsParams) bool {
			return params.Context == ctx && params.AccountID != nil && *params.AccountID == testAccountID
		}),
		mock.Anything,
	).Return(nil, assert.AnError)

	// Execute
	diags := ds.validateAccount(ctx, testAccountID)

	// Verify
	assert.False(t, diags.HasError())
	assert.Equal(t, 1, diags.WarningsCount())
	assert.Contains(t, diags.Warnings()[0].Summary(), "Failed to validate AWS account")
	mockClient.AssertExpectations(t)
}

func TestTriggerHealthCheck_WithAccountID_Success(t *testing.T) {
	mockClient := new(MockCloudAwsRegistration)
	ds := newTestDataSourceWithMock(mockClient)

	ctx := t.Context()
	testAccountID := "123456789012"
	testOrgID := ""

	// Mock successful health check trigger
	mockClient.On("CloudRegistrationAwsTriggerHealthCheck",
		mock.MatchedBy(func(params *cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams) bool {
			return params.Context == ctx &&
				len(params.AccountIds) == 1 &&
				params.AccountIds[0] == testAccountID &&
				len(params.OrganizationIds) == 0
		}),
		mock.Anything,
	).Return(&cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckOK{
		Payload: &models.RestAWSHealthCheckTriggerResponseExtV1{},
	}, nil)

	// Execute
	diags := ds.triggerHealthCheck(ctx, testAccountID, testOrgID)

	// Verify
	assert.False(t, diags.HasError())
	assert.Equal(t, 0, diags.WarningsCount())
	mockClient.AssertExpectations(t)
}

func TestTriggerHealthCheck_WithOrganizationID_Success(t *testing.T) {
	mockClient := new(MockCloudAwsRegistration)
	ds := newTestDataSourceWithMock(mockClient)

	ctx := t.Context()
	testAccountID := "123456789012"
	testOrgID := "o-1234567890"

	// Mock successful health check trigger for organization
	mockClient.On("CloudRegistrationAwsTriggerHealthCheck",
		mock.MatchedBy(func(params *cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams) bool {
			return params.Context == ctx &&
				len(params.OrganizationIds) == 1 &&
				params.OrganizationIds[0] == testOrgID &&
				len(params.AccountIds) == 0
		}),
		mock.Anything,
	).Return(&cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckOK{
		Payload: &models.RestAWSHealthCheckTriggerResponseExtV1{},
	}, nil)

	// Execute
	diags := ds.triggerHealthCheck(ctx, testAccountID, testOrgID)

	// Verify
	assert.False(t, diags.HasError())
	assert.Equal(t, 0, diags.WarningsCount())
	mockClient.AssertExpectations(t)
}

func TestTriggerHealthCheck_APIError(t *testing.T) {
	mockClient := new(MockCloudAwsRegistration)
	ds := newTestDataSourceWithMock(mockClient)

	ctx := t.Context()
	testAccountID := "123456789012"
	testOrgID := ""

	// Mock failed health check trigger
	mockClient.On("CloudRegistrationAwsTriggerHealthCheck",
		mock.MatchedBy(func(params *cloud_aws_registration.CloudRegistrationAwsTriggerHealthCheckParams) bool {
			return params.Context == ctx &&
				len(params.AccountIds) == 1 &&
				params.AccountIds[0] == testAccountID
		}),
		mock.Anything,
	).Return(nil, assert.AnError)

	// Execute
	diags := ds.triggerHealthCheck(ctx, testAccountID, testOrgID)

	// Verify
	assert.False(t, diags.HasError())
	assert.Equal(t, 1, diags.WarningsCount())
	assert.Contains(t, diags.Warnings()[0].Summary(), "Failed to trigger health check scan")
	mockClient.AssertExpectations(t)
}

func TestMetadata(t *testing.T) {
	ds := &cloudAwsAccountValidationDataSource{}
	req := datasource.MetadataRequest{
		ProviderTypeName: "crowdstrike",
	}
	resp := &datasource.MetadataResponse{}

	ds.Metadata(t.Context(), req, resp)

	assert.Equal(t, "crowdstrike_cloud_aws_account_validation", resp.TypeName)
}

func TestSchema(t *testing.T) {
	ds := &cloudAwsAccountValidationDataSource{}
	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}

	ds.Schema(t.Context(), req, resp)

	// Verify schema is not nil and has expected attributes
	assert.NotNil(t, resp.Schema)
	assert.NotNil(t, resp.Schema.Attributes["account_id"])
	assert.NotNil(t, resp.Schema.Attributes["organization_id"])
	assert.NotNil(t, resp.Schema.Attributes["validated"])

	// Check that account_id has required validator
	_, hasAccountID := resp.Schema.Attributes["account_id"]
	assert.True(t, hasAccountID, "account_id attribute should exist")

	// Check that organization_id exists
	_, hasOrgID := resp.Schema.Attributes["organization_id"]
	assert.True(t, hasOrgID, "organization_id attribute should exist")

	// Check that validated exists
	_, hasValidated := resp.Schema.Attributes["validated"]
	assert.True(t, hasValidated, "validated attribute should exist")
}

func TestConfigure_WithValidClient(t *testing.T) {
	ds := &cloudAwsAccountValidationDataSource{}
	mockClient := &client.CrowdStrikeAPISpecification{}

	req := datasource.ConfigureRequest{
		ProviderData: mockClient,
	}
	resp := &datasource.ConfigureResponse{}

	ds.Configure(t.Context(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.Equal(t, mockClient, ds.client)
}

func TestConfigure_WithInvalidClient(t *testing.T) {
	ds := &cloudAwsAccountValidationDataSource{}
	invalidData := "not a client"

	req := datasource.ConfigureRequest{
		ProviderData: invalidData,
	}
	resp := &datasource.ConfigureResponse{}

	ds.Configure(t.Context(), req, resp)

	assert.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "Unexpected Data Source Configure Type")
}

func TestConfigure_WithNilProviderData(t *testing.T) {
	ds := &cloudAwsAccountValidationDataSource{}

	req := datasource.ConfigureRequest{
		ProviderData: nil,
	}
	resp := &datasource.ConfigureResponse{}

	ds.Configure(t.Context(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	assert.Nil(t, ds.client)
}
