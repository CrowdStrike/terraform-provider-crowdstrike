package fcs_test

import (
	"context"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const legacyAgentlessRole = "CrowdStrikeAgentlessScanningIntegrationRole"

// awsAccountStateModel returns a refreshed state with DSPM/Vulnerability scanning set as given.
func awsAccountStateModel(dspmEnabled bool, roleName string, useAffixes bool) fcs.CloudAWSAccountModel {
	return fcs.CloudAWSAccountModel{
		AccountID:              types.StringValue("123456789012"),
		OrganizationID:         types.StringValue(""),
		TargetOUs:              types.ListValueMust(types.StringType, []attr.Value{}),
		IsOrgManagementAccount: types.BoolValue(false),
		AccountType:            types.StringValue("commercial"),
		DeploymentMethod:       types.StringValue("terraform-native"),
		ResourceNamePrefix:     types.StringValue(""),
		ResourceNameSuffix:     types.StringValue(""),
		AssetInventory:         &fcs.AssetInventoryOptions{Enabled: types.BoolValue(true), RoleName: types.StringNull()},
		RealtimeVisibility: &fcs.RealtimeVisibilityOptions{
			Enabled:                    types.BoolValue(false),
			CloudTrailRegion:           types.StringValue("us-east-1"),
			UseExistingCloudTrail:      types.BoolValue(true),
			LogIngestionMethod:         types.StringValue("eventbridge"),
			LogIngestionS3BucketName:   types.StringNull(),
			LogIngestionSnsTopicArn:    types.StringNull(),
			LogIngestionS3BucketPrefix: types.StringNull(),
			LogIngestionKmsKeyArn:      types.StringNull(),
			Regions:                    types.ListNull(types.StringType),
		},
		IDP:              &fcs.IDPOptions{Enabled: types.BoolValue(false), Status: types.StringValue("configured")},
		SensorManagement: &fcs.SensorManagementOptions{Enabled: types.BoolValue(false)},
		DSPM:             &fcs.DSPMOptions{Enabled: types.BoolValue(dspmEnabled), RoleName: types.StringValue(roleName)},
		VulnerabilityScanning: &fcs.VulnerabilityScanningOptions{
			Enabled:  types.BoolValue(false),
			RoleName: types.StringValue(roleName),
		},
		ExternalID:                       types.StringValue("external-id"),
		IntermediateRoleArn:              types.StringValue("arn:aws:iam::111111111111:role/intermediate"),
		IamRoleArn:                       types.StringValue("arn:aws:iam::123456789012:role/reader"),
		IamRoleName:                      types.StringValue("reader"),
		EventbusName:                     types.StringValue("eventbus"),
		EventbusArn:                      types.StringValue("arn:aws:events:us-east-1:111111111111:event-bus/eventbus"),
		CloudTrailBucketName:             types.StringValue("bucket"),
		DspmRoleArn:                      types.StringValue("arn:aws:iam::123456789012:role/" + roleName),
		DspmRoleName:                     types.StringValue(roleName),
		VulnerabilityScanningRoleArn:     types.StringValue("arn:aws:iam::123456789012:role/" + roleName),
		VulnerabilityScanningRoleName:    types.StringValue(roleName),
		AgentlessScanningRoleName:        types.StringValue(roleName),
		AgentlessScanningScannerRoleName: types.StringValue(""),
		AgentlessUseResourceAffixes:      types.BoolValue(useAffixes),
	}
}

// awsAccountConfigModel returns a configuration with only account_id, and DSPM when dspm is set.
func awsAccountConfigModel(dspm *fcs.DSPMOptions) fcs.CloudAWSAccountModel {
	return fcs.CloudAWSAccountModel{
		AccountID:                        types.StringValue("123456789012"),
		OrganizationID:                   types.StringNull(),
		TargetOUs:                        types.ListNull(types.StringType),
		IsOrgManagementAccount:           types.BoolNull(),
		AccountType:                      types.StringNull(),
		DeploymentMethod:                 types.StringNull(),
		ResourceNamePrefix:               types.StringNull(),
		ResourceNameSuffix:               types.StringNull(),
		DSPM:                             dspm,
		ExternalID:                       types.StringNull(),
		IntermediateRoleArn:              types.StringNull(),
		IamRoleArn:                       types.StringNull(),
		IamRoleName:                      types.StringNull(),
		EventbusName:                     types.StringNull(),
		EventbusArn:                      types.StringNull(),
		CloudTrailBucketName:             types.StringNull(),
		DspmRoleArn:                      types.StringNull(),
		DspmRoleName:                     types.StringNull(),
		VulnerabilityScanningRoleArn:     types.StringNull(),
		VulnerabilityScanningRoleName:    types.StringNull(),
		AgentlessScanningRoleName:        types.StringNull(),
		AgentlessScanningScannerRoleName: types.StringNull(),
		AgentlessUseResourceAffixes:      types.BoolNull(),
	}
}

// planAWSAccount runs PlanResourceChange through the provider server and returns the planned model.
// proposed is what Terraform proposes: the config, with the prior state for unset computed values.
func planAWSAccount(t *testing.T, prior, config, proposed fcs.CloudAWSAccountModel) fcs.CloudAWSAccountModel {
	t.Helper()
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	fcs.NewCloudAWSAccountResource().Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	require.False(t, schemaResp.Diagnostics.HasError(), "schema: %v", schemaResp.Diagnostics)
	sch := schemaResp.Schema
	tfType := sch.Type().TerraformType(ctx)

	toDynamic := func(m fcs.CloudAWSAccountModel) *tfprotov6.DynamicValue {
		state := tfsdk.State{Schema: sch, Raw: tftypes.NewValue(tfType, nil)}
		diags := state.Set(ctx, &m)
		require.False(t, diags.HasError(), "set: %v", diags)
		dv, err := tfprotov6.NewDynamicValue(tfType, state.Raw)
		require.NoError(t, err)
		return &dv
	}

	server, err := providerserver.NewProtocol6WithError(provider.New("test")())()
	require.NoError(t, err)

	resp, err := server.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
		TypeName:         "crowdstrike_cloud_aws_account",
		PriorState:       toDynamic(prior),
		Config:           toDynamic(config),
		ProposedNewState: toDynamic(proposed),
	})
	require.NoError(t, err)
	for _, d := range resp.Diagnostics {
		require.NotEqual(t, tfprotov6.DiagnosticSeverityError, d.Severity, "plan: %s: %s", d.Summary, d.Detail)
	}

	planned, err := resp.PlannedState.Unmarshal(tfType)
	require.NoError(t, err)
	var model fcs.CloudAWSAccountModel
	diags := tfsdk.Plan{Schema: sch, Raw: planned}.Get(ctx, &model)
	require.False(t, diags.HasError(), "get: %v", diags)
	return model
}

func TestCloudAWSAccountPlan_AgentlessRoles(t *testing.T) {
	t.Run("absent dspm block keeps the stored legacy role", func(t *testing.T) {
		prior := awsAccountStateModel(false, legacyAgentlessRole, false)
		planned := planAWSAccount(t, prior, awsAccountConfigModel(nil), prior)

		assert.Equal(t, types.StringValue(legacyAgentlessRole), planned.DSPM.RoleName)
		assert.Equal(t, types.StringValue(legacyAgentlessRole), planned.VulnerabilityScanning.RoleName)
		assert.Equal(t, prior.DspmRoleName, planned.DspmRoleName)
		assert.Equal(t, prior.AgentlessScanningRoleName, planned.AgentlessScanningRoleName)
		assert.Equal(t, prior.AgentlessScanningScannerRoleName, planned.AgentlessScanningScannerRoleName)
		assert.Equal(t, prior.AgentlessUseResourceAffixes, planned.AgentlessUseResourceAffixes)
	})

	t.Run("unset role_name keeps the stored generated role", func(t *testing.T) {
		const generated = "CSAgentlessIntegrationRole-abcd1234"
		prior := awsAccountStateModel(true, generated, true)
		prior.AgentlessScanningScannerRoleName = types.StringValue("CSAgentlessScannerRole-abcd1234")
		config := awsAccountConfigModel(&fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: types.StringNull()})
		planned := planAWSAccount(t, prior, config, prior)

		assert.Equal(t, types.StringValue(generated), planned.DSPM.RoleName)
		assert.Equal(t, prior.DspmRoleArn, planned.DspmRoleArn)
		assert.Equal(t, prior.AgentlessScanningRoleName, planned.AgentlessScanningRoleName)
		assert.Equal(t, prior.AgentlessScanningScannerRoleName, planned.AgentlessScanningScannerRoleName)
		assert.Equal(t, types.BoolValue(true), planned.AgentlessUseResourceAffixes)
	})

	t.Run("enabling dspm without role_name leaves the roles to CrowdStrike", func(t *testing.T) {
		prior := awsAccountStateModel(false, legacyAgentlessRole, false)
		config := awsAccountConfigModel(&fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: types.StringNull()})
		proposed := prior
		proposed.DSPM = &fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: prior.DSPM.RoleName}
		planned := planAWSAccount(t, prior, config, proposed)

		assert.True(t, planned.DSPM.RoleName.IsUnknown())
		assert.True(t, planned.DspmRoleName.IsUnknown())
		assert.True(t, planned.AgentlessScanningRoleName.IsUnknown())
		assert.True(t, planned.AgentlessScanningScannerRoleName.IsUnknown())
		assert.True(t, planned.AgentlessUseResourceAffixes.IsUnknown())
	})

	t.Run("enabling dspm with role_name plans it", func(t *testing.T) {
		prior := awsAccountStateModel(false, legacyAgentlessRole, false)
		config := awsAccountConfigModel(&fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: types.StringValue("custom-role")})
		proposed := prior
		proposed.DSPM = &fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: types.StringValue("custom-role")}
		planned := planAWSAccount(t, prior, config, proposed)

		assert.Equal(t, types.StringValue("custom-role"), planned.DSPM.RoleName)
		assert.True(t, planned.DspmRoleName.IsUnknown())
		assert.True(t, planned.AgentlessScanningScannerRoleName.IsUnknown())
	})

	t.Run("create leaves unset roles unknown", func(t *testing.T) {
		config := awsAccountConfigModel(&fcs.DSPMOptions{Enabled: types.BoolValue(true), RoleName: types.StringNull()})
		ctx := context.Background()
		var schemaResp resource.SchemaResponse
		fcs.NewCloudAWSAccountResource().Schema(ctx, resource.SchemaRequest{}, &schemaResp)
		tfType := schemaResp.Schema.Type().TerraformType(ctx)

		server, err := providerserver.NewProtocol6WithError(provider.New("test")())()
		require.NoError(t, err)
		state := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(tfType, nil)}
		require.False(t, state.Set(ctx, &config).HasError())
		configValue, err := tfprotov6.NewDynamicValue(tfType, state.Raw)
		require.NoError(t, err)
		nullValue, err := tfprotov6.NewDynamicValue(tfType, tftypes.NewValue(tfType, nil))
		require.NoError(t, err)

		resp, err := server.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
			TypeName:         "crowdstrike_cloud_aws_account",
			PriorState:       &nullValue,
			Config:           &configValue,
			ProposedNewState: &configValue,
		})
		require.NoError(t, err)
		require.Empty(t, resp.Diagnostics)

		planned, err := resp.PlannedState.Unmarshal(tfType)
		require.NoError(t, err)
		var model fcs.CloudAWSAccountModel
		require.False(t, tfsdk.Plan{Schema: schemaResp.Schema, Raw: planned}.Get(ctx, &model).HasError())

		assert.True(t, model.DSPM.RoleName.IsUnknown())
		// The vulnerability_scanning default no longer carries the legacy role
		assert.True(t, model.VulnerabilityScanning.RoleName.IsUnknown())
		assert.True(t, model.AgentlessUseResourceAffixes.IsUnknown())
	})
}
