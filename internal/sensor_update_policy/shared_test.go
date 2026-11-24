package sensorupdatepolicy

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripBuildPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "build number only",
			input: "17407",
			want:  "17407",
		},
		{
			name:  "full version string",
			input: "7.22.17407",
			want:  "17407",
		},
		{
			name:  "two part version",
			input: "22.17407",
			want:  "17407",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "pipe-delimited build tag",
			input: "20709|n|tagged|17",
			want:  "20709|n|tagged|17",
		},
		{
			name:  "pipe-delimited n-1 build tag",
			input: "20610|n-1|tagged|1",
			want:  "20610|n-1|tagged|1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stripBuildPrefix(tt.input); got != tt.want {
				t.Errorf("stripBuildPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestChangedBuildSettings(t *testing.T) {
	t.Parallel()

	arm64Variant := func(build string) []*models.SensorUpdateBuildReqV1 {
		return []*models.SensorUpdateBuildReqV1{{Build: utils.Addr(build), Platform: utils.Addr(linuxArm64Varient)}}
	}

	tests := []struct {
		name          string
		platform      string
		planned       policyBuilds
		current       policyBuilds
		want          *models.SensorUpdateSettingsReqV2
		wantOmitBuild bool
	}{
		{
			name:          "unchanged builds are not sent",
			planned:       policyBuilds{build: "18909", buildArm64: "18909"},
			current:       policyBuilds{build: "18909", buildArm64: "18909"},
			want:          &models.SensorUpdateSettingsReqV2{Build: "18909"},
			wantOmitBuild: true,
		},
		{
			name:          "full version string matching current build is unchanged",
			planned:       policyBuilds{build: "7.36.18909", buildArm64: "7.36.18909"},
			current:       policyBuilds{build: "18909", buildArm64: "18909"},
			want:          &models.SensorUpdateSettingsReqV2{Build: "18909"},
			wantOmitBuild: true,
		},
		{
			name:          "unchanged empty builds are not sent",
			want:          &models.SensorUpdateSettingsReqV2{},
			wantOmitBuild: true,
		},
		{
			name:    "changed build is sent without prefix",
			planned: policyBuilds{build: "7.40.19312", buildArm64: "18909"},
			current: policyBuilds{build: "18909", buildArm64: "18909"},
			want:    &models.SensorUpdateSettingsReqV2{Build: "19312"},
		},
		{
			name:    "build changed to empty is sent",
			current: policyBuilds{build: "18909"},
			want:    &models.SensorUpdateSettingsReqV2{},
		},
		{
			name:          "changed arm64 build is sent alone",
			platform:      "Linux",
			planned:       policyBuilds{build: "18909", buildArm64: "7.40.19312"},
			current:       policyBuilds{build: "18909", buildArm64: "18909"},
			want:          &models.SensorUpdateSettingsReqV2{Build: "18909", Variants: arm64Variant("19312")},
			wantOmitBuild: true,
		},
		{
			name:          "arm64 build changed to empty is sent",
			platform:      "linux",
			planned:       policyBuilds{build: "18909"},
			current:       policyBuilds{build: "18909", buildArm64: "18909"},
			want:          &models.SensorUpdateSettingsReqV2{Build: "18909", Variants: arm64Variant("")},
			wantOmitBuild: true,
		},
		{
			name:          "changed arm64 build is not sent for other platforms",
			platform:      "Windows",
			planned:       policyBuilds{build: "18909", buildArm64: "19312"},
			current:       policyBuilds{build: "18909", buildArm64: "18909"},
			want:          &models.SensorUpdateSettingsReqV2{Build: "18909"},
			wantOmitBuild: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			settings, opts := changedBuildSettings(buildChange{
				platform: tt.platform,
				planned:  tt.planned,
				current:  tt.current,
			})

			assert.Equal(t, tt.want, settings)
			assert.Equal(t, tt.wantOmitBuild, len(opts) == 1, "omit build")
		})
	}
}

func TestBuildToFramework(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		current  types.String
		apiBuild string
		want     types.String
	}{
		{
			name:     "full version string for the same build is kept",
			current:  types.StringValue("7.22.17407"),
			apiBuild: "17407",
			want:     types.StringValue("7.22.17407"),
		},
		{
			name:     "build number is kept",
			current:  types.StringValue("17407"),
			apiBuild: "17407",
			want:     types.StringValue("17407"),
		},
		{
			name:     "pipe-delimited build tag is kept",
			current:  types.StringValue("17407|n-1|tagged"),
			apiBuild: "17407|n-1|tagged",
			want:     types.StringValue("17407|n-1|tagged"),
		},
		{
			name:     "empty build is kept",
			current:  types.StringValue(""),
			apiBuild: "",
			want:     types.StringValue(""),
		},
		{
			name:     "different build uses api value",
			current:  types.StringValue("7.22.17407"),
			apiBuild: "18909",
			want:     types.StringValue("18909"),
		},
		{
			name:     "null uses api value",
			current:  types.StringNull(),
			apiBuild: "17407",
			want:     types.StringValue("17407"),
		},
		{
			name:     "unknown uses api value",
			current:  types.StringUnknown(),
			apiBuild: "17407",
			want:     types.StringValue("17407"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, buildToFramework(tt.current, tt.apiBuild))
		})
	}
}

func linuxPolicyWithBuilds(build, arm64Build string) models.SensorUpdatePolicyV2 {
	return models.SensorUpdatePolicyV2{
		ID:           utils.Addr("policy-1"),
		Name:         utils.Addr("test"),
		Description:  utils.Addr("test"),
		Enabled:      utils.Addr(true),
		PlatformName: utils.Addr("Linux"),
		Settings: &models.SensorUpdateSettingsRespV2{
			Build:               utils.Addr(build),
			UninstallProtection: utils.Addr("DISABLED"),
			Variants: []*models.SensorUpdateBuildRespV1{
				{Build: utils.Addr(arm64Build), Platform: utils.Addr(linuxArm64Varient)},
			},
		},
	}
}

// Configured full version strings must stay in state after apply, or Terraform
// reports an inconsistent result. Regression test for
// https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues/534
func TestWrapKeepsConfiguredFullVersionBuilds(t *testing.T) {
	t.Parallel()

	policy := linuxPolicyWithBuilds("17407", "17410")

	t.Run("sensor_update_policy", func(t *testing.T) {
		t.Parallel()

		model := sensorUpdatePolicyResourceModel{
			Build:        types.StringValue("7.22.17407"),
			BuildArm64:   types.StringValue("7.22.17410"),
			PlatformName: types.StringValue("Linux"),
		}

		diags := model.wrap(t.Context(), policy, true, false)
		require.False(t, diags.HasError(), "%v", diags.Errors())
		assert.Equal(t, types.StringValue("7.22.17407"), model.Build)
		assert.Equal(t, types.StringValue("7.22.17410"), model.BuildArm64)
	})

	t.Run("default_sensor_update_policy", func(t *testing.T) {
		t.Parallel()

		model := defaultSensorUpdatePolicyResourceModel{
			Build:        types.StringValue("7.22.17407"),
			BuildArm64:   types.StringValue("7.22.17410"),
			PlatformName: types.StringValue("Linux"),
		}

		diags := model.wrap(t.Context(), policy, true)
		require.False(t, diags.HasError(), "%v", diags.Errors())
		assert.Equal(t, types.StringValue("7.22.17407"), model.Build)
		assert.Equal(t, types.StringValue("7.22.17410"), model.BuildArm64)
	})
}

// Read refreshes state with the build the API returns when it no longer
// matches the configured value.
func TestWrapReplacesChangedBuilds(t *testing.T) {
	t.Parallel()

	policy := linuxPolicyWithBuilds("18909", "18910")

	model := sensorUpdatePolicyResourceModel{
		Build:        types.StringValue("7.22.17407"),
		BuildArm64:   types.StringValue("7.22.17410"),
		PlatformName: types.StringValue("Linux"),
	}

	diags := model.wrap(t.Context(), policy, false, false)
	require.False(t, diags.HasError(), "%v", diags.Errors())
	assert.Equal(t, types.StringValue("18909"), model.Build)
	assert.Equal(t, types.StringValue("18910"), model.BuildArm64)
}

func TestNewSensorBuild(t *testing.T) {
	t.Parallel()

	got := newSensorBuild(&models.SensorUpdateBuildRespV1{
		Build:         utils.Addr("17407|n|tagged|1"),
		Platform:      utils.Addr("Linux"),
		SensorVersion: utils.Addr("7.22.17407"),
		Stage:         utils.Addr("prod"),
	})

	assert.Equal(t, sensorBuild{
		Build:         types.StringValue("17407|n|tagged|1"),
		Platform:      types.StringValue("Linux"),
		SensorVersion: types.StringValue("7.22.17407"),
		Stage:         types.StringValue("prod"),
	}, got)
}
