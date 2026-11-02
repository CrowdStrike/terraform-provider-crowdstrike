package sensorupdatepolicy

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/stretchr/testify/assert"
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
