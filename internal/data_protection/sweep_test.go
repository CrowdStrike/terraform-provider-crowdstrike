package dataprotection

import (
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
)

func TestTryDeleteDataProtectionPolicyAcrossPlatforms_IgnoreThenSuccess(t *testing.T) {
	var calledPlatforms []string

	err := tryDeleteDataProtectionPolicyAcrossPlatforms("legacy-id", func(platform string) error {
		calledPlatforms = append(calledPlatforms, platform)

		if platform == "win" {
			return data_protection_configuration.NewEntitiesPolicyDeleteV2NotFound()
		}

		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(calledPlatforms) != 2 || calledPlatforms[0] != "win" || calledPlatforms[1] != "mac" {
		t.Fatalf("expected platforms [win mac], got %v", calledPlatforms)
	}
}

func TestTryDeleteDataProtectionPolicyAcrossPlatforms_AllIgnored(t *testing.T) {
	var calledPlatforms []string

	err := tryDeleteDataProtectionPolicyAcrossPlatforms("legacy-id", func(platform string) error {
		calledPlatforms = append(calledPlatforms, platform)
		return data_protection_configuration.NewEntitiesPolicyDeleteV2NotFound()
	})

	if err != nil {
		t.Fatalf("expected nil error when all delete errors are ignored, got %v", err)
	}
	if len(calledPlatforms) != 2 || calledPlatforms[0] != "win" || calledPlatforms[1] != "mac" {
		t.Fatalf("expected platforms [win mac], got %v", calledPlatforms)
	}
}

func TestTryDeleteDataProtectionPolicyAcrossPlatforms_NonIgnorableErrorReturned(t *testing.T) {
	expectedErr := errors.New("unexpected delete failure")

	err := tryDeleteDataProtectionPolicyAcrossPlatforms("legacy-id", func(platform string) error {
		if platform == "win" {
			return data_protection_configuration.NewEntitiesPolicyDeleteV2NotFound()
		}

		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}

func TestTryDeleteDataProtectionPolicyAcrossPlatforms_ContinueAfterNonIgnorableOnFirstPlatform(t *testing.T) {
	var calledPlatforms []string

	err := tryDeleteDataProtectionPolicyAcrossPlatforms("legacy-id", func(platform string) error {
		calledPlatforms = append(calledPlatforms, platform)

		if platform == "win" {
			return errors.New("transient win platform failure")
		}

		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error when second platform succeeds, got %v", err)
	}
	if len(calledPlatforms) != 2 || calledPlatforms[0] != "win" || calledPlatforms[1] != "mac" {
		t.Fatalf("expected platforms [win mac], got %v", calledPlatforms)
	}
}
