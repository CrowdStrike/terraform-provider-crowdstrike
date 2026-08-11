package dataprotection

import (
	"context"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
)

type (
	DataProtectionSensitivityLabelResourceModel = dataProtectionSensitivityLabelResourceModel
)

var BuildSensitivityLabelCreateRequest = buildSensitivityLabelCreateRequest

func (m *dataProtectionSensitivityLabelResourceModel) Wrap(
	label models.APISensitivityLabelV2,
) {
	m.wrap(label)
}

// Data protection policy.

type (
	DataProtectionPolicyResourceModel = dataProtectionPolicyResourceModel

	EujOptionOverride          = eujOptionOverride
	EujDropdownOptionsOverride = eujDropdownOptionsOverride
)

const (
	PlatformWindows = platformWindows
	PlatformMac     = platformMac
	APIPlatformWin  = apiPlatformWin
	APIPlatformMac  = apiPlatformMac

	MaxFileSizeMaxBytes     = maxFileSizeMaxBytes
	MaxFileSizeDefaultBytes = maxFileSizeDefaultBytes
	MaxFileSizeUnitBytes    = maxFileSizeUnitBytes
	MaxFileSizeUnitKB       = maxFileSizeUnitKB
	MaxFileSizeUnitMB       = maxFileSizeUnitMB

	MessageSourceDefault = messageSourceDefault
	MessageSourceCustom  = messageSourceCustom

	EujMandatoryBusinessPurposes = eujMandatoryBusinessPurposes
	EujMandatoryPersonalUse      = eujMandatoryPersonalUse
)

var (
	PlatformScopedSettings = platformScopedSettings
	PlatformNameToAPI      = platformNameToAPI
	PlatformNameFromAPI    = platformNameFromAPI

	WirePlatformName   = wirePlatformName
	SchemaPlatformName = schemaPlatformName

	ExpandPolicyProperties    = expandPolicyProperties
	MessageSource             = messageSource
	FlattenCustomMessage      = flattenCustomMessage
	ExpandExcludeDomains      = expandExcludeDomains
	FlattenExcludeDomains     = flattenExcludeDomains
	ExpandEujHeaderText       = expandEujHeaderText
	BuiltinHeaderText         = builtinHeaderText
	FlattenEujHeaderText      = flattenEujHeaderText
	ExpandEujDropdownOptions  = expandEujDropdownOptions
	FlattenEujDropdownOptions = flattenEujDropdownOptions

	ValidateMaxFileSizeBytes       = validateMaxFileSizeBytes
	ValidateEujEnabledOptions      = validateEujEnabledOptions
	ValidatePlatformScopedSettings = validatePlatformScopedSettings
)

// Name reports the attribute name a platform-scoped setting covers.
func (s platformScopedSetting) Name() string { return s.name }

// Platform reports the one platform that accepts the setting.
func (s platformScopedSetting) Platform() string { return s.platform }

// Value reports the default the setting carries on its own platform.
func (s platformScopedSetting) Value() attr.Value { return s.value }

// Null reports the typed null the setting takes on the other platform.
func (s platformScopedSetting) Null() attr.Value { return s.null }

// Get reads the setting's value out of a model.
func (s platformScopedSetting) Get(m DataProtectionPolicyResourceModel) attr.Value {
	return s.get(m)
}

// NewPolicyWrite builds a policyWrite for tests in the external test package.
func NewPolicyWrite(
	plan dataProtectionPolicyResourceModel,
	builtinHeader string,
) policyWrite {
	return policyWrite{plan: plan, builtinHeader: builtinHeader}
}

const PolicyWriteAttempts = policyWriteAttempts

// RetryPolicyWrite exposes retryPolicyWrite to tests in the external test package.
func RetryPolicyWrite[T any](
	ctx context.Context,
	description string,
	write func() (T, error),
) (T, error) {
	return retryPolicyWrite(ctx, description, write)
}

// SetPolicyWriteBackoff replaces the pause between write retries and returns the
// previous value, so a unit test can drive the retry loop without sleeping.
func SetPolicyWriteBackoff(backoff time.Duration) time.Duration {
	previous := policyWriteBackoff
	policyWriteBackoff = backoff

	return previous
}
