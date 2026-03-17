package dataprotection

import "github.com/crowdstrike/gofalcon/falcon/models"

type (
	DataProtectionSensitivityLabelResourceModel = dataProtectionSensitivityLabelResourceModel
)

var BuildSensitivityLabelCreateRequest = buildSensitivityLabelCreateRequest

func (m *dataProtectionSensitivityLabelResourceModel) Wrap(
	label models.APISensitivityLabelV2,
) {
	m.wrap(label)
}
