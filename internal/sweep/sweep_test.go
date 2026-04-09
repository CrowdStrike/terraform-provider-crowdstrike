package sweep_test

import (
	"testing"

	cloudcompliance "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_compliance"
	cloudgoogleregistration "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_google_registration"
	cloudgroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_group"
	cloudsecurity "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_security"
	contentupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/content_update_policy"
	dataprotection "github.com/crowdstrike/terraform-provider-crowdstrike/internal/data_protection"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/firewall"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	installtoken "github.com/crowdstrike/terraform-provider-crowdstrike/internal/install_token"
	ioarulegroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioa_rule_group"
	itautomation "github.com/crowdstrike/terraform-provider-crowdstrike/internal/it_automation"
	preventionpolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/prevention_policy"
	sensorupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_update_policy"
	sensorvisibilityexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/sensor_visibility_exclusion"
	usergroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/user_group"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestMain(m *testing.M) {
	registerSweepers()
	resource.TestMain(m)
}

func registerSweepers() {
	cloudcompliance.RegisterSweepers()
	cloudgoogleregistration.RegisterSweepers()
	cloudgroup.RegisterSweepers()
	cloudsecurity.RegisterSweepers()
	contentupdatepolicy.RegisterSweepers()
	dataprotection.RegisterSweepers()
	fcs.RegisterSweepers()
	fim.RegisterSweepers()
	firewall.RegisterSweepers()
	hostgroups.RegisterSweepers()
	installtoken.RegisterSweepers()
	ioarulegroup.RegisterSweepers()
	itautomation.RegisterSweepers()
	preventionpolicy.RegisterSweepers()
	sensorupdatepolicy.RegisterSweepers()
	sensorvisibilityexclusion.RegisterSweepers()
	usergroup.RegisterSweepers()
}
