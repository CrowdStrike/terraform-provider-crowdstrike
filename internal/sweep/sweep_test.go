package sweep_test

import (
	"testing"

	cloudcompliance "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_compliance"
	cloudgoogleregistration "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_google_registration"
	cloudgroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_group"
	cloudsecurity "github.com/crowdstrike/terraform-provider-crowdstrike/internal/cloud_security"
	containerregistry "github.com/crowdstrike/terraform-provider-crowdstrike/internal/container_registry"
	contentupdatepolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/content_update_policy"
	correlation_rules "github.com/crowdstrike/terraform-provider-crowdstrike/internal/correlation_rules"
	customioc "github.com/crowdstrike/terraform-provider-crowdstrike/internal/custom_ioc"
	dataprotection "github.com/crowdstrike/terraform-provider-crowdstrike/internal/data_protection"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fcs"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/firewall"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	installtoken "github.com/crowdstrike/terraform-provider-crowdstrike/internal/install_token"
	ioaexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioa_exclusion"
	ioarulegroup "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioa_rule_group"
	itautomation "github.com/crowdstrike/terraform-provider-crowdstrike/internal/it_automation"
	mlcertificateexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ml_certificate_exclusion"
	mlfilepathexclusion "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ml_file_path_exclusion"
	preventionpolicy "github.com/crowdstrike/terraform-provider-crowdstrike/internal/prevention_policy"
	rtrputfile "github.com/crowdstrike/terraform-provider-crowdstrike/internal/rtr_put_file"
	rtrscript "github.com/crowdstrike/terraform-provider-crowdstrike/internal/rtr_script"
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
	containerregistry.RegisterSweepers()
	contentupdatepolicy.RegisterSweepers()
	correlation_rules.RegisterSweepers()
	customioc.RegisterSweepers()
	dataprotection.RegisterSweepers()
	fcs.RegisterSweepers()
	fim.RegisterSweepers()
	firewall.RegisterSweepers()
	hostgroups.RegisterSweepers()
	installtoken.RegisterSweepers()
	ioaexclusion.RegisterSweepers()
	ioarulegroup.RegisterSweepers()
	itautomation.RegisterSweepers()
	mlcertificateexclusion.RegisterSweepers()
	mlfilepathexclusion.RegisterSweepers()
	preventionpolicy.RegisterSweepers()
	rtrputfile.RegisterSweepers()
	rtrscript.RegisterSweepers()
	sensorupdatepolicy.RegisterSweepers()
	sensorvisibilityexclusion.RegisterSweepers()
	usergroup.RegisterSweepers()
}
