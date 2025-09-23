package cloudcompliance_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCloudComplianceFrameworkControlDataSource(t *testing.T) {

	controlName := "Ensure CloudFront to Origin connection is configured using TLS1.1+ as the SSL\\\\TLS protocol"
	controlNameResponse := "Ensure CloudFront to Origin connection is configured using TLS1.1+ as the SSL\\TLS protocol"
	benchmark := "CIS 1.0.0 AWS Web Architecture"
	requirement := "1.17"
	resourcePrefix := "data.crowdstrike_cloud_compliance_framework_controls."

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testByFqlConfig(
					fmt.Sprintf(
						"compliance_control_name:'%s'+"+
							"compliance_control_requirement:'%s'+"+
							"compliance_control_benchmark_name:'%s'",
						controlName,
						requirement,
						benchmark,
					),
					"by_fql",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.benchmark", benchmark),
					resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.name", controlNameResponse),
					resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.requirement", requirement),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.section"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.uuid"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.authority"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.code"),
				),
			},
			{
				Config: testByNameConfig(controlName, benchmark, "by_name"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.benchmark", benchmark),
					resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.name", controlNameResponse),
					resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.requirement", requirement),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.section"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.uuid"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.authority"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.code"),
				),
			},
			{
				Config: testByRequirementConfig(requirement, benchmark, "by_requirement"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.benchmark", benchmark),
					resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.name", controlNameResponse),
					resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.requirement", requirement),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.section"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.uuid"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.authority"),
					resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.code"),
				),
			},
		},
	})
}

func testByFqlConfig(fql string, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  fql = "%s"
}
`, resourceName, fql)
}

func testByNameConfig(name string, benchmark string, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  name = "%s"
  benchmark = "%s"
}
`, resourceName, name, benchmark)
}

func testByRequirementConfig(requirement string, benchmark string, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  requirement = "%s"
  benchmark = "%s"
}
`, resourceName, requirement, benchmark)
}
