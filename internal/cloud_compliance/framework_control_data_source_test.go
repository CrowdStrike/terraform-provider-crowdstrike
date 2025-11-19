package cloudcompliance_test

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCloudComplianceFrameworkControlDataSource(t *testing.T) {
	var steps []resource.TestStep
	controlName := `Ensure CloudFront to Origin connection is configured using TLS1.1+ as the SSL\\TLS protocol`
	controlNameResponse := "Ensure CloudFront to Origin connection is configured using TLS1.1+ as the SSL\\TLS protocol"
	section := "Data Protection"
	benchmark := "CIS 1.0.0 AWS Web Architecture"
	paginationBenchmark := "CIS 1.*"
	requirement := "1.17"
	resourcePrefix := "data.crowdstrike_cloud_compliance_framework_controls."
	baseTests := []resource.TestStep{
		{
			Config: testDatasourceByFqlConfig(
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
				resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.benchmark.0", benchmark),
				resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.name", controlNameResponse),
				resource.TestCheckResourceAttr(resourcePrefix+"by_fql", "controls.0.requirement", requirement),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.section"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.id"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.authority"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_fql", "controls.0.code"),
			),
		},
		{
			Config: testDatasourceByNameConfig(controlName, benchmark, "by_name"),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.benchmark.0", benchmark),
				resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.name", controlNameResponse),
				resource.TestCheckResourceAttr(resourcePrefix+"by_name", "controls.0.requirement", requirement),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.section"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.id"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.authority"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_name", "controls.0.code"),
			),
		},
		{
			Config: testDatasourceByRequirementConfig(requirement, benchmark, "by_requirement"),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.benchmark.0", benchmark),
				resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.name", controlNameResponse),
				resource.TestCheckResourceAttr(resourcePrefix+"by_requirement", "controls.0.requirement", requirement),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.section"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.id"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.authority"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_requirement", "controls.0.code"),
			),
		},
		{
			Config: testDatasourceBySectionConfig(requirement, benchmark, section, "by_section"),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourcePrefix+"by_section", "controls.0.benchmark.0", benchmark),
				resource.TestCheckResourceAttr(resourcePrefix+"by_section", "controls.0.name", controlNameResponse),
				resource.TestCheckResourceAttr(resourcePrefix+"by_section", "controls.0.requirement", requirement),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_section", "controls.0.section"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_section", "controls.0.id"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_section", "controls.0.authority"),
				resource.TestCheckResourceAttrSet(resourcePrefix+"by_section", "controls.0.code"),
			),
		},
		{
			Config: testDatasourcePaginationConfig(paginationBenchmark, "pagination"),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrWith(resourcePrefix+"pagination", "controls.#", func(value string) error {
					count, err := strconv.Atoi(value)
					if err != nil {
						return fmt.Errorf("failed to parse controls count: %v", err)
					}
					if count <= 1000 {
						return fmt.Errorf("expected controls count to be greater than 1000, got %d", count)
					}
					return nil
				}),
			),
		},
	}

	steps = append(steps, testDatasourceConfigConflicts()...)
	steps = append(steps, baseTests...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

func testDatasourceByFqlConfig(fql, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  fql = "%s"
}
`, resourceName, fql)
}

func testDatasourceByNameConfig(name, benchmark, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  control_name = "%s"
  benchmark    = "%s"
}
`, resourceName, name, benchmark)
}

func testDatasourceByRequirementConfig(requirement, benchmark, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  requirement = "%s"
  benchmark   = "%s"
}
`, resourceName, requirement, benchmark)
}

func testDatasourceBySectionConfig(requirement, benchmark, section, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  requirement = "%s"
  benchmark   = "%s"
  section     = "%s"
}
`, resourceName, requirement, benchmark, section)
}

func testDatasourcePaginationConfig(benchmark, resourceName string) string {
	return fmt.Sprintf(`
data "crowdstrike_cloud_compliance_framework_controls" "%s" {
  benchmark = "%s"
}
`, resourceName, benchmark)
}

func testDatasourceConfigConflicts() []resource.TestStep {
	return []resource.TestStep{
		{
			Config: `
data "crowdstrike_cloud_compliance_framework_controls" "test" {
	fql = "test"
	control_name = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_compliance_framework_controls" "test" {
	fql       = "test"
	benchmark = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_compliance_framework_controls" "test" {
	fql         = "test"
	requirement = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
		{
			Config: `
data "crowdstrike_cloud_compliance_framework_controls" "test" {
	fql     = "test"
	section = "test"
}
			`,
			ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
		},
	}
}
