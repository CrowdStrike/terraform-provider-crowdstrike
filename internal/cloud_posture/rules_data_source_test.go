package cloudposture_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type dataRuleConfig struct {
	cloudProvider string
	ruleName      string
	resourceType  string
	benchmark     string
	framework     string
	service       string
}

var awsConfig = dataRuleConfig{
	cloudProvider: "AWS",
	ruleName:      "NLB/ALB configured publicly with TLS/SSL disabled",
	resourceType:  "AWS::ElasticLoadBalancingV2::LoadBalancer",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "ELB",
}

var azureConfig = dataRuleConfig{
	cloudProvider: "Azure",
	ruleName:      "Virtual Machine allows public internet access to Docker (port 2375/2376)",
	resourceType:  "Microsoft.Compute/virtualMachines",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Virtual Machines",
}

var gcpConfig = dataRuleConfig{
	cloudProvider: "GCP",
	ruleName:      "GKE Cluster insecure kubelet read only port is enabled",
	resourceType:  "container.googleapis.com/Cluster",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Google Kubernetes Engine",
}

func TestCloudPostureRulesDataSource(t *testing.T) {
	var steps []resource.TestStep

	steps = append(steps, testCloudRules(awsConfig)...)
	steps = append(steps, testCloudRules(azureConfig)...)
	steps = append(steps, testCloudRules(gcpConfig)...)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}

func testCloudRules(config dataRuleConfig) (steps []resource.TestStep) {
	resourceName := fmt.Sprintf("data.crowdstrike_cloud_posture_rules.%s", config.cloudProvider)
	steps = []resource.TestStep{
		{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_posture_rules" "%[1]s" {
  cloud_provider = "%[1]s"
  resource_type  = "%[2]s"
}
`, config.cloudProvider, config.resourceType),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(resourceName, "rules.#"),
				resource.TestMatchResourceAttr(resourceName, "rules.#", regexp.MustCompile(`^[2-9]|\d{2,}$`)),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					UUIDs := []string{}
					for i := 0; ; i++ {
						key := fmt.Sprintf("rules.%d.id", i)
						if v, ok := rs.Primary.Attributes[key]; ok {
							UUIDs = append(UUIDs, v)
						} else {
							break
						}
					}
					for i, uuid := range UUIDs {
						if v, ok := rs.Primary.Attributes[fmt.Sprintf("rules.%d.id", i)]; !ok || v != uuid {
							return fmt.Errorf("Expected Id %s for rule %d, got %s", uuid, i, v)
						}
					}
					return nil
				},
			),
		},
		{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_posture_rules" "%[1]s" {
  cloud_provider = "%[1]s"
  rule_name = "%[2]s"
}
`, config.cloudProvider, config.ruleName),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					if v, ok := rs.Primary.Attributes["rules.0.id"]; !ok || v == "" {
						return fmt.Errorf("Id not set for rule")
					}
					return nil
				},
			),
		},
		{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_posture_rules" "%[1]s" {
  cloud_provider = "%[1]s"
  rule_name = "%[2]s"
  benchmark = "%[3]s"
  framework = "%[4]s"
  service = "%[5]s"
}
`, config.cloudProvider, config.ruleName, config.benchmark, config.framework, config.service),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					if v, ok := rs.Primary.Attributes["rules.0.id"]; !ok || v == "" {
						return fmt.Errorf("Id not set for rule")
					}
					return nil
				},
			),
		},
		{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_posture_rules" "%s" {
  fql = "rule_name:'%s'"
}
`, config.cloudProvider, config.ruleName),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.id"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.remediation_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.alert_info.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.severity"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.domain"),
				resource.TestCheckResourceAttr(resourceName, "rules.0.name", config.ruleName),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.controls.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.cloud_provider"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.attack_types.#"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.resource_type"),
				resource.TestCheckResourceAttrSet(resourceName, "rules.0.subdomain"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return fmt.Errorf("Not found: %s", resourceName)
					}
					if v, ok := rs.Primary.Attributes["rules.0.id"]; !ok || v == "" {
						return fmt.Errorf("Id not set for rule")
					}
					return nil
				},
			),
		},
	}

	return steps
}
