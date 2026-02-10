package ioarulegroup_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccIOARuleGroupResourceLinux(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupLinuxConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Linux"),
					resource.TestCheckResourceAttr(resourceName, "description", "Test IOA rule group for Linux"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Created by acceptance test"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_on"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_on"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "2"),
				),
			},
			{
				Config: testAccIOARuleGroupLinuxConfigUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "3"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccIOARuleGroupResourceWindows(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupWindowsConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Windows"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "2"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccIOARuleGroupResourceMac(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupMacConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Mac"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccIOARuleGroupResourceAllRuleTypes(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ioa_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupAllRuleTypesConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform", "Linux"),
					resource.TestCheckResourceAttr(resourceName, "rules.#", "4"),
				),
			},
		},
	})
}

func testAccIOARuleGroupLinuxConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Test IOA rule group for Linux"
  comment     = "Created by acceptance test"
  enabled     = false

  rules = [
    {
      name             = "Process Creation Rule"
      description      = "Monitors suspicious process creation"
      comment          = "Test rule 1"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      parent_image_filename = {
        include = ".*/bin/bash"
      }

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "Network Connection Rule"
      description      = "Monitors suspicious network connections"
      comment          = "Test rule 2"
      pattern_severity = "critical"
      type             = "Network Connection"
      action           = "Detect"
      enabled          = false

      image_filename = {
        include = ".*python.*"
      }

      remote_ip_address = {
        include = ".*"
      }

      connection_type = ["TCP", "UDP"]
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupLinuxConfigUpdate(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%[1]s-updated"
  platform    = "Linux"
  description = "Updated description"
  comment     = "Updated by acceptance test"
  enabled     = true

  rules = [
    {
      name             = "Process Creation Rule"
      description      = "Monitors suspicious process creation - updated"
      comment          = "Test rule 1 updated"
      pattern_severity = "critical"
      type             = "Process Creation"
      action           = "Kill Process"
      enabled          = true

      parent_image_filename = {
        include = ".*/bin/.*"
      }

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*malicious.*"
      }
    },
    {
      name             = "Network Connection Rule"
      description      = "Monitors suspicious network connections"
      comment          = "Test rule 2"
      pattern_severity = "critical"
      type             = "Network Connection"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*python.*"
      }

      remote_ip_address = {
        include = ".*"
      }

      connection_type = ["TCP"]
    },
    {
      name             = "File Creation Rule"
      description      = "Monitors suspicious file creation"
      comment          = "New rule"
      pattern_severity = "medium"
      type             = "File Creation"
      action           = "Monitor"
      enabled          = false

      file_path = {
        include = ".*/tmp/.*\\.sh"
      }

      image_filename = {
        include = ".*"
      }

      file_type = ["SCRIPT", "PE"]
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupWindowsConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Windows"
  description = "Test IOA rule group for Windows"
  comment     = "Created by acceptance test"
  enabled     = false

  rules = [
    {
      name             = "Process Creation Rule"
      description      = "Monitors suspicious process creation on Windows"
      comment          = "Windows test rule"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      parent_image_filename = {
        include = ".*\\\\cmd\\.exe"
      }

      image_filename = {
        include = ".*\\\\powershell\\.exe"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "File Creation Rule"
      description      = "Monitors suspicious file creation on Windows"
      comment          = "Windows file rule"
      pattern_severity = "medium"
      type             = "File Creation"
      action           = "Detect"
      enabled          = true

      file_path = {
        include = ".*\\\\Temp\\\\.*"
      }

      image_filename = {
        include = ".*"
      }

      file_type = ["PE", "SCRIPT"]
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupMacConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Mac"
  description = "Test IOA rule group for Mac"
  comment     = "Created by acceptance test"
  enabled     = false

  rules = [
    {
      name             = "Process Creation Rule"
      description      = "Monitors suspicious process creation on Mac"
      comment          = "Mac test rule"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      parent_image_filename = {
        include = ".*/bin/bash"
      }

      image_filename = {
        include = ".*/usr/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupAllRuleTypesConfig(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Test all rule types"
  comment     = "All rule types test"
  enabled     = true

  rules = [
    {
      name             = "Process Creation Rule"
      description      = "Process creation monitoring"
      comment          = "Process rule"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "File Creation Rule"
      description      = "File creation monitoring"
      comment          = "File rule"
      pattern_severity = "medium"
      type             = "File Creation"
      action           = "Detect"
      enabled          = true

      file_path = {
        include = ".*/tmp/.*"
      }

      image_filename = {
        include = ".*"
      }

      file_type = ["SCRIPT"]
    },
    {
      name             = "Network Connection Rule"
      description      = "Network connection monitoring"
      comment          = "Network rule"
      pattern_severity = "critical"
      type             = "Network Connection"
      action           = "Kill Process"
      enabled          = true

      image_filename = {
        include = ".*"
      }

      remote_ip_address = {
        include = ".*"
      }

      connection_type = ["TCP", "UDP", "ICMP"]
    },
    {
      name             = "Domain Name Rule"
      description      = "Domain name monitoring"
      comment          = "Domain rule"
      pattern_severity = "high"
      type             = "Domain Name"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious.*"
        exclude = ".*legitimate.*"
      }
    }
  ]
}
`, rName)
}
