package ioarulegroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const resourceName = "crowdstrike_ioa_rule_group.test"

func TestAccIOARuleGroupResource_Basic(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Linux"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("deleted"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("committed_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIOARuleGroupResource_Update(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Linux"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("committed_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("deleted"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
			{
				Config: testAccIOARuleGroupConfigUpdate(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated rule group description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Detect Suspicious Process Updated"),
								"description":      knownvalue.StringExact("Updated process creation detection"),
								"pattern_severity": knownvalue.StringExact("critical"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Kill Process"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/opt/.*"),
									"exclude": knownvalue.StringExact(".*/opt/safe/.*"),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							1: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Monitor Bash Activity"),
								"description":      knownvalue.StringExact("Monitors bash process creation"),
								"pattern_severity": knownvalue.StringExact("medium"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Monitor"),
								"enabled":          knownvalue.Bool(true),
								"parent_image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/bin/bash"),
									"exclude": knownvalue.Null(),
								}),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/bin/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigUpdateRuleInPlace(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("Updated rule group description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Detect Suspicious Process Updated"),
								"description":      knownvalue.StringExact("Modified description for in-place update"),
								"pattern_severity": knownvalue.StringExact("medium"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Detect"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/opt/.*"),
									"exclude": knownvalue.StringExact(".*/opt/safe/.*"),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							1: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Monitor Bash Activity"),
								"description":      knownvalue.StringExact("Updated bash monitoring description"),
								"pattern_severity": knownvalue.StringExact("medium"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Monitor"),
								"enabled":          knownvalue.Bool(true),
								"parent_image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/bin/bash"),
									"exclude": knownvalue.Null(),
								}),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/bin/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Linux"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIOARuleGroupResource_ProcessCreation(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigProcessCreationFull(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Full Process Creation Rule"),
								"description":      knownvalue.StringExact("Tests all common fields for process creation"),
								"pattern_severity": knownvalue.StringExact("high"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Detect"),
								"enabled":          knownvalue.Bool(true),
								"grandparent_image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*explorer\\.exe"),
									"exclude": knownvalue.Null(),
								}),
								"grandparent_command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"parent_image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*cmd\\.exe"),
									"exclude": knownvalue.StringExact(".*system32.*"),
								}),
								"parent_command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*powershell\\.exe"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*-encodedcommand.*"),
									"exclude": knownvalue.StringExact(".*Get-Help.*"),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccIOARuleGroupResource_FileCreation(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigFileCreation(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Suspicious File Creation"),
								"description":      knownvalue.StringExact("Detects suspicious file creation"),
								"pattern_severity": knownvalue.StringExact("medium"),
								"type":             knownvalue.StringExact("File Creation"),
								"action":           knownvalue.StringExact("Detect"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*powershell\\.exe"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"file_path": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*\\\\Windows\\\\Temp\\\\.*"),
									"exclude": knownvalue.StringExact(".*\\.log"),
								}),
								"file_type": knownvalue.SetExact([]knownvalue.Check{
									knownvalue.StringExact("PE"),
									knownvalue.StringExact("SCRIPT"),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccIOARuleGroupResource_NetworkConnection(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigNetworkConnection(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Linux")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Suspicious Network Connection"),
								"description":      knownvalue.StringExact("Monitors suspicious outbound connections"),
								"pattern_severity": knownvalue.StringExact("critical"),
								"type":             knownvalue.StringExact("Network Connection"),
								"action":           knownvalue.StringExact("Monitor"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/tmp/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"remote_ip_address": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"remote_port": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"connection_type": knownvalue.SetExact([]knownvalue.Check{
									knownvalue.StringExact("ICMP"),
									knownvalue.StringExact("TCP"),
									knownvalue.StringExact("UDP"),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Linux"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccIOARuleGroupResource_DomainName(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigDomainName(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platform"), knownvalue.StringExact("Mac")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Suspicious Domain Access"),
								"description":      knownvalue.StringExact("Detects access to suspicious domains"),
								"pattern_severity": knownvalue.StringExact("high"),
								"type":             knownvalue.StringExact("Domain Name"),
								"action":           knownvalue.StringExact("Detect"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/bin/curl"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
								"domain_name": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*malicious\\.example\\.com.*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccIOARuleGroupConfigBasic(rName, "Mac"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccIOARuleGroupResource_AllActions(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigMonitorAction(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Monitor Rule"),
								"description":      knownvalue.StringExact("Tests the Monitor action"),
								"pattern_severity": knownvalue.StringExact("low"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Monitor"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/local/bin/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigDetectAction(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Detect Rule"),
								"description":      knownvalue.StringExact("Tests the Detect action"),
								"pattern_severity": knownvalue.StringExact("medium"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Detect"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/local/bin/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigKillProcessAction(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules"),
						knownvalue.ListPartial(map[int]knownvalue.Check{
							0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
								"name":             knownvalue.StringExact("Kill Process Rule"),
								"description":      knownvalue.StringExact("Tests the Kill Process action"),
								"pattern_severity": knownvalue.StringExact("critical"),
								"type":             knownvalue.StringExact("Process Creation"),
								"action":           knownvalue.StringExact("Kill Process"),
								"enabled":          knownvalue.Bool(true),
								"image_filename": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*/usr/local/bin/.*"),
									"exclude": knownvalue.Null(),
								}),
								"command_line": knownvalue.ObjectExact(map[string]knownvalue.Check{
									"include": knownvalue.StringExact(".*"),
									"exclude": knownvalue.Null(),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIOARuleGroupResource_Validation_AllFieldsWildcard(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccIOARuleGroupConfigValidationAllWildcard(),
				ExpectError: regexp.MustCompile(`At least one non-exclude regex must match something besides .*`),
			},
		},
	})
}

func TestAccIOARuleGroupResource_Validation_AllFieldsWildcardWithExclude(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccIOARuleGroupConfigValidationWildcardWithExclude(),
				ExpectError: regexp.MustCompile(`At least one non-exclude regex must match something besides .*`),
			},
		},
	})
}

func TestAccIOARuleGroupResource_Validation_FilePathOnlyForFileCreation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name:        "file_path_on_process_creation",
			config:      testAccIOARuleGroupConfigValidationFilePathOnProcessCreation(),
			expectError: regexp.MustCompile(`file_path`),
		},
		{
			name:        "file_type_on_process_creation",
			config:      testAccIOARuleGroupConfigValidationFileTypeOnProcessCreation(),
			expectError: regexp.MustCompile(`file_type`),
		},
		{
			name:        "domain_name_on_process_creation",
			config:      testAccIOARuleGroupConfigValidationDomainNameOnProcessCreation(),
			expectError: regexp.MustCompile(`domain_name`),
		},
		{
			name:        "remote_ip_address_on_file_creation",
			config:      testAccIOARuleGroupConfigValidationNetworkFieldOnFileCreation(),
			expectError: regexp.MustCompile(`remote_ip_address`),
		},
		{
			name:        "connection_type_on_file_creation",
			config:      testAccIOARuleGroupConfigValidationConnectionTypeOnFileCreation(),
			expectError: regexp.MustCompile(`connection_type`),
		},
		{
			name:        "domain_name_on_network_connection",
			config:      testAccIOARuleGroupConfigValidationDomainNameOnNetworkConnection(),
			expectError: regexp.MustCompile(`domain_name`),
		},
		{
			name:        "file_path_on_domain_name",
			config:      testAccIOARuleGroupConfigValidationFilePathOnDomainName(),
			expectError: regexp.MustCompile(`file_path`),
		},
		{
			name:        "remote_ip_address_on_domain_name",
			config:      testAccIOARuleGroupConfigValidationNetworkFieldOnDomainName(),
			expectError: regexp.MustCompile(`remote_ip_address`),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccIOARuleGroupConfigBasic(rName, platform string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = %[1]q
  platform = %[2]q
}`, rName, platform)
}

func testAccIOARuleGroupConfigUpdate(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%[1]s-updated"
  platform    = "Linux"
  description = "Updated rule group description"
  comment     = "Updated by Terraform acceptance tests"
  enabled     = false

  rules = [
    {
      name             = "Detect Suspicious Process Updated"
      description      = "Updated process creation detection"
      comment          = "Updated rule"
      pattern_severity = "critical"
      type             = "Process Creation"
      action           = "Kill Process"
      enabled          = true

      image_filename = {
        include = ".*/opt/.*"
        exclude = ".*/opt/safe/.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "Monitor Bash Activity"
      description      = "Monitors bash process creation"
      comment          = "Additional rule"
      pattern_severity = "medium"
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

func testAccIOARuleGroupConfigUpdateRuleInPlace(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = "%[1]s-updated"
  platform    = "Linux"
  description = "Updated rule group description"
  comment     = "Updated by Terraform acceptance tests"
  enabled     = false

  rules = [
    {
      name             = "Detect Suspicious Process Updated"
      description      = "Modified description for in-place update"
      comment          = "Updated rule"
      pattern_severity = "medium"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*/opt/.*"
        exclude = ".*/opt/safe/.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "Monitor Bash Activity"
      description      = "Updated bash monitoring description"
      comment          = "Additional rule"
      pattern_severity = "medium"
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

func testAccIOARuleGroupConfigProcessCreationFull(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Windows"
  description = "Full process creation rule group"
  comment     = "Testing all process creation fields"
  enabled     = true

  rules = [
    {
      name             = "Full Process Creation Rule"
      description      = "Tests all common fields for process creation"
      comment          = "Comprehensive process creation test"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true

      grandparent_image_filename = {
        include = ".*explorer\\.exe"
      }

      grandparent_command_line = {
        include = ".*"
      }

      parent_image_filename = {
        include = ".*cmd\\.exe"
        exclude = ".*system32.*"
      }

      parent_command_line = {
        include = ".*"
      }

      image_filename = {
        include = ".*powershell\\.exe"
      }

      command_line = {
        include = ".*-encodedcommand.*"
        exclude = ".*Get-Help.*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigFileCreation(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Windows"
  description = "File creation rule group"
  comment     = "Testing file creation rule type"
  enabled     = true

  rules = [
    {
      name             = "Suspicious File Creation"
      description      = "Detects suspicious file creation"
      comment          = "File creation test rule"
      pattern_severity = "medium"
      type             = "File Creation"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*powershell\\.exe"
      }

      command_line = {
        include = ".*"
      }

      file_path = {
        include = ".*\\\\Windows\\\\Temp\\\\.*"
        exclude = ".*\\.log"
      }

      file_type = ["PE", "SCRIPT"]
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigNetworkConnection(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Network connection rule group"
  comment     = "Testing network connection rule type"
  enabled     = true

  rules = [
    {
      name             = "Suspicious Network Connection"
      description      = "Monitors suspicious outbound connections"
      comment          = "Network connection test rule"
      pattern_severity = "critical"
      type             = "Network Connection"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      remote_ip_address = {
        include = ".*"
      }

      remote_port = {
        include = ".*"
      }

      connection_type = ["ICMP", "TCP", "UDP"]
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigDomainName(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Mac"
  description = "Domain name rule group"
  comment     = "Testing domain name rule type"
  enabled     = true

  rules = [
    {
      name             = "Suspicious Domain Access"
      description      = "Detects access to suspicious domains"
      comment          = "Domain name test rule"
      pattern_severity = "high"
      type             = "Domain Name"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*/usr/bin/curl"
      }

      command_line = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious\\.example\\.com.*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigMonitorAction(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Monitor action test"
  comment     = "Testing Monitor action"
  enabled     = true

  rules = [
    {
      name             = "Monitor Rule"
      description      = "Tests the Monitor action"
      comment          = "Monitor action"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*/usr/local/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigDetectAction(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Detect action test"
  comment     = "Testing Detect action"
  enabled     = true

  rules = [
    {
      name             = "Detect Rule"
      description      = "Tests the Detect action"
      comment          = "Detect action"
      pattern_severity = "medium"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*/usr/local/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigKillProcessAction(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name        = %[1]q
  platform    = "Linux"
  description = "Kill Process action test"
  comment     = "Testing Kill Process action"
  enabled     = true

  rules = [
    {
      name             = "Kill Process Rule"
      description      = "Tests the Kill Process action"
      comment          = "Kill Process action"
      pattern_severity = "critical"
      type             = "Process Creation"
      action           = "Kill Process"
      enabled          = true

      image_filename = {
        include = ".*/usr/local/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`, rName)
}

func testAccIOARuleGroupConfigValidationAllWildcard() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-wildcard"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "All Wildcard Rule"
      description      = "Rule with only wildcard includes"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationWildcardWithExclude() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-wildcard-exclude"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Wildcard With Exclude Rule"
      description      = "Rule with wildcard include and specific exclude"
      comment          = "Should fail - exclude does not count"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*"
        exclude = ".*safe_process.*"
      }

      command_line = {
        include = ".*"
        exclude = ".*harmless.*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationFilePathOnProcessCreation() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-filepath-proc"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid File Path on Process Creation"
      description      = "file_path should not be allowed on Process Creation"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      file_path = {
        include = ".*/etc/.*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationFileTypeOnProcessCreation() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-filetype-proc"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid File Type on Process Creation"
      description      = "file_type should not be allowed on Process Creation"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      file_type = ["PE"]
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationDomainNameOnProcessCreation() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-domain-proc"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid Domain Name on Process Creation"
      description      = "domain_name should not be allowed on Process Creation"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious\\.com.*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationNetworkFieldOnFileCreation() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-network-file"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid Network Field on File Creation"
      description      = "remote_ip_address should not be allowed on File Creation"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "File Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      file_path = {
        include = ".*/etc/.*"
      }

      remote_ip_address = {
        include = ".*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationConnectionTypeOnFileCreation() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-conntype-file"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid Connection Type on File Creation"
      description      = "connection_type should not be allowed on File Creation"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "File Creation"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      file_path = {
        include = ".*/etc/.*"
      }

      connection_type = ["TCP"]
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationDomainNameOnNetworkConnection() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-domain-network"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid Domain Name on Network Connection"
      description      = "domain_name should not be allowed on Network Connection"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Network Connection"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      remote_ip_address = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious\\.com.*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationFilePathOnDomainName() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-filepath-domain"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid File Path on Domain Name"
      description      = "file_path should not be allowed on Domain Name"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Domain Name"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious\\.com.*"
      }

      file_path = {
        include = ".*/etc/.*"
      }
    }
  ]
}
`
}

func testAccIOARuleGroupConfigValidationNetworkFieldOnDomainName() string {
	return `
resource "crowdstrike_ioa_rule_group" "test" {
  name     = "tf-acc-test-validation-network-domain"
  platform = "Linux"
  enabled  = false

  rules = [
    {
      name             = "Invalid Network Field on Domain Name"
      description      = "remote_ip_address should not be allowed on Domain Name"
      comment          = "Should fail validation"
      pattern_severity = "low"
      type             = "Domain Name"
      action           = "Monitor"
      enabled          = false

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }

      domain_name = {
        include = ".*malicious\\.com.*"
      }

      remote_ip_address = {
        include = ".*"
      }
    }
  ]
}
`
}

func TestAccIOARuleGroupResource_Comment(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigGroupComment(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccIOARuleGroupConfigGroupComment(rName, "GROUP_COMMENT"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("GROUP_COMMENT")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccIOARuleGroupConfigGroupComment(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccIOARuleGroupConfigGroupComment(rName, comment string) string {
	commentLine := ""
	if comment != "" {
		commentLine = fmt.Sprintf("  comment = %q", comment)
	}
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = %[1]q
  platform = "Linux"
%[2]s
}
`, rName, commentLine)
}

func TestAccIOARuleGroupResource_RuleComment(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccIOARuleGroupConfigRuleComments(rName, "", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("comment"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("comment"),
						knownvalue.Null(),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigRuleComments(rName, "A1", "B1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("comment"),
						knownvalue.StringExact("A1"),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("comment"),
						knownvalue.StringExact("B1"),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigRuleComments(rName, "A2", "B1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("comment"),
						knownvalue.StringExact("A2"),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("comment"),
						knownvalue.StringExact("B1"),
					),
				},
			},
			{
				Config: testAccIOARuleGroupConfigRuleComments(rName, "", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("comment"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						resourceName,
						tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("comment"),
						knownvalue.Null(),
					),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccIOARuleGroupConfigRuleComments(rName, ruleAComment, ruleBComment string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = %[1]q
  platform = "Linux"

  rules = [
    {
      name             = "ruleA"
      description      = "rule A description"
%[2]s
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*/usr/bin/.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "ruleB"
      description      = "rule B description"
%[3]s
      pattern_severity = "low"
      type             = "Process Creation"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*/usr/sbin/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
`, rName, ruleCommentLine(ruleAComment), ruleCommentLine(ruleBComment))
}

func ruleCommentLine(comment string) string {
	if comment == "" {
		return ""
	}
	return fmt.Sprintf("      comment          = %q", comment)
}

func ruleAttr(i int, name string) tfjsonpath.Path {
	return tfjsonpath.New("rules").AtSliceIndex(i).AtMapKey(name)
}

func ruleID(i int) tfjsonpath.Path {
	return ruleAttr(i, "instance_id")
}

var ruleGroupDir = config.StaticDirectory("testdata/rule_group")

// ruleGroup holds the variables of testdata/rule_group. Each field sets the
// variable of the same name.
type ruleGroup struct {
	rules        []string
	keys         map[string]string
	unknownKeys  []string
	unknown      bool
	unknownRules bool
}

func (g ruleGroup) vars(name string) config.Variables {
	keys := make(map[string]config.Variable, len(g.keys))
	for id, key := range g.keys {
		keys[id] = config.StringVariable(key)
	}
	return config.Variables{
		"rule_group_name": config.StringVariable(name),
		"rules":           stringList(g.rules),
		"keys":            config.MapVariable(keys),
		"unknown_keys":    stringList(g.unknownKeys),
		"unknown":         config.BoolVariable(g.unknown),
		"unknown_rules":   config.BoolVariable(g.unknownRules),
	}
}

func stringList(values []string) config.Variable {
	list := make([]config.Variable, len(values))
	for i, v := range values {
		list[i] = config.StringVariable(v)
	}
	return config.ListVariable(list...)
}

// TestAccIOARuleGroupResource_RulesMatchByPosition checks that rules without
// keys take the instance ID of the existing rule at the same list position,
// unless that rule has a different type, in which case it is recreated.
func TestAccIOARuleGroupResource_RulesMatchByPosition(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())
	thirdID := statecheck.CompareValue(compare.ValuesSame())
	firstIDChanges := statecheck.CompareValue(compare.ValuesDiffer())
	firstNewID := statecheck.CompareValue(compare.ValuesSame())
	thirdIDChanges := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Insert a rule of the same type at the front.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"n", "a", "b"}}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(2)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					thirdID.AddStateValue(resourceName, ruleID(2)),
					firstIDChanges.AddStateValue(resourceName, ruleID(0)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-n")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "name"), knownvalue.StringExact("rule-a")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-b")),
				},
			},
			{
				// Insert a Domain Name rule at the front. The existing rule at
				// index 0 is a Process Creation rule, so it is recreated.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"d", "n", "a", "b"}}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(2), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(3)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstIDChanges.AddStateValue(resourceName, ruleID(0)),
					firstNewID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					thirdID.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(4)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "type"), knownvalue.StringExact("Domain Name")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "name"), knownvalue.StringExact("rule-n")),
				},
			},
			{
				// Remove rule-a. The remaining rules take IDs by position and
				// the last existing rule is deleted.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"d", "n", "b"}}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstNewID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					thirdID.AddStateValue(resourceName, ruleID(2)),
					thirdIDChanges.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-b")),
				},
			},
			{
				// Change rule-b's type in place.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"d", "n", "b_domain"}}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(2)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstNewID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					thirdIDChanges.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "type"), knownvalue.StringExact("Domain Name")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_RuleKeys adds keyed rules to a group with no
// rules, then inserts, reorders, removes, edits, retypes, and rekeys them.
func TestAccIOARuleGroupResource_RuleKeys(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())
	nID := statecheck.CompareValue(compare.ValuesSame())
	bIDChanges := statecheck.CompareValue(compare.ValuesDiffer())
	bNewID := statecheck.CompareValue(compare.ValuesSame())
	aIDChanges := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.Null()),
				},
			},
			{
				// Add keyed rules to a group that had none.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("a")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("b")),
				},
			},
			{
				// Insert a rule at the front.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"n", "a", "b"},
					keys:  map[string]string{"n": "n", "a": "a", "b": "b"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					nID.AddStateValue(resourceName, ruleID(0)),
					aID.AddStateValue(resourceName, ruleID(1)),
					bID.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-n")),
				},
			},
			{
				// Reorder the rules.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b", "n", "a"},
					keys:  map[string]string{"b": "b", "n": "n", "a": "a"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bID.AddStateValue(resourceName, ruleID(0)),
					nID.AddStateValue(resourceName, ruleID(1)),
					aID.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-b")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-a")),
				},
			},
			{
				// Remove rule-n from the middle.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b", "a"},
					keys:  map[string]string{"b": "b", "a": "a"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bID.AddStateValue(resourceName, ruleID(0)),
					aID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(2)),
				},
			},
			{
				// Edit rule-b's description and rename rule-a.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b_edited", "a_renamed"},
					keys:  map[string]string{"b_edited": "b", "a_renamed": "a"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bID.AddStateValue(resourceName, ruleID(0)),
					aID.AddStateValue(resourceName, ruleID(1)),
					bIDChanges.AddStateValue(resourceName, ruleID(0)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "description"), knownvalue.StringExact("rule-b edited")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "name"), knownvalue.StringExact("rule-a-renamed")),
				},
			},
			{
				// Change rule-b's type.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b_domain", "a_renamed"},
					keys:  map[string]string{"b_domain": "b", "a_renamed": "a"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bIDChanges.AddStateValue(resourceName, ruleID(0)),
					bNewID.AddStateValue(resourceName, ruleID(0)),
					aID.AddStateValue(resourceName, ruleID(1)),
					aIDChanges.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "type"), knownvalue.StringExact("Domain Name")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("b")),
				},
			},
			{
				// Change rule-a's key.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b_domain", "a_renamed"},
					keys:  map[string]string{"b_domain": "b", "a_renamed": "a2"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bNewID.AddStateValue(resourceName, ruleID(0)),
					aIDChanges.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("a2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(2)),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_RemoveRuleKeys removes every key from a keyed
// group, which returns to matching rules by list position.
func TestAccIOARuleGroupResource_RemoveRuleKeys(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Remove the keys and swap the rules.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"b", "a"}}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-b")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.Null()),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_AdoptRuleKeys adds keys to rules that have
// none. Keys must be added on their own, so adding them together with a
// rename, a new rule, or a reorder fails at plan time.
func TestAccIOARuleGroupResource_AdoptRuleKeys(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Add keys and rename rule-a.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a_renamed", "b"},
					keys:  map[string]string{"a_renamed": "a", "b": "b"},
				}.vars(rName),
				ExpectError: regexp.MustCompile(`Rule keys added with other rule changes(.|\n)*"rule-a-renamed"`),
			},
			{
				// Add keys and a new rule.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b", "c"},
					keys:  map[string]string{"a": "a", "b": "b", "c": "c"},
				}.vars(rName),
				ExpectError: regexp.MustCompile(`Rule keys added with other rule changes(.|\n)*"rule-c"`),
			},
			{
				// Add keys and swap the rules.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"b", "a"},
					keys:  map[string]string{"b": "b", "a": "a"},
				}.vars(rName),
				ExpectError: regexp.MustCompile(`Rule keys added with other rule changes(.|\n)*"rule-b"`),
			},
			{
				// Add keys only.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("a")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("b")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownName_AdoptKeys adds keys while a
// rule's name is unknown at plan time. The check that the rules are unchanged
// runs again during apply, which either matches the rules by index or fails,
// so the plan already shows each rule's instance ID.
func TestAccIOARuleGroupResource_UnknownName_AdoptKeys(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Add keys while rule-b's name is unknown at plan time. The name
				// resolves to its current value.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:   []string{"a", "b_unknown_name"},
					keys:    map[string]string{"a": "a", "b_unknown_name": "b"},
					unknown: true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "name")),
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "name"), knownvalue.StringExact("rule-b")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("b")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_AdoptRuleKeys_Imported imports a rule group, whose
// rules have no keys, into a configuration that adds keys to the rules in
// state order, then reorders the rules by key.
func TestAccIOARuleGroupResource_AdoptRuleKeys_Imported(t *testing.T) {
	rName := acctest.RandomResourceName()
	importedName := "crowdstrike_ioa_rule_group.imported"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b", "c"}}.vars(rName),
			},
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b", "c"}}.vars(rName),
				ResourceName:    resourceName,
				ImportState:     true,
				// ImportStateVerify fails if the API lists imported rules in a
				// different order than they were created.
				ImportStateVerify: true,
			},
			{
				// Import the rule group into a second resource whose rules have
				// keys, in state order.
				ConfigDirectory: config.StaticDirectory("testdata/imported_rule_group"),
				ConfigVariables: config.Variables{
					"rule_group_name": config.StringVariable(rName),
					"imported_rules":  config.ListVariable(config.StringVariable("a"), config.StringVariable("b"), config.StringVariable("c")),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(importedName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(importedName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(importedName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(resourceName, ruleID(0), importedName, ruleID(0), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, ruleID(1), importedName, ruleID(1), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, ruleID(2), importedName, ruleID(2), compare.ValuesSame()),
					statecheck.ExpectKnownValue(importedName, ruleAttr(0, "local_key"), knownvalue.StringExact("a")),
					statecheck.ExpectKnownValue(importedName, ruleAttr(2, "local_key"), knownvalue.StringExact("c")),
				},
			},
			{
				// Reorder the imported rules by key.
				ConfigDirectory: config.StaticDirectory("testdata/imported_rule_group"),
				ConfigVariables: config.Variables{
					"rule_group_name": config.StringVariable(rName),
					"imported_rules":  config.ListVariable(config.StringVariable("c"), config.StringVariable("a"), config.StringVariable("b")),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(importedName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(importedName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(importedName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(resourceName, ruleID(2), importedName, ruleID(0), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, ruleID(0), importedName, ruleID(1), compare.ValuesSame()),
					statecheck.CompareValuePairs(resourceName, ruleID(1), importedName, ruleID(2), compare.ValuesSame()),
					statecheck.ExpectKnownValue(importedName, ruleAttr(0, "name"), knownvalue.StringExact("rule-c")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_Validation_MixedRuleKeys checks that keys are all or
// nothing.
func TestAccIOARuleGroupResource_Validation_MixedRuleKeys(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b", "c"},
					keys:  map[string]string{"a": "a"},
				}.vars(rName),
				ExpectError: regexp.MustCompile(`Missing rule key(.|\n)*"rule-b"(.|\n)*Missing rule key(.|\n)*"rule-c"`),
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownKey_ByPosition makes one rule's key
// unknown at plan time while the other rule has none. Every instance ID is
// unknown at plan. A key that resolves to null keeps the rules matched by
// position, and apply rejects a key that resolves to a value.
func TestAccIOARuleGroupResource_UnknownKey_ByPosition(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// rule-b's key is unknown at plan time and resolves to null.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"a", "b"},
					unknownKeys: []string{"b"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.Null()),
				},
			},
			{
				// rule-b's key is unknown at plan time and resolves to "b", so
				// apply rejects the mix of keyed and unkeyed rules.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"a", "b"},
					keys:        map[string]string{"b": "b"},
					unknownKeys: []string{"b"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "local_key")),
					},
				},
				ExpectError: regexp.MustCompile(`Error running apply(.|\n)*Missing rule key(.|\n)*"rule-a"`),
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownAllKeys_ByIndex makes every key unknown
// at plan time while the existing rules have none. Every instance ID is
// unknown at plan. Whether the keys resolve to null or to values, the rules
// match by index during apply, and a rename while the keys resolve to null is
// not rejected.
func TestAccIOARuleGroupResource_UnknownAllKeys_ByIndex(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Rename rule-a while both keys are unknown at plan time. Both
				// keys resolve to null.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"a_renamed", "b"},
					unknownKeys: []string{"a_renamed", "b"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(0, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-a-renamed")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.Null()),
				},
			},
			{
				// Both keys are unknown at plan time and resolve to "a" and "b".
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"a_renamed", "b"},
					keys:        map[string]string{"a_renamed": "a", "b": "b"},
					unknownKeys: []string{"a_renamed", "b"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(0, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("a")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("b")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownAllKeys_KeyedPrior reorders keyed
// rules while every key is unknown at plan time, so every instance ID is
// unknown at plan and the rules match by key during apply.
func TestAccIOARuleGroupResource_UnknownAllKeys_KeyedPrior(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Both keys are unknown at plan time and resolve to "b" and "a".
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"b", "a"},
					keys:        map[string]string{"a": "a", "b": "b"},
					unknownKeys: []string{"b", "a"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					bID.AddStateValue(resourceName, ruleID(0)),
					aID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("b")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("a")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_Validation_DuplicateRuleKeys checks the duplicate key error
// points at the rules attribute, so Terraform shows the offending rules.
func TestAccIOARuleGroupResource_Validation_DuplicateRuleKeys(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "same", "b": "same"},
				}.vars(rName),
				ExpectError: regexp.MustCompile(`Duplicate local_key Values(.|\n)*\d+:\s+rules = \(`),
			},
		},
	})
}

// TestAccIOARuleGroupResource_RulePairingUpgrade checks that state written by
// the last release plans no changes with this provider. It uses Config rather
// than ConfigDirectory because ExternalProviders requires it.
func TestAccIOARuleGroupResource_RulePairingUpgrade(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"crowdstrike": {
						Source:            "crowdstrike/crowdstrike",
						VersionConstraint: "1.1.0",
					},
				},
				Config: testAccIOARuleGroupConfigUpgrade(rName),
			},
			{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Config:                   testAccIOARuleGroupConfigUpgrade(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func testAccIOARuleGroupConfigUpgrade(rName string) string {
	return fmt.Sprintf(`
resource "crowdstrike_ioa_rule_group" "test" {
  name     = %[1]q
  platform = "Mac"
  enabled  = true

  rules = [
    {
      name             = "rule-d"
      description      = "rule-d description"
      pattern_severity = "high"
      type             = "Domain Name"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*"
      }

      domain_name = {
        include = ".*rule-d\\.example\\.com.*"
      }
    },
    {
      name             = "rule-a"
      description      = "rule-a description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*rule-a.*"
      }

      command_line = {
        include = ".*"
      }
    },
    {
      name             = "rule-b"
      description      = "rule-b description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true

      image_filename = {
        include = ".*rule-b.*"
      }

      command_line = {
        include = ".*"
      }
    },
  ]
}
`, rName)
}

// TestAccIOARuleGroupResource_UnknownName_ByKey inserts a keyed rule while
// another keyed rule's name is unknown at plan time. Keys alone pair the
// rules, so the plan already knows every existing instance ID.
func TestAccIOARuleGroupResource_UnknownName_ByKey(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Insert rule-n at the front while rule-b's name is unknown at
				// plan time. The name resolves to its current value.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:   []string{"n", "a", "b_unknown_name"},
					keys:    map[string]string{"n": "n", "a": "a", "b_unknown_name": "b"},
					unknown: true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(2, "name")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(2), knownvalue.NotNull()),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(1)),
					bID.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-b")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownKey_ByKey makes one keyed rule's key
// unknown at plan time, so every instance ID is unknown at plan. A key that
// resolves to the rule's existing key keeps its instance ID, and a new rule
// whose key resolves to a new key is created.
func TestAccIOARuleGroupResource_UnknownKey_ByKey(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// rule-b's key is unknown at plan time and resolves to "b".
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"a", "b"},
					keys:        map[string]string{"a": "a", "b": "b"},
					unknownKeys: []string{"b"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "local_key"), knownvalue.StringExact("b")),
				},
			},
			{
				// Add rule-n at the front. Its key is unknown at plan time and
				// resolves to "n".
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:       []string{"n", "a", "b"},
					keys:        map[string]string{"n": "n", "a": "a", "b": "b"},
					unknownKeys: []string{"n"},
					unknown:     true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(0, "local_key")),
						plancheck.ExpectUnknownValue(resourceName, ruleID(0)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
						plancheck.ExpectUnknownValue(resourceName, ruleID(2)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(1)),
					bID.AddStateValue(resourceName, ruleID(2)),
					statecheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "local_key"), knownvalue.StringExact("n")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownType_ByKey makes a keyed rule's type
// unknown at plan time. The plan cannot tell whether the rule must be
// recreated, so its instance ID is unknown until apply.
func TestAccIOARuleGroupResource_UnknownType_ByKey(t *testing.T) {
	rName := acctest.RandomResourceName()
	aID := statecheck.CompareValue(compare.ValuesSame())
	bID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules: []string{"a", "b"},
					keys:  map[string]string{"a": "a", "b": "b"},
				}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// rule-b's type is unknown at plan time and resolves to its
				// current type.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:   []string{"a", "b_unknown_type"},
					keys:    map[string]string{"a": "a", "b_unknown_type": "b"},
					unknown: true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(1, "type")),
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(1)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					aID.AddStateValue(resourceName, ruleID(0)),
					bID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(1, "type"), knownvalue.StringExact("Process Creation")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownRulesList inserts a rule while the whole
// rules list is unknown at plan time. Once the list is known, the rules take
// instance IDs by list position.
func TestAccIOARuleGroupResource_UnknownRulesList(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Insert rule-n at the front while the whole rules list is
				// unknown at plan time.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:        []string{"n", "a", "b"},
					unknown:      true,
					unknownRules: true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, tfjsonpath.New("rules")),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("rules"), knownvalue.ListSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(0, "name"), knownvalue.StringExact("rule-n")),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-b")),
				},
			},
		},
	})
}

// TestAccIOARuleGroupResource_UnknownName_ByPosition adds a rule ahead of an
// existing rule whose name is unknown at plan time. No rule has a key.
func TestAccIOARuleGroupResource_UnknownName_ByPosition(t *testing.T) {
	rName := acctest.RandomResourceName()
	firstID := statecheck.CompareValue(compare.ValuesSame())
	secondID := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{rules: []string{"a", "b"}}.vars(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
				},
			},
			{
				// Insert rule-n at the front while rule-b's name is unknown at
				// plan time. Rules pair by position, so the first two keep their
				// IDs.
				ConfigDirectory: ruleGroupDir,
				ConfigVariables: ruleGroup{
					rules:   []string{"n", "a", "b_unknown_name"},
					unknown: true,
				}.vars(rName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(resourceName, ruleAttr(2, "name")),
						plancheck.ExpectKnownValue(resourceName, ruleID(0), knownvalue.NotNull()),
						plancheck.ExpectKnownValue(resourceName, ruleID(1), knownvalue.NotNull()),
						plancheck.ExpectUnknownValue(resourceName, ruleID(2)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					firstID.AddStateValue(resourceName, ruleID(0)),
					secondID.AddStateValue(resourceName, ruleID(1)),
					statecheck.ExpectKnownValue(resourceName, ruleAttr(2, "name"), knownvalue.StringExact("rule-b")),
				},
			},
		},
	})
}
