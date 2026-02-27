package ioarulegroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
									knownvalue.StringExact("TCP"),
									knownvalue.StringExact("UDP"),
								}),
							}),
						}),
					),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
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

      connection_type = ["TCP", "UDP"]
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
