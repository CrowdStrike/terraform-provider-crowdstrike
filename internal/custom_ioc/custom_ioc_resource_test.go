package customioc_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	customioc "github.com/crowdstrike/terraform-provider-crowdstrike/internal/custom_ioc"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCustomIOCResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("domain")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(rName+".example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"action", "mobile_action"},
			},
		},
	})
}

func TestAccCustomIOCResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	modifiedByStays := statecheck.CompareValue(compare.ValuesSame())
	modifiedOnChanges := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("domain")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(rName+".example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				Config: testAccCustomIOCConfig_updated(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("domain")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(rName+".example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("no_action")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
						knownvalue.StringExact("linux"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.StringExact("2099-12-31T23:59:59Z")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.StringExact("terraform")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("tf-acc-test"),
					})),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				Config: testAccCustomIOCConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("domain")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(rName+".example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				Config: testAccCustomIOCConfig_basicNoDescription(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"action", "mobile_action"},
			},
		},
	})
}

func TestAccCustomIOCResource_type(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	sha256A := acctest.SHA256(rName + "-a")
	sha256B := acctest.SHA256(rName + "-b")
	md5Hash := acctest.MD5(rName)

	expectReplace := resource.ConfigPlanChecks{
		PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_typeSha256(rName, sha256A, "allow"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("sha256")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(sha256A)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.Null()),
				},
			},
			{
				Config:           testAccCustomIOCConfig_typeSha256(rName, sha256B, "allow"),
				ConfigPlanChecks: expectReplace,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("sha256")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(sha256B)),
				},
			},
			{
				Config:           testAccCustomIOCConfig_typeWithDetect(rName, "md5", md5Hash),
				ConfigPlanChecks: expectReplace,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("md5")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact(md5Hash)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.Null()),
				},
			},
			{
				Config:           testAccCustomIOCConfig_typeWithDetect(rName, "ipv4", "192.0.2.10"),
				ConfigPlanChecks: expectReplace,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact("192.0.2.10")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.Null()),
				},
			},
			{
				Config:           testAccCustomIOCConfig_typeWithDetect(rName, "ipv6", "2001:db8::1"),
				ConfigPlanChecks: expectReplace,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ipv6")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("value"), knownvalue.StringExact("2001:db8::1")),
				},
			},
			{
				Config:           testAccCustomIOCConfig_typeAllSubdomains(rName),
				ConfigPlanChecks: expectReplace,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("all_subdomains")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("detect")),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_action(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"
	hash := acctest.SHA256(rName)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "allow", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "detect", "low"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "prevent", "high"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "prevent_no_ui", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("prevent_no_ui")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "no_action", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("no_action")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_platforms(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_platforms(rName, []string{"windows"}, "detect", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_platforms(rName, []string{"windows", "ios"}, "detect", "prevent"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
						knownvalue.StringExact("ios"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("prevent")),
				},
			},
			{
				Config: testAccCustomIOCConfig_platforms(rName, []string{"ios"}, "", "prevent"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("ios"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("prevent")),
				},
			},
			{
				Config: testAccCustomIOCConfig_platforms(rName, []string{"ios", "android"}, "", "prevent"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("ios"),
						knownvalue.StringExact("android"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("prevent")),
				},
			},
			{
				Config: testAccCustomIOCConfig_platforms(rName, []string{"windows"}, "detect", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("platforms"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("windows"),
					})),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_description(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_description(rName, rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName)),
				},
			},
			{
				Config: testAccCustomIOCConfig_description(rName, rName+"-updated"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName+"-updated")),
				},
			},
			{
				Config: testAccCustomIOCConfig_description(rName, rName+"-final"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact(rName+"-final")),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_source(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_source(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_source(rName, "terraform"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.StringExact("terraform")),
				},
			},
			{
				Config: testAccCustomIOCConfig_source(rName, "custom-source"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.StringExact("custom-source")),
				},
			},
			{
				Config: testAccCustomIOCConfig_source(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("source"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_tags(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_tags(rName, nil),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_tags(rName, []string{"one"}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("one"),
					})),
				},
			},
			{
				Config: testAccCustomIOCConfig_tags(rName, []string{"one", "two"}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("one"),
						knownvalue.StringExact("two"),
					})),
				},
			},
			{
				Config: testAccCustomIOCConfig_tags(rName, []string{"three"}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("three"),
					})),
				},
			},
			{
				Config: testAccCustomIOCConfig_tags(rName, nil),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_expiration(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_expiration(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_expiration(rName, "2099-12-31T23:59:59Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.StringExact("2099-12-31T23:59:59Z")),
				},
			},
			{
				Config: testAccCustomIOCConfig_expiration(rName, "2100-06-30T00:00:00Z"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.StringExact("2100-06-30T00:00:00Z")),
				},
			},
			{
				Config:      testAccCustomIOCConfig_expiration(rName, "2020-01-01T00:00:00Z"),
				ExpectError: regexp.MustCompile(`(?s)expiration must be a future date`),
			},
			{
				Config: testAccCustomIOCConfig_expiration(rName, ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("expiration"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_hostGroups(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"
	hg1 := "crowdstrike_host_group.test1"
	hg2 := "crowdstrike_host_group.test2"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_hostGroups(rName, "[crowdstrike_host_group.test1.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccCustomIOCConfig_hostGroups(rName, "[crowdstrike_host_group.test1.id, crowdstrike_host_group.test2.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
				},
			},
			{
				Config: testAccCustomIOCConfig_hostGroups(rName, `["all"]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
				},
			},
			{
				Config: testAccCustomIOCConfig_hostGroups(rName, "[crowdstrike_host_group.test2.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg2, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_mobileAction(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_mobileAction(rName, "allow", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_mobileAction(rName, "detect", "low"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
				},
			},
			{
				Config: testAccCustomIOCConfig_mobileAction(rName, "prevent", "high"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("high")),
				},
			},
			{
				Config: testAccCustomIOCConfig_mobileAction(rName, "prevent_no_ui", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("prevent_no_ui")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_mobileAction(rName, "no_action", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("mobile_action"), knownvalue.StringExact("no_action")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_severity(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_custom_ioc.test"
	hash := acctest.SHA256(rName)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "allow", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "detect", "low"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("detect")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("low")),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "detect", "critical"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("critical")),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "prevent", "medium"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("prevent")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.StringExact("medium")),
				},
			},
			{
				Config: testAccCustomIOCConfig_action(rName, hash, "allow", ""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("severity"), knownvalue.Null()),
				},
			},
		},
	})
}

func TestAccCustomIOCResource_validateConfig(t *testing.T) {
	rName := acctest.RandomResourceName()
	hash := acctest.SHA256(rName)

	cases := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name:        "sha256 rejects mobile platform",
			config:      testAccCustomIOCConfig_invalidSha256Mobile(rName),
			expectError: regexp.MustCompile(`(?s)Hash types.*only support`),
		},
		{
			name:        "all_subdomains rejects non-mobile platform",
			config:      testAccCustomIOCConfig_invalidAllSubdomainsNonMobile(rName),
			expectError: regexp.MustCompile(`(?s)only supports mobile platforms`),
		},
		{
			name:        "domain rejects prevent on non-mobile",
			config:      testAccCustomIOCConfig_invalidDomainAction(rName),
			expectError: regexp.MustCompile(`(?s)not permitted for "domain" indicators`),
		},
		{
			name:        "severity required when action=detect",
			config:      testAccCustomIOCConfig_missingSeverity(rName),
			expectError: regexp.MustCompile(`(?s)severity is required`),
		},
		{
			name:        "mixed platforms require both actions",
			config:      testAccCustomIOCConfig_mixedMissingMobileAction(rName),
			expectError: regexp.MustCompile(`(?s)mobile_action is required when platforms contains a mobile`),
		},
		{
			name:        "non-mobile platform requires action",
			config:      testAccCustomIOCConfig_missingActionForPlatforms(rName, `["windows"]`),
			expectError: regexp.MustCompile(`(?s)action is required when platforms contains a non-mobile`),
		},
		{
			name:        "mobile platform requires mobile_action",
			config:      testAccCustomIOCConfig_missingActionForPlatforms(rName, `["ios"]`),
			expectError: regexp.MustCompile(`(?s)mobile_action is required when platforms contains a mobile`),
		},
		{
			name:        "action set with mobile-only platforms",
			config:      testAccCustomIOCConfig_actionPlatformMismatch(rName, `["ios"]`),
			expectError: regexp.MustCompile(`(?s)action has no effect without a non-mobile platform`),
		},
		{
			name:        "mobile_action set with non-mobile-only platforms",
			config:      testAccCustomIOCConfig_actionPlatformMismatch(rName, `["windows"]`),
			expectError: regexp.MustCompile(`(?s)mobile_action has no effect without a mobile platform`),
		},
		{
			name:        "severity set with action=allow",
			config:      testAccCustomIOCConfig_severityForbiddenAction(rName, "allow"),
			expectError: regexp.MustCompile(`(?s)Invalid severity`),
		},
		{
			name:        "severity set with mobile_action=allow",
			config:      testAccCustomIOCConfig_severityForbiddenMobileAction(rName, "allow"),
			expectError: regexp.MustCompile(`(?s)Invalid severity`),
		},
		{
			name:        "severity set with action=prevent_no_ui",
			config:      testAccCustomIOCConfig_severityForbiddenAction(rName, "prevent_no_ui"),
			expectError: regexp.MustCompile(`(?s)Invalid severity`),
		},
		{
			name:        "severity set with action=no_action",
			config:      testAccCustomIOCConfig_severityForbiddenAction(rName, "no_action"),
			expectError: regexp.MustCompile(`(?s)Invalid severity`),
		},
		{
			name:        "expiration must be in the future on create",
			config:      testAccCustomIOCConfig_pastExpiration(rName),
			expectError: regexp.MustCompile(`(?s)expiration must be a future date`),
		},
		{
			name:        "severity required when mobile_action=detect",
			config:      testAccCustomIOCConfig_missingSeverityMobile(rName),
			expectError: regexp.MustCompile(`(?s)severity is required`),
		},
		{
			name:        "description whitespace rejected",
			config:      testAccCustomIOCConfig_description(rName, "   "),
			expectError: regexp.MustCompile(`(?s)must not be empty or contain only whitespace`),
		},
		{
			name:        "source whitespace rejected",
			config:      testAccCustomIOCConfig_source(rName, "   "),
			expectError: regexp.MustCompile(`(?s)must not be empty or contain only whitespace`),
		},
		{
			name:        "tag element whitespace rejected",
			config:      testAccCustomIOCConfig_tags(rName, []string{"   "}),
			expectError: regexp.MustCompile(`(?s)must not be empty or contain only whitespace`),
		},
		{
			name:        "invalid type rejected",
			config:      testAccCustomIOCConfig_invalidType(rName),
			expectError: regexp.MustCompile(`(?s)value must be one of`),
		},
		{
			name:        "invalid platform rejected",
			config:      testAccCustomIOCConfig_invalidPlatform(rName),
			expectError: regexp.MustCompile(`(?s)value must be one of`),
		},
		{
			name:        "invalid action rejected",
			config:      testAccCustomIOCConfig_action(rName, hash, "shrug", ""),
			expectError: regexp.MustCompile(`(?s)value must be one of`),
		},
		{
			name:        "invalid severity rejected",
			config:      testAccCustomIOCConfig_action(rName, hash, "detect", "extreme"),
			expectError: regexp.MustCompile(`(?s)value must be one of`),
		},
		{
			name:        "empty platforms rejected",
			config:      testAccCustomIOCConfig_emptyPlatforms(rName),
			expectError: regexp.MustCompile(`(?s)set must contain at least 1 element`),
		},
		{
			name:        "empty tags rejected",
			config:      testAccCustomIOCConfig_emptyTags(rName),
			expectError: regexp.MustCompile(`(?s)set must contain at least 1 element`),
		},
		{
			name:        "empty host_groups rejected",
			config:      testAccCustomIOCConfig_emptyHostGroups(rName),
			expectError: regexp.MustCompile(`(?s)set must contain at least 1 element`),
		},
		{
			name:        "host_groups empty string element rejected",
			config:      testAccCustomIOCConfig_hostGroupsEmptyString(rName),
			expectError: regexp.MustCompile(`(?s)string length must be at least 1`),
		},
		{
			name:        `host_groups mixing "all" with specific IDs rejected`,
			config:      testAccCustomIOCConfig_allMixedWithIDs(rName),
			expectError: regexp.MustCompile(`(?s)host_groups cannot mix "all" with specific host group IDs`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
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

func TestBuildUpdateExpiration(t *testing.T) {
	t.Parallel()

	past := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	futureDT := strfmt.DateTime(future)

	tests := []struct {
		name string
		plan timetypes.RFC3339
		want *strfmt.DateTime
	}{
		{"null plan clears expiration", timetypes.NewRFC3339Null(), &strfmt.DateTime{}},
		{"expired plan is omitted", timetypes.NewRFC3339TimeValue(past), nil},
		{"future plan is sent", timetypes.NewRFC3339TimeValue(future), &futureDT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, diags := customioc.BuildUpdateExpiration(tt.plan)
			if diags.HasError() {
				t.Fatalf("unexpected diag errors: %v", diags)
			}

			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("got %v, want nil", time.Time(*got))
			case tt.want != nil && got == nil:
				t.Fatalf("got nil, want %v", time.Time(*tt.want))
			case tt.want != nil && !time.Time(*got).Equal(time.Time(*tt.want)):
				t.Fatalf("got %v, want %v", time.Time(*got), time.Time(*tt.want))
			}
		})
	}
}

// description is set to rName so the sweeper, which matches on the
// sweep.ResourcePrefix embedded in rName, can clean up leftover indicators.
func testAccCustomIOCConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName)
}

// testAccCustomIOCConfig_basicNoDescription mirrors _basic but omits
// description. Sweeper matches on description, so this config cannot be
// swept if a test crashes mid-run.
func testAccCustomIOCConfig_basicNoDescription(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_updated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "no_action"
  description = "%[1]s-updated"
  platforms   = ["windows", "linux"]
  host_groups = ["all"]
  expiration  = "2099-12-31T23:59:59Z"
  source      = "terraform"
  tags        = ["tf-acc-test"]
}
`, rName)
}

func testAccCustomIOCConfig_hostGroups(rName, hostGroups string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test1" {
  name        = "%[1]s-hg1"
  description = "test host group for custom_ioc tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-hg2"
  description = "test host group for custom_ioc tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = %[2]s
}
`, rName, hostGroups)
}

func testAccCustomIOCConfig_allMixedWithIDs(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all", "some-other-id"]
}
`, rName)
}

func testAccCustomIOCConfig_typeSha256(rName, hash, action string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "sha256"
  value       = %[2]q
  action      = %[3]q
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, hash, action)
}

func testAccCustomIOCConfig_typeWithDetect(rName, iocType, value string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = %[2]q
  value       = %[3]q
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, iocType, value)
}

func testAccCustomIOCConfig_typeAllSubdomains(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "all_subdomains"
  value         = "%[1]s.example.com"
  mobile_action = "detect"
  severity      = "low"
  description   = %[1]q
  platforms     = ["ios", "android"]
  host_groups   = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_description(rName, description string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[2]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, description)
}

func testAccCustomIOCConfig_source(rName, source string) string {
	sourceLine := ""
	if source != "" {
		sourceLine = fmt.Sprintf("  source      = %q\n", source)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
%[2]s  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, sourceLine)
}

func testAccCustomIOCConfig_tags(rName string, tags []string) string {
	tagsLine := ""
	if tags != nil {
		quoted := make([]string, len(tags))
		for i, tag := range tags {
			quoted[i] = fmt.Sprintf("%q", tag)
		}
		tagsLine = fmt.Sprintf("  tags        = [%s]\n", strings.Join(quoted, ", "))
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
%[2]s}
`, rName, tagsLine)
}

func testAccCustomIOCConfig_expiration(rName, expiration string) string {
	expirationLine := ""
	if expiration != "" {
		expirationLine = fmt.Sprintf("  expiration  = %q\n", expiration)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
%[2]s}
`, rName, expirationLine)
}

func testAccCustomIOCConfig_action(rName, hash, action, severity string) string {
	severityLine := ""
	if severity != "" {
		severityLine = fmt.Sprintf("  severity    = %q\n", severity)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "sha256"
  value       = %[2]q
  action      = %[3]q
%[4]s  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, hash, action, severityLine)
}

func testAccCustomIOCConfig_mobileAction(rName, mobileAction, severity string) string {
	severityLine := ""
	if severity != "" {
		severityLine = fmt.Sprintf("  severity      = %q\n", severity)
	}
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "domain"
  value         = "%[1]s.example.com"
  mobile_action = %[2]q
%[3]s  description   = %[1]q
  platforms     = ["ios", "android"]
  host_groups   = ["all"]
}
`, rName, mobileAction, severityLine)
}

func testAccCustomIOCConfig_platforms(rName string, platforms []string, action, mobileAction string) string {
	quoted := make([]string, len(platforms))
	for i, p := range platforms {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	platformsList := "[" + strings.Join(quoted, ", ") + "]"

	actionLine := ""
	if action != "" {
		actionLine = fmt.Sprintf("  action        = %q\n", action)
	}
	mobileActionLine := ""
	if mobileAction != "" {
		mobileActionLine = fmt.Sprintf("  mobile_action = %q\n", mobileAction)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "domain"
  value         = "%[1]s.example.com"
%[2]s%[3]s  severity      = "low"
  description   = %[1]q
  platforms     = %[4]s
  host_groups   = ["all"]
}
`, rName, actionLine, mobileActionLine, platformsList)
}

func testAccCustomIOCConfig_invalidSha256Mobile(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "sha256"
  value         = %[2]q
  action        = "detect"
  mobile_action = "detect"
  severity      = "low"
  description   = %[1]q
  platforms     = ["windows", "ios"]
  host_groups   = ["all"]
}
`, rName, acctest.SHA256(rName))
}

func testAccCustomIOCConfig_invalidAllSubdomainsNonMobile(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "all_subdomains"
  value         = "%[1]s.example.com"
  mobile_action = "detect"
  severity      = "low"
  description   = %[1]q
  platforms     = ["ios", "windows"]
  host_groups   = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_invalidDomainAction(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "prevent"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_missingSeverity(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_mixedMissingMobileAction(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows", "ios"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_severityForbiddenAction(rName, action string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "sha256"
  value       = %[2]q
  action      = %[3]q
  severity    = "high"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName, acctest.SHA256(rName), action)
}

func testAccCustomIOCConfig_severityForbiddenMobileAction(rName, mobileAction string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "domain"
  value         = "%[1]s.example.com"
  mobile_action = %[2]q
  severity      = "high"
  description   = %[1]q
  platforms     = ["ios"]
  host_groups   = ["all"]
}
`, rName, mobileAction)
}

func testAccCustomIOCConfig_missingActionForPlatforms(rName, platforms string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  description = %[1]q
  platforms   = %[2]s
  host_groups = ["all"]
}
`, rName, platforms)
}

func testAccCustomIOCConfig_actionPlatformMismatch(rName, platforms string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "domain"
  value         = "%[1]s.example.com"
  action        = "detect"
  mobile_action = "detect"
  severity      = "low"
  description   = %[1]q
  platforms     = %[2]s
  host_groups   = ["all"]
}
`, rName, platforms)
}

func testAccCustomIOCConfig_pastExpiration(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
  expiration  = "2020-01-01T00:00:00Z"
}
`, rName)
}

func testAccCustomIOCConfig_missingSeverityMobile(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type          = "domain"
  value         = "%[1]s.example.com"
  mobile_action = "detect"
  description   = %[1]q
  platforms     = ["ios"]
  host_groups   = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_invalidType(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "unknown"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_invalidPlatform(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["beos"]
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_emptyPlatforms(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = []
  host_groups = ["all"]
}
`, rName)
}

func testAccCustomIOCConfig_emptyTags(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = ["all"]
  tags        = []
}
`, rName)
}

func testAccCustomIOCConfig_emptyHostGroups(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = []
}
`, rName)
}

func testAccCustomIOCConfig_hostGroupsEmptyString(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_custom_ioc" "test" {
  type        = "domain"
  value       = "%[1]s.example.com"
  action      = "detect"
  severity    = "low"
  description = %[1]q
  platforms   = ["windows"]
  host_groups = [""]
}
`, rName)
}
