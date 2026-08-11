// Tests for crowdstrike_data_protection_policy: the acceptance tests first, then
// the unit tests over the resource's own expand, flatten, mapping, and validation
// helpers.
//
// The acceptance tests require a tenant entitled to Falcon Data Protection in
// addition to Falcon Insight XDR. The feature is gated, so a tenant without the
// entitlement fails every one of them with a 403.
package dataprotection_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	dataprotection "github.com/crowdstrike/terraform-provider-crowdstrike/internal/data_protection"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policyResourceName = "crowdstrike_data_protection_policy.test"

// policyImportStep round-trips the policy through `terraform import` and verifies
// every attribute against the state the preceding step produced.
var policyImportStep = resource.TestStep{
	ResourceName:      policyResourceName,
	ImportState:       true,
	ImportStateVerify: true,
}

// policyInPlaceUpdate asserts the next step updates the policy rather than
// replacing it, which is what proves an attribute is not accidentally
// force-new.
var policyInPlaceUpdate = resource.ConfigPlanChecks{
	PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionUpdate),
	},
}

// TestAccDataProtectionPolicy_basic covers the smallest valid policy and both
// supported import paths.
func TestAccDataProtectionPolicy_basic(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					checkRemotePolicyExists(),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("cid"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					checkRemotePolicyValueMatchesState(
						"cid",
						func(p *models.PolicymanagerExternalPolicy) any { return deref(p.Cid) },
					),
					checkRemotePolicyValueMatchesState(
						"created_at",
						func(p *models.PolicymanagerExternalPolicy) any { return deref(p.CreatedAt) },
					),
					checkRemotePolicyValueMatchesState(
						"created_by",
						func(p *models.PolicymanagerExternalPolicy) any { return deref(p.CreatedBy) },
					),
					checkRemotePolicyModified(false),
				},
			},
			policyImportStep,
			{
				ResourceName:    policyResourceName,
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithID,
				ImportPlanChecks: resource.ImportPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_update is the main lifecycle test for ordinary
// attributes: start with them omitted, configure them, import the populated policy,
// then omit them again. Focused tests below cover behavior that is not represented by
// this normal update path.
func TestAccDataProtectionPolicy_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	classifications := createTestClassifications(t, rName, 2)
	idSame := statecheck.CompareValue(compare.ValuesSame())

	configured := policySharedSettingsHCL()
	maps.Copy(configured, map[string]string{
		"description":                        `"updated description"`,
		"enabled":                            `true`,
		"classifications":                    hclStringList(classifications),
		"be_exclude_domains":                 `["*://*.zulu.example/*", "*://*.alpha.example/*"]`,
		"be_custom_splash_message":           `"Checking this file"`,
		"custom_allowed_action_notification": `"This action was logged"`,
		"custom_blocked_action_notification": `"This action was blocked"`,
		"euj_company_logo":                   fmt.Sprintf("%q", policyTransparentLogo),
		"euj_custom_header_text":             `"Explain why you need this file."`,
		"euj_business_purposes_enabled":      `false`,
		"euj_personal_use_enabled":           `false`,
		"euj_custom_dropdown_options":        `["Legal review", "Customer request"]`,
	})

	minimalChecks := func(name string) []statecheck.StateCheck {
		return slices.Concat(
			[]statecheck.StateCheck{
				idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("name"), knownvalue.StringExact(name)),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("description"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("classifications"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_exclude_domains"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_custom_splash_message"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("custom_allowed_action_notification"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("custom_blocked_action_notification"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_company_logo"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_header_text"), knownvalue.Null()),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_business_purposes_enabled"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_personal_use_enabled"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_dropdown_options"), knownvalue.Null()),
				checkRemotePolicyDescription(""),
				checkRemotePolicyValue(
					"enabled",
					false,
					func(p *models.PolicymanagerExternalPolicy) any { return deref(p.IsEnabled) },
				),
				checkRemotePolicyHostGroupCount(0),
				checkRemotePolicyClassifications(nil),
				checkRemotePolicyValue(
					"be_exclude_domains",
					"",
					func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BeExcludeDomains
					},
				),
				checkRemotePolicyValue("be_splash_message_source", "default", func(p *models.PolicymanagerExternalPolicy) any {
					if p.PolicyProperties == nil {
						return nil
					}
					return p.PolicyProperties.BeSplashMessageSource
				}),
				checkRemotePolicyValue("allow_notifications", "default", func(p *models.PolicymanagerExternalPolicy) any {
					if p.PolicyProperties == nil {
						return nil
					}
					return p.PolicyProperties.AllowNotifications
				}),
				checkRemotePolicyValue("block_notifications", "default", func(p *models.PolicymanagerExternalPolicy) any {
					if p.PolicyProperties == nil {
						return nil
					}
					return p.PolicyProperties.BlockNotifications
				}),
				checkRemotePolicyValue("euj_dialog_box_logo", "", func(p *models.PolicymanagerExternalPolicy) any {
					if p.PolicyProperties == nil {
						return nil
					}
					return p.PolicyProperties.EujDialogBoxLogo
				}),
				checkRemotePolicyEujHeader(""),
				checkRemotePolicyEujOptions(true, true, nil),
				checkRemotePolicySharedSettings(false),
				checkRemotePolicyClipboardWebOrigin(false),
			},
			stateChecksForSharedSettings(false),
		)
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config:            testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: minimalChecks(rName),
			},
			{
				Config:           testAccPolicyConfigHostGroups(rName+"-updated", []int{0, 1}, configured),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("classifications"), knownvalue.SetExact([]knownvalue.Check{
							knownvalue.StringExact(classifications[0]),
							knownvalue.StringExact(classifications[1]),
						})),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_exclude_domains"), knownvalue.SetExact([]knownvalue.Check{
							knownvalue.StringExact("*://*.alpha.example/*"),
							knownvalue.StringExact("*://*.zulu.example/*"),
						})),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_custom_splash_message"), knownvalue.StringExact("Checking this file")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("custom_allowed_action_notification"), knownvalue.StringExact("This action was logged")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("custom_blocked_action_notification"), knownvalue.StringExact("This action was blocked")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_company_logo"), knownvalue.StringExact(policyTransparentLogo)),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_header_text"), knownvalue.StringExact("Explain why you need this file.")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_business_purposes_enabled"), knownvalue.Bool(false)),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_personal_use_enabled"), knownvalue.Bool(false)),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_dropdown_options"), knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact("Legal review"),
							knownvalue.StringExact("Customer request"),
						})),
						checkRemotePolicyDescription("updated description"),
						checkRemotePolicyValue(
							"enabled",
							true,
							func(p *models.PolicymanagerExternalPolicy) any { return deref(p.IsEnabled) },
						),
						checkRemotePolicyHostGroupCount(2),
						checkRemotePolicyClassifications(classifications),
						checkRemotePolicyValue(
							"be_exclude_domains",
							"*://*.alpha.example/*,*://*.zulu.example/*",
							func(p *models.PolicymanagerExternalPolicy) any {
								if p.PolicyProperties == nil {
									return nil
								}
								return p.PolicyProperties.BeExcludeDomains
							},
						),
						checkRemotePolicyValue("be_splash_custom_message", "Checking this file", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.BeSplashCustomMessage
						}),
						checkRemotePolicyValue("custom_allow_notification", "This action was logged", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.CustomAllowNotification
						}),
						checkRemotePolicyValue("custom_block_notification", "This action was blocked", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.CustomBlockNotification
						}),
						checkRemotePolicyValue("be_splash_message_source", "custom", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.BeSplashMessageSource
						}),
						checkRemotePolicyValue("allow_notifications", "custom", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.AllowNotifications
						}),
						checkRemotePolicyValue("block_notifications", "custom", func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.BlockNotifications
						}),
						checkRemotePolicyValue("euj_dialog_box_logo", policyTransparentLogo, func(p *models.PolicymanagerExternalPolicy) any {
							if p.PolicyProperties == nil {
								return nil
							}
							return p.PolicyProperties.EujDialogBoxLogo
						}),
						checkRemotePolicyEujHeader("Explain why you need this file."),
						checkRemotePolicyEujOptions(false, false, []string{"Legal review", "Customer request"}),
						checkRemotePolicySharedSettings(true),
						checkRemotePolicyClipboardWebOrigin(true),
					},
					stateChecksForSharedSettings(true),
				),
			},
			policyImportStep,
			{
				Config:            testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigPlanChecks:  policyInPlaceUpdate,
				ConfigStateChecks: minimalChecks(rName),
			},
		},
	})
}

// TestAccDataProtectionPolicy_enabled covers the create and destroy paths that are
// unique to an enabled policy. Ordinary enable/disable updates are covered by the
// main update test.
func TestAccDataProtectionPolicy_enabled(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"enabled": `true`,
				}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					checkRemotePolicyValue(
						"enabled",
						true,
						func(p *models.PolicymanagerExternalPolicy) any { return deref(p.IsEnabled) },
					),
					checkRemotePolicyModified(true),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_hostGroups covers the collection behavior that is easy
// to lose inside the general update test: assignment during create, unordered set
// semantics, membership changes, and remote clearing.
func TestAccDataProtectionPolicy_hostGroups(t *testing.T) {
	rName := acctest.RandomResourceName()
	idSame := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigHostGroups(rName, []int{0, 1}, nil),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
					statecheck.CompareValueCollection(
						policyResourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")},
						"crowdstrike_host_group.test-0", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValueCollection(
						policyResourceName, []tfjsonpath.Path{tfjsonpath.New("host_groups")},
						"crowdstrike_host_group.test-1", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					checkRemotePolicyHostGroupCount(2),
					checkRemotePolicyModified(true),
				},
			},
			{
				// Reordering a set in configuration must not cause an update. The
				// out-of-band mutation reverses only the remote array; the final plan
				// must remain empty after refresh.
				Config: testAccPolicyConfigHostGroups(rName, []int{1, 0}, nil),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionNoop),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					reorderRemotePolicyHostGroups(),
				},
			},
			{
				Config:           testAccPolicyConfigHostGroups(rName, []int{0}, nil),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					checkRemotePolicyHostGroupCount(1),
				},
			},
			{
				Config:           testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("host_groups"), knownvalue.Null()),
					checkRemotePolicyHostGroupCount(0),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_classifications covers create-time assignment,
// unordered set semantics, membership changes, and remote clearing.
func TestAccDataProtectionPolicy_classifications(t *testing.T) {
	rName := acctest.RandomResourceName()
	classifications := createTestClassifications(t, rName, 2)
	idSame := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigClassifications(rName, classifications),
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("classifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(classifications[0]),
						knownvalue.StringExact(classifications[1]),
					})),
					checkRemotePolicyClassifications(classifications),
					checkRemotePolicyModified(false),
				},
			},
			{
				Config: testAccPolicyConfigClassifications(rName, []string{classifications[1], classifications[0]}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionNoop),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					reorderRemotePolicyClassifications(),
				},
			},
			{
				Config:           testAccPolicyConfigClassifications(rName, classifications[:1]),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("classifications"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(classifications[0]),
					})),
					checkRemotePolicyClassifications(classifications[:1]),
				},
			},
			{
				Config:           testAccPolicyConfigClassifications(rName, nil),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("classifications"), knownvalue.Null()),
					checkRemotePolicyClassifications(nil),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_platformName_requiresReplace verifies that changing
// platform replaces the policy rather than attempting an in-place update.
func TestAccDataProtectionPolicy_platformName_requiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	idDiffers := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					idDiffers.AddStateValue(policyResourceName, tfjsonpath.New("id")),
				},
			},
			{
				Config: testAccPolicyConfigMinimal(rName, "Mac"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionReplace),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idDiffers.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Mac")),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_disappears verifies that a policy deleted outside
// Terraform is removed from state during refresh.
func TestAccDataProtectionPolicy_disappears(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					checkRemotePolicyExists(),
					deleteRemotePolicy(),
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccDataProtectionPolicy_import_invalidID verifies import ID validation before
// an invalid ID is sent to the API.
func TestAccDataProtectionPolicy_import_invalidID(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
			},
			{
				ResourceName:  policyResourceName,
				ImportState:   true,
				ImportStateId: "not-a-policy-id",
				ExpectError:   regexp.MustCompile(`Expected a 32-character hexadecimal policy ID`),
			},
		},
	})
}

// TestAccDataProtectionPolicy_windows covers the lifecycle of attributes that are
// valid only on Windows: platform defaults, configured values, and reversion to
// defaults when omitted.
func TestAccDataProtectionPolicy_windows(t *testing.T) {
	rName := acctest.RandomResourceName()
	idSame := statecheck.CompareValue(compare.ValuesSame())

	configured := make(map[string]string, len(policyWindowsScopedSettings))
	wanted := make(map[string]knownvalue.Check, len(policyWindowsScopedSettings))
	for _, setting := range policyWindowsScopedSettings {
		configured[setting.attribute] = setting.hcl
		wanted[setting.attribute] = setting.want
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Windows")),
						checkRemotePolicyWindowsSettings(false),
					},
					stateChecksForSettings(policyPlatformScopedDefaults("Windows")),
				),
			},
			{
				Config:           testAccPolicyConfigSettings(rName, "Windows", configured),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enable_ocr"), knownvalue.Null()),
						checkRemotePolicyWindowsSettings(true),
					},
					stateChecksForSettings(wanted),
				),
			},
			{
				Config:           testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						checkRemotePolicyWindowsSettings(false),
					},
					stateChecksForSettings(policyPlatformScopedDefaults("Windows")),
				),
			},
		},
	})
}

// TestAccDataProtectionPolicy_mac covers the Mac platform partition and the
// lifecycle of enable_ocr, the only Mac-specific setting.
func TestAccDataProtectionPolicy_mac(t *testing.T) {
	rName := acctest.RandomResourceName()
	idSame := statecheck.CompareValue(compare.ValuesSame())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Mac"),
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("platform_name"), knownvalue.StringExact("Mac")),
						checkRemotePolicyEnableOCR(true),
					},
					stateChecksForSettings(policyPlatformScopedDefaults("Mac")),
				),
			},
			{
				Config: testAccPolicyConfigSettings(rName, "Mac", map[string]string{
					"enable_ocr": `false`,
				}),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enable_ocr"), knownvalue.Bool(false)),
					checkRemotePolicyEnableOCR(false),
				},
			},
			{
				Config: testAccPolicyConfigMinimal(rName, "Mac"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enable_ocr"), knownvalue.Bool(true)),
					},
				},
				ConfigStateChecks: slices.Concat(
					[]statecheck.StateCheck{
						idSame.AddStateValue(policyResourceName, tfjsonpath.New("id")),
						checkRemotePolicyEnableOCR(true),
					},
					stateChecksForSettings(policyPlatformScopedDefaults("Mac")),
				),
			},
		},
	})
}

// TestAccDataProtectionPolicy_platformSettings_wrongPlatform verifies that every
// platform-scoped attribute is rejected during planning on the other platform.
func TestAccDataProtectionPolicy_platformSettings_wrongPlatform(t *testing.T) {
	rName := acctest.RandomResourceName()

	cases := []struct {
		attribute string
		platform  string
		hcl       string
	}{
		{"screen_capture", "Mac", `true`},
		{"screen_capture_pre_event_seconds", "Mac", `"5"`},
		{"screen_capture_post_event_seconds", "Mac", `"5"`},
		{"evidence_storage", "Mac", `true`},
		{"end_user_encryption_activity", "Mac", `true`},
		{"evidence_storage_max_free_space_percent", "Mac", `50`},
		{"evidence_storage_max_size_gib", "Mac", `10`},
		{"network_inspection", "Mac", `true`},
		{"network_inspection_files_exceeding_size_limit", "Mac", `"block"`},
		{"browsers_without_active_extension", "Mac", `"block_policy"`},
		{"block_all_data_access", "Mac", `true`},
		{"enable_ocr", "Windows", `true`},
	}

	for _, testCase := range cases {
		t.Run(testCase.attribute, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config: testAccPolicyConfigSettings(rName, testCase.platform, map[string]string{
							testCase.attribute: testCase.hcl,
						}),
						PlanOnly: true,
						ExpectError: wrappedErrorRegexp(fmt.Sprintf(
							"%s is not supported on %s policies",
							testCase.attribute, testCase.platform,
						)),
					},
				},
			})
		})
	}
}

// TestAccDataProtectionPolicy_settingDependencies verifies every resource-level
// dependency and the framework behavior for omitted and unknown controller values.
func TestAccDataProtectionPolicy_settingDependencies(t *testing.T) {
	rName := acctest.RandomResourceName()

	cases := []struct {
		name         string
		platform     string
		violated     map[string]string
		omitted      map[string]string
		omittedFires bool
		unknown      map[string]string
		controller   string
		errorText    string
	}{
		{
			name: "similarity_detection_requires_context_inspection", platform: "Windows",
			violated: map[string]string{"similarity_detection": `true`, "context_inspection": `false`},
			omitted:  map[string]string{"similarity_detection": `true`}, omittedFires: false,
			unknown:    map[string]string{"similarity_detection": `true`, "context_inspection": unknownBoolHCL},
			controller: "context_inspection", errorText: "similarity_detection requires context_inspection",
		},
		{
			name: "clipboard_web_origin_requires_context_inspection", platform: "Windows",
			violated: map[string]string{"clipboard_web_origin": `true`, "context_inspection": `false`},
			omitted:  map[string]string{"clipboard_web_origin": `true`}, omittedFires: false,
			unknown:    map[string]string{"clipboard_web_origin": `true`, "context_inspection": unknownBoolHCL},
			controller: "context_inspection", errorText: "clipboard_web_origin requires context_inspection",
		},
		{
			name: "minimum_similarity_threshold_requires_similarity_detection", platform: "Windows",
			violated: map[string]string{"minimum_similarity_threshold": `"50"`, "similarity_detection": `false`},
			omitted:  map[string]string{"minimum_similarity_threshold": `"50"`}, omittedFires: true,
			unknown:    map[string]string{"minimum_similarity_threshold": `"50"`, "similarity_detection": unknownBoolHCL},
			controller: "similarity_detection", errorText: "minimum_similarity_threshold requires similarity_detection",
		},
		{
			name: "inspection_depth_requires_content_inspection", platform: "Windows",
			violated: map[string]string{"inspection_depth": `"deep_scan"`, "content_inspection": `false`},
			omitted:  map[string]string{"inspection_depth": `"deep_scan"`}, omittedFires: false,
			unknown:    map[string]string{"inspection_depth": `"deep_scan"`, "content_inspection": unknownBoolHCL},
			controller: "content_inspection", errorText: "inspection_depth requires content_inspection",
		},
		{
			name: "inspection_confidence_requires_content_inspection", platform: "Windows",
			violated: map[string]string{"inspection_confidence": `"high"`, "content_inspection": `false`},
			omitted:  map[string]string{"inspection_confidence": `"high"`}, omittedFires: false,
			unknown:    map[string]string{"inspection_confidence": `"high"`, "content_inspection": unknownBoolHCL},
			controller: "content_inspection", errorText: "inspection_confidence requires content_inspection",
		},
		{
			name: "block_all_data_access_requires_browsers_without_active_extension", platform: "Windows",
			violated: map[string]string{"block_all_data_access": `true`, "browsers_without_active_extension": `"allow"`},
			omitted:  map[string]string{"block_all_data_access": `true`}, omittedFires: true,
			unknown:    map[string]string{"block_all_data_access": `true`, "browsers_without_active_extension": unknownStringHCL(`"block_policy"`, `"allow"`)},
			controller: "browsers_without_active_extension", errorText: "block_all_data_access requires browsers_without_active_extension",
		},
		{
			name: "enable_ocr_requires_content_inspection", platform: "Mac",
			violated: map[string]string{"enable_ocr": `true`, "content_inspection": `false`},
			omitted:  map[string]string{"enable_ocr": `true`}, omittedFires: false,
			unknown:    map[string]string{"enable_ocr": `true`, "content_inspection": unknownBoolHCL},
			controller: "content_inspection", errorText: "enable_ocr requires content_inspection",
		},
		{
			name: "screen_capture_requires_evidence_storage", platform: "Windows",
			violated: map[string]string{"screen_capture": `true`, "evidence_storage": `false`},
			omitted:  map[string]string{"screen_capture": `true`}, omittedFires: true,
			unknown:    map[string]string{"screen_capture": `true`, "evidence_storage": unknownBoolHCL},
			controller: "evidence_storage", errorText: "screen_capture requires evidence_storage",
		},
		{
			name: "end_user_encryption_activity_requires_evidence_storage", platform: "Windows",
			violated: map[string]string{"end_user_encryption_activity": `true`, "evidence_storage": `false`},
			omitted:  map[string]string{"end_user_encryption_activity": `true`}, omittedFires: true,
			unknown:    map[string]string{"end_user_encryption_activity": `true`, "evidence_storage": unknownBoolHCL},
			controller: "evidence_storage", errorText: "end_user_encryption_activity requires evidence_storage",
		},
		{
			name: "evidence_storage_max_size_gib_requires_evidence_storage", platform: "Windows",
			violated: map[string]string{"evidence_storage_max_size_gib": `10`, "evidence_storage": `false`},
			omitted:  map[string]string{"evidence_storage_max_size_gib": `10`}, omittedFires: true,
			unknown:    map[string]string{"evidence_storage_max_size_gib": `10`, "evidence_storage": unknownBoolHCL},
			controller: "evidence_storage", errorText: "evidence_storage_max_size_gib requires evidence_storage",
		},
		{
			name: "evidence_storage_max_free_space_percent_requires_evidence_storage", platform: "Windows",
			violated: map[string]string{"evidence_storage_max_free_space_percent": `50`, "evidence_storage": `false`},
			omitted:  map[string]string{"evidence_storage_max_free_space_percent": `50`}, omittedFires: true,
			unknown:    map[string]string{"evidence_storage_max_free_space_percent": `50`, "evidence_storage": unknownBoolHCL},
			controller: "evidence_storage", errorText: "evidence_storage_max_free_space_percent requires evidence_storage",
		},
		{
			name: "screen_capture_pre_event_seconds_requires_screen_capture", platform: "Windows",
			violated: map[string]string{"screen_capture_pre_event_seconds": `"5"`, "screen_capture": `false`},
			omitted:  map[string]string{"screen_capture_pre_event_seconds": `"5"`}, omittedFires: true,
			unknown:    map[string]string{"screen_capture_pre_event_seconds": `"5"`, "screen_capture": unknownBoolHCL},
			controller: "screen_capture", errorText: "screen_capture_pre_event_seconds requires screen_capture",
		},
		{
			name: "screen_capture_post_event_seconds_requires_screen_capture", platform: "Windows",
			violated: map[string]string{"screen_capture_post_event_seconds": `"10"`, "screen_capture": `false`},
			omitted:  map[string]string{"screen_capture_post_event_seconds": `"10"`}, omittedFires: true,
			unknown:    map[string]string{"screen_capture_post_event_seconds": `"10"`, "screen_capture": unknownBoolHCL},
			controller: "screen_capture", errorText: "screen_capture_post_event_seconds requires screen_capture",
		},
		{
			name: "network_inspection_files_exceeding_size_limit_requires_network_inspection", platform: "Windows",
			violated: map[string]string{"network_inspection_files_exceeding_size_limit": `"block"`, "network_inspection": `false`},
			omitted:  map[string]string{"network_inspection_files_exceeding_size_limit": `"block"`}, omittedFires: true,
			unknown:    map[string]string{"network_inspection_files_exceeding_size_limit": `"block"`, "network_inspection": unknownBoolHCL},
			controller: "network_inspection", errorText: "network_inspection_files_exceeding_size_limit requires network_inspection",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Run("violated", func(t *testing.T) {
				resource.ParallelTest(t, resource.TestCase{
					ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
					PreCheck:                 func() { acctest.PreCheck(t) },
					Steps: []resource.TestStep{{
						Config:      testAccPolicyConfigSettings(rName, testCase.platform, testCase.violated),
						PlanOnly:    true,
						ExpectError: wrappedErrorRegexp(testCase.errorText),
					}},
				})
			})

			t.Run("controller_omitted", func(t *testing.T) {
				step := resource.TestStep{
					Config:   testAccPolicyConfigSettings(rName, testCase.platform, testCase.omitted),
					PlanOnly: true,
				}
				if testCase.omittedFires {
					step.ExpectError = wrappedErrorRegexp(testCase.errorText)
				} else {
					step.ExpectNonEmptyPlan = true
				}

				resource.ParallelTest(t, resource.TestCase{
					ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
					PreCheck:                 func() { acctest.PreCheck(t) },
					Steps:                    []resource.TestStep{step},
				})
			})

			t.Run("controller_unknown", func(t *testing.T) {
				resource.ParallelTest(t, resource.TestCase{
					ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
					PreCheck:                 func() { acctest.PreCheck(t) },
					Steps: []resource.TestStep{{
						Config:   testAccPolicyConfigUnknownController(rName, testCase.platform, testCase.unknown),
						PlanOnly: true,
						ConfigPlanChecks: resource.ConfigPlanChecks{
							PostApplyPreRefresh: []plancheck.PlanCheck{
								plancheck.ExpectUnknownValue(policyResourceName, tfjsonpath.New(testCase.controller)),
							},
						},
						ExpectNonEmptyPlan: true,
					}},
				})
			})
		})
	}
}

// TestAccDataProtectionPolicy_omittedSettingDrift verifies that an omitted setting
// with a declared default remains managed: an out-of-band change is detected and the
// next apply restores the default.
func TestAccDataProtectionPolicy_omittedSettingDrift(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_upload_timeout_seconds"), knownvalue.Int32Exact(40)),
					mutateRemotePolicySettings(&models.PolicymanagerPolicyProperties{
						BeUploadTimeoutDurationSeconds: 99,
					}),
				},
				ExpectNonEmptyPlan: true,
			},
			{
				Config: testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(policyResourceName, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_upload_timeout_seconds"), knownvalue.Int32Exact(40)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_upload_timeout_seconds"), knownvalue.Int32Exact(40)),
					checkRemotePolicyValue("be_upload_timeout_duration_seconds", int32(40), func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BeUploadTimeoutDurationSeconds
					}),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_clipboardWebOrigin covers the field's custom wire
// handling on create and its false zero value on update.
func TestAccDataProtectionPolicy_clipboardWebOrigin(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"context_inspection":   `true`,
					"clipboard_web_origin": `true`,
				}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("clipboard_web_origin"), knownvalue.Bool(true)),
					checkRemotePolicyClipboardWebOrigin(true),
				},
			},
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"context_inspection":   `true`,
					"clipboard_web_origin": `false`,
				}),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("clipboard_web_origin"), knownvalue.Bool(false)),
					checkRemotePolicyClipboardWebOrigin(false),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_maxFileSize covers the unit-preserving API behavior and
// the resource's converted-byte limit.
func TestAccDataProtectionPolicy_maxFileSize(t *testing.T) {
	t.Run("units", func(t *testing.T) {
		rName := acctest.RandomResourceName()
		cases := []struct {
			size string
			unit string
			want float64
		}{
			{"524288000", "Bytes", 524288000},
			{"524288", "KB", 524288},
			{"524.288", "MB", 524.288},
		}

		steps := make([]resource.TestStep, 0, len(cases))
		for _, testCase := range cases {
			steps = append(steps, resource.TestStep{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"max_file_size":      testCase.size,
					"max_file_size_unit": fmt.Sprintf("%q", testCase.unit),
				}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("max_file_size"), knownvalue.Float64Exact(testCase.want)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("max_file_size_unit"), knownvalue.StringExact(testCase.unit)),
					checkRemotePolicyValue("max_file_size_to_inspect", testCase.want, func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.MaxFileSizeToInspect
					}),
					checkRemotePolicyValue("max_file_size_to_inspect_unit", testCase.unit, func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.MaxFileSizeToInspectUnit
					}),
				},
			})
		}

		resource.ParallelTest(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			PreCheck:                 func() { acctest.PreCheck(t) },
			CheckDestroy:             testAccCheckPolicyDestroy,
			Steps:                    steps,
		})
	})

	t.Run("limit", func(t *testing.T) {
		rName := acctest.RandomResourceName()
		resource.ParallelTest(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			PreCheck:                 func() { acctest.PreCheck(t) },
			Steps: []resource.TestStep{{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"max_file_size":      `525`,
					"max_file_size_unit": `"MB"`,
				}),
				PlanOnly:    true,
				ExpectError: wrappedErrorRegexp("is 525000000 bytes"),
			}},
		})
	})
}

// TestAccDataProtectionPolicy_bePasteClipboardMaxSize covers the unit-dependent
// upper values accepted by Falcon while preserving the configured unit.
func TestAccDataProtectionPolicy_bePasteClipboardMaxSize(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"be_paste_clipboard_max_size":      `64`,
					"be_paste_clipboard_max_size_unit": `"KiB"`,
				}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_paste_clipboard_max_size"), knownvalue.Float64Exact(64)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_paste_clipboard_max_size_unit"), knownvalue.StringExact("KiB")),
					checkRemotePolicyValue("be_paste_clipboard_max_size", float64(64), func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BePasteClipboardMaxSize
					}),
					checkRemotePolicyValue("be_paste_clipboard_max_size_unit", "KiB", func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BePasteClipboardMaxSizeUnit
					}),
				},
			},
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"be_paste_clipboard_max_size":      `65536`,
					"be_paste_clipboard_max_size_unit": `"Bytes"`,
				}),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_paste_clipboard_max_size"), knownvalue.Float64Exact(65536)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("be_paste_clipboard_max_size_unit"), knownvalue.StringExact("Bytes")),
					checkRemotePolicyValue("be_paste_clipboard_max_size", float64(65536), func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BePasteClipboardMaxSize
					}),
					checkRemotePolicyValue("be_paste_clipboard_max_size_unit", "Bytes", func(p *models.PolicymanagerExternalPolicy) any {
						if p.PolicyProperties == nil {
							return nil
						}
						return p.PolicyProperties.BePasteClipboardMaxSizeUnit
					}),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_eujCustomHeaderText covers the custom header's special
// create behavior, its import round trip, and changing then removing it.
func TestAccDataProtectionPolicy_eujCustomHeaderText(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"euj_custom_header_text": `"Explain why you need this file."`,
				}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_header_text"), knownvalue.StringExact("Explain why you need this file.")),
					checkRemotePolicyEujHeader("Explain why you need this file."),
					checkRemotePolicyModified(true),
				},
			},
			policyImportStep,
			{
				Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
					"euj_custom_header_text": `"Provide a business justification."`,
				}),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_header_text"), knownvalue.StringExact("Provide a business justification.")),
					checkRemotePolicyEujHeader("Provide a business justification."),
				},
			},
			{
				Config:           testAccPolicyConfigMinimal(rName, "Windows"),
				ConfigPlanChecks: policyInPlaceUpdate,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyResourceName, tfjsonpath.New("euj_custom_header_text"), knownvalue.Null()),
					checkRemotePolicyEujHeader(""),
				},
			},
		},
	})
}

// TestAccDataProtectionPolicy_eujDropdownOptions verifies the minimum number of
// enabled justification choices. The normal add/remove lifecycle and the shared wire
// representation are exercised by the main update test.
func TestAccDataProtectionPolicy_eujDropdownOptions(t *testing.T) {
	rName := acctest.RandomResourceName()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{{
			Config: testAccPolicyConfigSettings(rName, "Windows", map[string]string{
				"euj_business_purposes_enabled": `false`,
			}),
			PlanOnly:    true,
			ExpectError: wrappedErrorRegexp("dialog offers 1 option(s), but Falcon requires at least 2"),
		}},
	})
}

// testAccPolicyConfigMinimal builds a policy with only its required attributes.
func testAccPolicyConfigMinimal(name, platform string) string {
	return testAccPolicyConfigSettings(name, platform, nil)
}

// testAccPolicyConfigHostGroups builds a Windows policy, creates the referenced
// host groups in the same configuration, and writes the policy references in the
// supplied order.
func testAccPolicyConfigHostGroups(name string, order []int, settings map[string]string) string {
	count := 0
	for _, index := range order {
		if index+1 > count {
			count = index + 1
		}
	}

	var groups strings.Builder
	for i := range count {
		fmt.Fprintf(&groups, `
resource "crowdstrike_host_group" "test-%[2]d" {
  name        = "%[1]s-%[2]d"
  description = "host group for data protection policy acceptance tests"
  type        = "staticByID"
  host_ids    = []
}
`, name, i)
	}

	values := maps.Clone(settings)
	if values == nil {
		values = make(map[string]string)
	}
	if len(order) > 0 {
		var refs strings.Builder
		for _, index := range order {
			fmt.Fprintf(&refs, "    crowdstrike_host_group.test-%d.id,\n", index)
		}
		values["host_groups"] = fmt.Sprintf("[\n%s  ]", refs.String())
	}

	return groups.String() + testAccPolicyConfigSettings(name, "Windows", values)
}

// testAccPolicyConfigClassifications builds a Windows policy assigned the given
// classification IDs. Passing none omits the attribute.
func testAccPolicyConfigClassifications(name string, classificationIDs []string) string {
	settings := map[string]string{}
	if len(classificationIDs) > 0 {
		settings["classifications"] = hclStringList(classificationIDs)
	}
	return testAccPolicyConfigSettings(name, "Windows", settings)
}

func hclStringList(values []string) string {
	var body strings.Builder
	body.WriteString("[")
	for i, value := range values {
		if i > 0 {
			body.WriteString(", ")
		}
		fmt.Fprintf(&body, "%q", value)
	}
	body.WriteString("]")
	return body.String()
}

// unknownBoolHCL is unknown during planning because it depends on a host group that
// has not been created yet.
const unknownBoolHCL = `length(crowdstrike_host_group.test.id) > 0`

func unknownStringHCL(whenTrue, whenFalse string) string {
	return fmt.Sprintf("%s ? %s : %s", unknownBoolHCL, whenTrue, whenFalse)
}

// testAccPolicyConfigSettings builds a policy from raw HCL attribute values.
func testAccPolicyConfigSettings(name, platform string, settings map[string]string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_data_protection_policy" "test" {
  platform_name = %[2]q
  name          = %[1]q
%[3]s}
`, name, platform, renderPolicySettings(settings))
}

// testAccPolicyConfigUnknownController adds a host group so expressions that depend
// on its ID are unknown when the policy configuration is validated.
func testAccPolicyConfigUnknownController(name, platform string, settings map[string]string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "%[1]s-controller"
  description = "host group for data protection policy acceptance tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_data_protection_policy" "test" {
  platform_name = %[2]q
  name          = %[1]q
%[3]s}
`, name, platform, renderPolicySettings(settings))
}

// renderPolicySettings emits the attribute lines for a settings map, sorted by
// attribute name so the generated configuration is stable from run to run. An empty
// value omits the attribute entirely, which is how the collection helpers express
// "no host groups" and "no classifications": for a Terraform-owned collection,
// omission and not an empty list is the way to say empty.
func renderPolicySettings(settings map[string]string) string {
	var body strings.Builder
	for _, attribute := range slices.Sorted(maps.Keys(settings)) {
		if settings[attribute] == "" {
			continue
		}
		fmt.Fprintf(&body, "  %s = %s\n", attribute, settings[attribute])
	}

	return body.String()
}

// createTestClassifications creates count data protection classifications through
// the API and returns their IDs. Classifications have no Terraform resource, so
// creating them directly is the only way to obtain real IDs to assign, and a
// nonexistent ID makes the policy API answer 500 rather than reject the request.
//
// They are removed once the test finishes, which happens after the policy that
// references them has been destroyed.
func createTestClassifications(t *testing.T, prefix string, count int) []string {
	t.Helper()

	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("Acceptance tests skipped unless %s is set", resource.EnvTfAcc)
	}

	// PreCheck initializes the shared client, which the fixture needs before the
	// test steps run.
	acctest.PreCheck(t)

	ctx := context.Background()
	conn := testconfig.GetTestClient()

	resources := make([]*models.PolicymanagerExternalClassificationPost, 0, count)
	for i := range count {
		resources = append(resources, &models.PolicymanagerExternalClassificationPost{
			Name: utils.Addr(fmt.Sprintf("%s-classification-%d", prefix, i)),
		})
	}

	res, err := conn.DataProtectionConfiguration.EntitiesClassificationPostV2(
		data_protection_configuration.NewEntitiesClassificationPostV2Params().
			WithContext(ctx).
			WithBody(&models.PolicymanagerCreateClassificationsRequest{Resources: resources}),
	)
	if err != nil {
		t.Fatalf("creating test classifications: %s", err)
	}
	if res == nil || res.Payload == nil {
		t.Fatal("creating test classifications: empty response")
	}

	ids := make([]string, 0, count)
	for _, classification := range res.Payload.Resources {
		if classification == nil || classification.ID == nil {
			continue
		}
		ids = append(ids, *classification.ID)
	}
	if len(ids) != count {
		t.Fatalf("creating test classifications: wanted %d ids, got %d", count, len(ids))
	}

	t.Cleanup(func() {
		if _, err := conn.DataProtectionConfiguration.EntitiesClassificationDeleteV2(
			data_protection_configuration.NewEntitiesClassificationDeleteV2Params().
				WithContext(context.Background()).
				WithIds(ids),
		); err != nil {
			t.Errorf("cleaning up test classifications %v: %s", ids, err)
		}
	})

	return ids
}

// getPolicyByID reads one policy. The endpoint answers a deleted ID with HTTP 200
// and a payload error of code 404, so absence is detected from the payload.
func getPolicyByID(ctx context.Context, id string) (*models.PolicymanagerExternalPolicy, error) {
	conn := testconfig.GetTestClient()
	params := data_protection_configuration.NewEntitiesPolicyGetV2Params().
		WithContext(ctx).
		WithIds([]string{id})

	res, err := conn.DataProtectionConfiguration.EntitiesPolicyGetV2(params)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Payload == nil {
		return nil, nil
	}

	for _, policy := range res.Payload.Resources {
		if policy != nil && policy.ID != nil && *policy.ID == id {
			return policy, nil
		}
	}

	return nil, nil
}

// policyIDFromState reads the ID of the policy under test out of the state.
func policyIDFromState(state *tfjson.State) (string, error) {
	resource, err := policyStateResource(state)
	if err != nil {
		return "", err
	}

	id, ok := resource.AttributeValues["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("no id found for %s", policyResourceName)
	}

	return id, nil
}

// policyStateResource finds the state entry for the policy under test.
func policyStateResource(state *tfjson.State) (*tfjson.StateResource, error) {
	if state == nil || state.Values == nil || state.Values.RootModule == nil {
		return nil, fmt.Errorf("no state available")
	}

	for _, resource := range state.Values.RootModule.Resources {
		if resource.Address == policyResourceName {
			return resource, nil
		}
	}

	return nil, fmt.Errorf("not found in state: %s", policyResourceName)
}

// checkRemotePolicyExists verifies that the policy tracked in Terraform state exists in Falcon.
func checkRemotePolicyExists() statecheck.StateCheck {
	return remotePolicyCheck{
		description: "existence",
		check:       func(*tfjson.StateResource, *models.PolicymanagerExternalPolicy) error { return nil },
	}
}

// remotePolicyCheck runs an assertion against the live policy associated with the
// Terraform state resource.
type remotePolicyCheck struct {
	description string
	check       func(*tfjson.StateResource, *models.PolicymanagerExternalPolicy) error
}

func (c remotePolicyCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	id, err := policyIDFromState(req.State)
	if err != nil {
		resp.Error = err
		return
	}

	stateResource, err := policyStateResource(req.State)
	if err != nil {
		resp.Error = err
		return
	}

	policy, err := getPolicyByID(ctx, id)
	if err != nil {
		resp.Error = fmt.Errorf("reading data protection policy %s: %w", id, err)
		return
	}
	if policy == nil {
		resp.Error = fmt.Errorf("data protection policy %s not found via API", id)
		return
	}

	if err := c.check(stateResource, policy); err != nil {
		resp.Error = fmt.Errorf("data protection policy %s: %s: %w", id, c.description, err)
	}
}

func terraformValuesEqual(got, want any) bool {
	if reflect.DeepEqual(got, want) {
		return true
	}

	gotJSON, gotErr := json.Marshal(got)
	wantJSON, wantErr := json.Marshal(want)
	return gotErr == nil && wantErr == nil && string(gotJSON) == string(wantJSON)
}

func checkRemotePolicyValue(
	name string,
	want any,
	get func(*models.PolicymanagerExternalPolicy) any,
) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote " + name,
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			got := get(policy)
			if !reflect.DeepEqual(got, want) {
				return fmt.Errorf("expected %v, got %v", want, got)
			}
			return nil
		},
	}
}

func checkRemotePolicyValueMatchesState(
	attribute string,
	get func(*models.PolicymanagerExternalPolicy) any,
) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote " + attribute,
		check: func(stateResource *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			want, ok := stateResource.AttributeValues[attribute]
			if !ok {
				return fmt.Errorf("Terraform state has no %s attribute", attribute)
			}

			got := get(policy)
			if !terraformValuesEqual(got, want) {
				return fmt.Errorf("expected to match Terraform state value %v, got %v", want, got)
			}
			return nil
		},
	}
}

// checkRemotePolicyEujHeader asserts the remote euj_header_text. wantCustom is the text that
// must be present and selected in the custom slot, or "" when Falcon's built-in header
// must be the selected one instead.
//
// It deliberately never asserts the built-in sentence itself, only that the API
// reported one. The provider reads that sentence from the API rather than holding a
// constant, so pinning it here would recreate exactly the coupling this design
// avoids, and the test would fail the day Falcon rewords the message even though the
// provider handled it correctly.
func checkRemotePolicyEujHeader(wantCustom string) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote euj_header_text",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			if policy.PolicyProperties == nil {
				return errors.New("the API returned no policy_properties")
			}

			headerText := policy.PolicyProperties.EujHeaderText
			if headerText == nil {
				return errors.New("the API returned no euj_header_text")
			}
			if len(headerText.Headers) != 2 {
				return fmt.Errorf("expected exactly 2 headers, got %d", len(headerText.Headers))
			}

			builtin, custom := headerText.Headers[0], headerText.Headers[1]
			if builtin == nil || custom == nil {
				return errors.New("the API returned a nil header entry")
			}
			if builtin.Header == nil || *builtin.Header == "" {
				return errors.New("the API reported no built-in header text in headers[0]")
			}
			if builtin.Selected == nil || custom.Selected == nil {
				return errors.New("the API returned a header with no selected flag")
			}

			if wantCustom == "" {
				if !*builtin.Selected {
					return errors.New("expected the built-in header to be selected")
				}
				return nil
			}

			if !*custom.Selected {
				return errors.New("expected the custom header to be selected")
			}
			if custom.Header == nil || *custom.Header != wantCustom {
				return fmt.Errorf("expected custom header %q, got %v", wantCustom, custom.Header)
			}

			return nil
		},
	}
}

// checkRemotePolicyEujOptions asserts the remote euj_dropdown_options array. The two
// built-ins must occupy slots 0 and 1, in that order, carrying the selection flags
// the two boolean attributes control; every later slot is a custom option and must
// match wantCustom in order.
//
// It deliberately asserts the whole array rather than one slot at a time. Three
// Terraform attributes share this one wire field and the provider rebuilds it in
// full on every write, so a bug here shows up as a wrong shape, not a wrong scalar.
func checkRemotePolicyEujOptions(businessPurposes, personalUse bool, wantCustom []string) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote euj_dropdown_options",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			if policy.PolicyProperties == nil {
				return errors.New("the API returned no policy_properties")
			}

			options := policy.PolicyProperties.EujDropdownOptions
			if options == nil {
				return errors.New("the API returned no euj_dropdown_options")
			}

			wantLen := 2 + len(wantCustom)
			if len(options.Justifications) != wantLen {
				return fmt.Errorf(
					"expected %d justifications, got %d",
					wantLen, len(options.Justifications),
				)
			}

			builtins := []struct {
				text     string
				selected bool
			}{
				{"Business purposes", businessPurposes},
				{"Personal use", personalUse},
			}
			for i, builtin := range builtins {
				option := options.Justifications[i]
				if option == nil || option.Justification == nil || option.Selected == nil {
					return fmt.Errorf("justification %d is missing text or selection", i)
				}
				if *option.Justification != builtin.text {
					return fmt.Errorf(
						"justification %d: expected the built-in %q, got %q",
						i, builtin.text, *option.Justification,
					)
				}
				if *option.Selected != builtin.selected {
					return fmt.Errorf(
						"justification %d (%s): expected selected %t, got %t",
						i, builtin.text, builtin.selected, *option.Selected,
					)
				}
			}

			for i, want := range wantCustom {
				option := options.Justifications[i+2]
				if option == nil || option.Justification == nil || option.Selected == nil {
					return fmt.Errorf("custom justification %d is missing text or selection", i)
				}
				if *option.Justification != want {
					return fmt.Errorf(
						"custom justification %d: expected %q, got %q",
						i, want, *option.Justification,
					)
				}
				if !*option.Selected {
					return fmt.Errorf("custom justification %d (%s): expected selected true", i, want)
				}
			}

			return nil
		},
	}
}

// policyScopedSetting describes one Windows-only setting and the wire values
// expected when configured and when omitted.
type policyScopedSetting struct {
	attribute   string
	hcl         string
	want        knownvalue.Check
	wireField   string
	wireWanted  any
	wireDefault any
	get         func(properties *models.PolicymanagerPolicyProperties) any
}

// The configured values satisfy the dependencies among the Windows-only settings,
// so the whole group can be exercised in one lifecycle test.
var policyWindowsScopedSettings = []policyScopedSetting{
	{
		"browsers_without_active_extension", `"block_policy"`, knownvalue.StringExact("block_policy"),
		"browsers_without_active_extension", "block_policy", "allow",
		func(p *models.PolicymanagerPolicyProperties) any { return p.BrowsersWithoutActiveExtension },
	},
	{
		"block_all_data_access", `true`, knownvalue.Bool(true),
		"block_all_data_access", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.BlockAllDataAccess) },
	},
	{
		"evidence_storage", `true`, knownvalue.Bool(true),
		"evidence_download_enabled", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EvidenceDownloadEnabled) },
	},
	{
		"end_user_encryption_activity", `true`, knownvalue.Bool(true),
		"evidence_encrypted_enabled", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EvidenceEncryptedEnabled) },
	},
	{
		"evidence_storage_max_free_space_percent", `50`, knownvalue.Float64Exact(50),
		"evidence_storage_free_disk_perc", float64(50), float64(2),
		func(p *models.PolicymanagerPolicyProperties) any { return p.EvidenceStorageFreeDiskPerc },
	},
	{
		"evidence_storage_max_size_gib", `10`, knownvalue.Float64Exact(10),
		"evidence_storage_max_size", float64(10), float64(1),
		func(p *models.PolicymanagerPolicyProperties) any { return p.EvidenceStorageMaxSize },
	},
	{
		"screen_capture", `true`, knownvalue.Bool(true),
		"enable_screen_capture", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return p.EnableScreenCapture },
	},
	{
		"screen_capture_pre_event_seconds", `"5"`, knownvalue.StringExact("5"),
		"screen_capture_duration_pre_event", "5", "3",
		func(p *models.PolicymanagerPolicyProperties) any { return p.ScreenCaptureDurationPreEvent },
	},
	{
		"screen_capture_post_event_seconds", `"10"`, knownvalue.StringExact("10"),
		"screen_capture_duration_post_event", "10", "3",
		func(p *models.PolicymanagerPolicyProperties) any { return p.ScreenCaptureDurationPostEvent },
	},
	{
		"network_inspection", `true`, knownvalue.Bool(true),
		"enable_network_inspection", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EnableNetworkInspection) },
	},
	{
		"network_inspection_files_exceeding_size_limit", `"block"`, knownvalue.StringExact("block"),
		"network_inspection_files_exceeding_size_limit", "block", "allow",
		func(p *models.PolicymanagerPolicyProperties) any { return p.NetworkInspectionFilesExceedingSizeLimit },
	},
}

func checkRemotePolicyWindowsSettings(configured bool) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote Windows settings",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			if policy.PolicyProperties == nil {
				return errors.New("the API returned no policy_properties")
			}

			for _, setting := range policyWindowsScopedSettings {
				want := setting.wireDefault
				if configured {
					want = setting.wireWanted
				}
				if got := setting.get(policy.PolicyProperties); !reflect.DeepEqual(got, want) {
					return fmt.Errorf("%s: expected %v, got %v", setting.wireField, want, got)
				}
			}
			return nil
		},
	}
}

// The two justification logos, as the base64 PNG data URIs the attribute requires.
// Both are 1x1 pixels: the schema bounds the encoded length and the data-URI prefix
// but nothing here depends on the image content, only on the two values differing so
// the change step is a real change.
const (
	policyTransparentLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII="
	policyRedLogo         = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DQAAAEgQGALFXOsAAAAABJRU5ErkJggg=="
)

// checkRemotePolicyModified asserts whether the API has ever recorded a modification
// to the policy, which is how the suite tells a create that stood on its own from one
// the provider had to follow with an update. The API leaves modified_at unset until
// the first patch.
//
// The resource exposes no modified_at attribute, deliberately: it is Falcon's own
// bookkeeping rather than anything a practitioner configures. Asserting it against
// the live policy is also the stronger form, since a state mirror could only ever
// report what the provider chose to write.
func checkRemotePolicyModified(want bool) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote modified_at",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			modified := policy.ModifiedAt != nil && *policy.ModifiedAt != ""
			if modified != want {
				return fmt.Errorf(
					"expected the policy to have been modified=%t, got modified=%t (modified_at %v)",
					want, modified, policy.ModifiedAt,
				)
			}
			return nil
		},
	}
}

// checkRemotePolicyDescription asserts the description the API actually holds.
// Terraform state alone cannot distinguish a cleared description from one the API silently
// preserved, because both canonicalize to null on the way back in.
func checkRemotePolicyDescription(want string) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote description",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			got := ""
			if policy.Description != nil {
				got = *policy.Description
			}
			if got != want {
				return fmt.Errorf("expected %q, got %q", want, got)
			}
			return nil
		},
	}
}

// checkRemotePolicyHostGroupCount asserts how many host groups the API actually
// holds. Terraform state alone cannot distinguish a detached collection from one the API
// silently preserved, because the API answers an empty host_groups with null and
// flex canonicalizes that to a null set either way.
func checkRemotePolicyHostGroupCount(want int) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote host_groups",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			if len(policy.HostGroups) != want {
				return fmt.Errorf("expected %d host groups, got %d: %v", want, len(policy.HostGroups), policy.HostGroups)
			}
			return nil
		},
	}
}

// checkRemotePolicyClassifications asserts the classifications the API actually
// holds, ignoring order.
func checkRemotePolicyClassifications(want []string) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote classifications",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			var got []string
			if policy.PolicyProperties != nil {
				got = policy.PolicyProperties.Classifications
			}

			if len(got) != len(want) {
				return fmt.Errorf("expected %d classifications %v, got %d: %v", len(want), want, len(got), got)
			}
			for _, id := range want {
				if !slices.Contains(got, id) {
					return fmt.Errorf("expected classification %s to be assigned, got %v", id, got)
				}
			}
			return nil
		},
	}
}

// deleteRemotePolicyCheck performs an out-of-band deletion. The policy under
// test is disabled, so no disable call is needed.
type deleteRemotePolicyCheck struct{}

func (c deleteRemotePolicyCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	id, err := policyIDFromState(req.State)
	if err != nil {
		resp.Error = err
		return
	}

	resource, err := policyStateResource(req.State)
	if err != nil {
		resp.Error = err
		return
	}

	platform, ok := resource.AttributeValues["platform_name"].(string)
	if !ok {
		resp.Error = fmt.Errorf("no platform_name found for %s", policyResourceName)
		return
	}

	conn := testconfig.GetTestClient()
	params := data_protection_configuration.NewEntitiesPolicyDeleteV2Params().
		WithContext(ctx).
		WithPlatformName(testAccWirePlatform(platform)).
		WithIds([]string{id})

	// The delete endpoint answers concurrent deletes with a 500 even when the
	// policy was in fact removed, so the outcome is confirmed by a read rather
	// than taken from the status code.
	_, deleteErr := conn.DataProtectionConfiguration.EntitiesPolicyDeleteV2(params)

	policy, err := getPolicyByID(ctx, id)
	if err != nil {
		resp.Error = fmt.Errorf("confirming deletion of data protection policy %s: %w", id, err)
		return
	}
	if policy != nil {
		resp.Error = fmt.Errorf("data protection policy %s was not deleted: %w", id, deleteErr)
	}
}

func deleteRemotePolicy() statecheck.StateCheck {
	return deleteRemotePolicyCheck{}
}

// testAccWirePlatform translates a practitioner-facing platform value into the
// wire value the query parameter requires. The test package deliberately keeps
// its own copy so the tests assert against the API rather than against the
// provider's own translation.
func testAccWirePlatform(platform string) string {
	if platform == "Mac" {
		return "mac"
	}
	return "win"
}

// policySharedSetting declares a shared setting's default, configured value, and
// wire mapping once. The main update test derives both configuration and assertions
// from this table.
type policySharedSetting struct {
	attribute        string
	defaultState     knownvalue.Check
	configuredHCL    string
	configuredState  knownvalue.Check
	wireField        string
	defaultRemote    any
	configuredRemote any
	get              func(properties *models.PolicymanagerPolicyProperties) any
}

// context_inspection and content_inspection stay true in the populated state because
// other settings in the same configuration depend on them. Their dependency behavior
// is covered separately.
var policySharedSettings = []policySharedSetting{
	{
		"context_inspection", knownvalue.Bool(true), `true`, knownvalue.Bool(true),
		"enable_context_inspection", true, true,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EnableContextInspection) },
	},
	{
		"content_inspection", knownvalue.Bool(true), `true`, knownvalue.Bool(true),
		"enable_content_inspection", true, true,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EnableContentInspection) },
	},
	{
		"clipboard_inspection", knownvalue.Bool(false), `true`, knownvalue.Bool(true),
		"enable_clipboard_inspection", false, true,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EnableClipboardInspection) },
	},
	{
		"clipboard_web_origin", knownvalue.Bool(false), `true`, knownvalue.Bool(true),
		"enable_clipboard_web_origin", false, true, nil,
	},
	{
		"similarity_detection", knownvalue.Bool(false), `true`, knownvalue.Bool(true),
		"similarity_detection", false, true,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.SimilarityDetection) },
	},
	{
		"minimum_similarity_threshold", knownvalue.StringExact("80"), `"50"`, knownvalue.StringExact("50"),
		"similarity_threshold", "80", "50",
		func(p *models.PolicymanagerPolicyProperties) any { return p.SimilarityThreshold },
	},
	{
		"inspection_depth", knownvalue.StringExact("balanced"), `"deep_scan"`, knownvalue.StringExact("deep_scan"),
		"inspection_depth", "balanced", "deep_scan",
		func(p *models.PolicymanagerPolicyProperties) any { return p.InspectionDepth },
	},
	{
		"inspection_confidence", knownvalue.StringExact("medium"), `"high"`, knownvalue.StringExact("high"),
		"min_confidence_level", "medium", "high",
		func(p *models.PolicymanagerPolicyProperties) any { return p.MinConfidenceLevel },
	},
	{
		"max_file_size", knownvalue.Float64Exact(104857600), `512`, knownvalue.Float64Exact(512),
		"max_file_size_to_inspect", float64(104857600), float64(512),
		func(p *models.PolicymanagerPolicyProperties) any { return p.MaxFileSizeToInspect },
	},
	{
		"max_file_size_unit", knownvalue.StringExact("Bytes"), `"KB"`, knownvalue.StringExact("KB"),
		"max_file_size_to_inspect_unit", "Bytes", "KB",
		func(p *models.PolicymanagerPolicyProperties) any { return p.MaxFileSizeToInspectUnit },
	},
	{
		"be_splash_screen", knownvalue.Bool(true), `false`, knownvalue.Bool(false),
		"be_splash_enabled", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.BeSplashEnabled) },
	},
	{
		"be_upload_timeout_seconds", knownvalue.Int32Exact(40), `90`, knownvalue.Int32Exact(90),
		"be_upload_timeout_duration_seconds", int32(40), int32(90),
		func(p *models.PolicymanagerPolicyProperties) any { return p.BeUploadTimeoutDurationSeconds },
	},
	{
		"be_upload_timeout_response", knownvalue.StringExact("allow"), `"block"`, knownvalue.StringExact("block"),
		"be_upload_timeout_response", "allow", "block",
		func(p *models.PolicymanagerPolicyProperties) any { return p.BeUploadTimeoutResponse },
	},
	{
		"be_paste_timeout_milliseconds", knownvalue.Int32Exact(800), `1500`, knownvalue.Int32Exact(1500),
		"be_paste_timeout_duration_milliseconds", int32(800), int32(1500),
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteTimeoutDurationMilliseconds },
	},
	{
		"be_paste_timeout_response", knownvalue.StringExact("allow"), `"block"`, knownvalue.StringExact("block"),
		"be_paste_timeout_response", "allow", "block",
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteTimeoutResponse },
	},
	{
		"be_paste_clipboard_min_size", knownvalue.Float64Exact(32), `0.5`, knownvalue.Float64Exact(0.5),
		"be_paste_clipboard_min_size", float64(32), float64(0.5),
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteClipboardMinSize },
	},
	{
		"be_paste_clipboard_min_size_unit", knownvalue.StringExact("Bytes"), `"KiB"`, knownvalue.StringExact("KiB"),
		"be_paste_clipboard_min_size_unit", "Bytes", "KiB",
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteClipboardMinSizeUnit },
	},
	{
		"be_paste_clipboard_max_size", knownvalue.Float64Exact(0.0625), `4096`, knownvalue.Float64Exact(4096),
		"be_paste_clipboard_max_size", float64(0.0625), float64(4096),
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteClipboardMaxSize },
	},
	{
		"be_paste_clipboard_max_size_unit", knownvalue.StringExact("KiB"), `"Bytes"`, knownvalue.StringExact("Bytes"),
		"be_paste_clipboard_max_size_unit", "KiB", "Bytes",
		func(p *models.PolicymanagerPolicyProperties) any { return p.BePasteClipboardMaxSizeUnit },
	},
	{
		"be_paste_clipboard_block_over_max_size", knownvalue.Bool(false), `true`, knownvalue.Bool(true),
		"be_paste_clipboard_over_size_behaviour_block", false, true,
		func(p *models.PolicymanagerPolicyProperties) any {
			return deref(p.BePasteClipboardOverSizeBehaviourBlock)
		},
	},
	{
		"euj_require_additional_details", knownvalue.Bool(true), `false`, knownvalue.Bool(false),
		"euj_require_additional_details", true, false,
		func(p *models.PolicymanagerPolicyProperties) any { return deref(p.EujRequireAdditionalDetails) },
	},
	{
		"euj_dialog_timeout", knownvalue.Int32Exact(120), `300`, knownvalue.Int32Exact(300),
		"euj_dialog_timeout", int32(120), int32(300),
		func(p *models.PolicymanagerPolicyProperties) any { return p.EujDialogTimeout },
	},
}

func policySharedSettingsHCL() map[string]string {
	settings := make(map[string]string, len(policySharedSettings))
	for _, setting := range policySharedSettings {
		settings[setting.attribute] = setting.configuredHCL
	}
	return settings
}

func stateChecksForSharedSettings(configured bool) []statecheck.StateCheck {
	checks := make([]statecheck.StateCheck, 0, len(policySharedSettings))
	for _, setting := range policySharedSettings {
		want := setting.defaultState
		if configured {
			want = setting.configuredState
		}
		checks = append(checks, statecheck.ExpectKnownValue(
			policyResourceName, tfjsonpath.New(setting.attribute), want,
		))
	}
	return checks
}

func checkRemotePolicySharedSettings(configured bool) statecheck.StateCheck {
	return remotePolicyCheck{
		description: "remote shared settings",
		check: func(_ *tfjson.StateResource, policy *models.PolicymanagerExternalPolicy) error {
			if policy.PolicyProperties == nil {
				return errors.New("the API returned no policy_properties")
			}

			for _, setting := range policySharedSettings {
				if setting.get == nil {
					continue
				}
				want := setting.defaultRemote
				if configured {
					want = setting.configuredRemote
				}
				if got := setting.get(policy.PolicyProperties); !reflect.DeepEqual(got, want) {
					return fmt.Errorf("%s: expected %v, got %v", setting.wireField, want, got)
				}
			}
			return nil
		},
	}
}

// policyPlatformScopedDefaults is the expected state when platform-scoped settings
// are omitted. Windows-only settings are null on Mac; enable_ocr is null on Windows.
func policyPlatformScopedDefaults(platform string) map[string]knownvalue.Check {
	windows := map[string]knownvalue.Check{
		"browsers_without_active_extension":             knownvalue.StringExact("allow"),
		"block_all_data_access":                         knownvalue.Bool(false),
		"screen_capture":                                knownvalue.Bool(false),
		"screen_capture_pre_event_seconds":              knownvalue.StringExact("3"),
		"screen_capture_post_event_seconds":             knownvalue.StringExact("3"),
		"evidence_storage":                              knownvalue.Bool(false),
		"end_user_encryption_activity":                  knownvalue.Bool(false),
		"evidence_storage_max_free_space_percent":       knownvalue.Float64Exact(2),
		"evidence_storage_max_size_gib":                 knownvalue.Float64Exact(1),
		"network_inspection":                            knownvalue.Bool(false),
		"network_inspection_files_exceeding_size_limit": knownvalue.StringExact("allow"),
		"enable_ocr":                                    knownvalue.Null(),
	}

	if platform == "Windows" {
		return windows
	}

	mac := make(map[string]knownvalue.Check, len(windows))
	for attribute := range windows {
		mac[attribute] = knownvalue.Null()
	}
	mac["enable_ocr"] = knownvalue.Bool(true)
	return mac
}

// stateChecksForSettings turns a map of expected values into deterministic state
// checks, used for the platform-scoped defaults and configured Windows values.
func stateChecksForSettings(values map[string]knownvalue.Check) []statecheck.StateCheck {
	checks := make([]statecheck.StateCheck, 0, len(values))
	for _, attribute := range slices.Sorted(maps.Keys(values)) {
		checks = append(checks, statecheck.ExpectKnownValue(
			policyResourceName, tfjsonpath.New(attribute), values[attribute],
		))
	}
	return checks
}

// wrappedErrorRegexp matches a phrase in Terraform's diagnostic output across the
// line wrapping it applies to long messages. Terraform breaks diagnostics at word
// boundaries, so the words are matched with any whitespace between them.
func wrappedErrorRegexp(phrase string) *regexp.Regexp {
	words := strings.Fields(phrase)
	for i, word := range words {
		words[i] = regexp.QuoteMeta(word)
	}

	return regexp.MustCompile(`(?s)` + strings.Join(words, `\s+`))
}

// deref renders a pointer field as a comparable value, so a setting the API
// omitted entirely reports as absent rather than as the zero value.
func deref[T any](value *T) any {
	if value == nil {
		return nil
	}

	return *value
}

// patchPolicyOutOfBand applies a partial patch using the policy identity, platform,
// and enablement already present in Terraform state.
func patchPolicyOutOfBand(
	ctx context.Context,
	state *tfjson.State,
	patch *models.PolicymanagerExternalPolicyPatch,
) error {
	id, err := policyIDFromState(state)
	if err != nil {
		return err
	}
	stateResource, err := policyStateResource(state)
	if err != nil {
		return err
	}
	platform, ok := stateResource.AttributeValues["platform_name"].(string)
	if !ok {
		return fmt.Errorf("no platform_name found for %s", policyResourceName)
	}
	enabled, ok := stateResource.AttributeValues["enabled"].(bool)
	if !ok {
		return fmt.Errorf("no enabled found for %s", policyResourceName)
	}

	patch.ID = &id
	patch.IsEnabled = utils.Addr(enabled)

	conn := testconfig.GetTestClient()
	params := data_protection_configuration.NewEntitiesPolicyPatchV2Params().
		WithContext(ctx).
		WithPlatformName(testAccWirePlatform(platform)).
		WithBody(&models.PolicymanagerUpdatePoliciesRequest{
			Resources: []*models.PolicymanagerExternalPolicyPatch{patch},
		})

	res, err := conn.DataProtectionConfiguration.EntitiesPolicyPatchV2(params)
	if err != nil {
		return fmt.Errorf("changing data protection policy %s out-of-band: %w", id, err)
	}
	if res == nil || res.Payload == nil {
		return fmt.Errorf("changing data protection policy %s out-of-band: empty response", id)
	}
	if len(res.Payload.Errors) > 0 {
		return fmt.Errorf("changing data protection policy %s out-of-band: %v", id, res.Payload.Errors[0])
	}
	return nil
}

// mutateRemotePolicySettingsCheck performs an out-of-band settings mutation.
type mutateRemotePolicySettingsCheck struct {
	properties *models.PolicymanagerPolicyProperties
}

func (c mutateRemotePolicySettingsCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	resp.Error = patchPolicyOutOfBand(ctx, req.State, &models.PolicymanagerExternalPolicyPatch{
		PolicyProperties: c.properties,
	})
}

func mutateRemotePolicySettings(properties *models.PolicymanagerPolicyProperties) statecheck.StateCheck {
	return mutateRemotePolicySettingsCheck{properties: properties}
}

type reorderRemotePolicyHostGroupsCheck struct{}

func (reorderRemotePolicyHostGroupsCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	id, err := policyIDFromState(req.State)
	if err != nil {
		resp.Error = err
		return
	}
	policy, err := getPolicyByID(ctx, id)
	if err != nil {
		resp.Error = err
		return
	}
	if policy == nil || len(policy.HostGroups) < 2 {
		resp.Error = fmt.Errorf("expected at least two remote host groups to reorder")
		return
	}

	reordered := slices.Clone(policy.HostGroups)
	slices.Reverse(reordered)
	resp.Error = patchPolicyOutOfBand(ctx, req.State, &models.PolicymanagerExternalPolicyPatch{
		HostGroups: reordered,
	})
}

func reorderRemotePolicyHostGroups() statecheck.StateCheck {
	return reorderRemotePolicyHostGroupsCheck{}
}

type reorderRemotePolicyClassificationsCheck struct{}

func (reorderRemotePolicyClassificationsCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	id, err := policyIDFromState(req.State)
	if err != nil {
		resp.Error = err
		return
	}
	policy, err := getPolicyByID(ctx, id)
	if err != nil {
		resp.Error = err
		return
	}
	if policy == nil || policy.PolicyProperties == nil || len(policy.PolicyProperties.Classifications) < 2 {
		resp.Error = fmt.Errorf("expected at least two remote classifications to reorder")
		return
	}

	reordered := slices.Clone(policy.PolicyProperties.Classifications)
	slices.Reverse(reordered)
	properties := *policy.PolicyProperties
	properties.Classifications = reordered
	resp.Error = patchPolicyOutOfBand(ctx, req.State, &models.PolicymanagerExternalPolicyPatch{
		PolicyProperties: &properties,
	})
}

func reorderRemotePolicyClassifications() statecheck.StateCheck {
	return reorderRemotePolicyClassificationsCheck{}
}

// These two settings are present on the API wire but missing from the generated
// gofalcon policy models, so acceptance checks decode them directly from the response.
type policyRawResponse struct {
	Resources []*policyRawPolicy `json:"resources"`
}

type policyRawPolicy struct {
	ID               string               `json:"id"`
	PolicyProperties *policyRawProperties `json:"policy_properties"`
}

type policyRawProperties struct {
	EnableClipboardWebOrigin *bool `json:"enable_clipboard_web_origin"`
	EnableOCR                *bool `json:"enable_ocr"`
}

// policyRawReader decodes a policy read into policyRawResponse. The generated client
// method type asserts on its own 200 response type, so one is still produced; the
// decoded resources travel out through the reader instead. Every other status code is
// delegated untouched so the body is never consumed twice.
type policyRawReader struct {
	generated runtime.ClientResponseReader
	raw       *policyRawResponse
}

func (r *policyRawReader) ReadResponse(
	response runtime.ClientResponse,
	consumer runtime.Consumer,
) (any, error) {
	if response.Code() != 200 {
		return r.generated.ReadResponse(response, consumer)
	}

	raw := new(policyRawResponse)
	if err := consumer.Consume(response.Body(), raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	r.raw = raw

	return data_protection_configuration.NewEntitiesPolicyGetV2OK(), nil
}

// policyRawPropertiesByID reads the unmodelled settings straight off the API
// response.
func policyRawPropertiesByID(ctx context.Context, id string) (*policyRawProperties, error) {
	conn := testconfig.GetTestClient()
	params := data_protection_configuration.NewEntitiesPolicyGetV2Params().
		WithContext(ctx).
		WithIds([]string{id})

	reader := &policyRawReader{}
	option := func(op *runtime.ClientOperation) {
		reader.generated = op.Reader
		op.Reader = reader
	}

	if _, err := conn.DataProtectionConfiguration.EntitiesPolicyGetV2(params, option); err != nil {
		return nil, err
	}
	if reader.raw == nil {
		return nil, fmt.Errorf("no response decoded for data protection policy %s", id)
	}

	for _, policy := range reader.raw.Resources {
		if policy == nil || policy.ID != id || policy.PolicyProperties == nil {
			continue
		}
		return policy.PolicyProperties, nil
	}

	return nil, fmt.Errorf("data protection policy %s not found via API", id)
}

// policyRawBoolCheck asserts the raw API value of one setting gofalcon does not
// model. A nil value means the API did not return the field at all, which is a
// distinct failure from returning the wrong value and is reported as such.
type policyRawBoolCheck struct {
	field string
	get   func(properties *policyRawProperties) *bool
	want  bool
}

func (c policyRawBoolCheck) CheckState(
	ctx context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	id, err := policyIDFromState(req.State)
	if err != nil {
		resp.Error = err
		return
	}

	properties, err := policyRawPropertiesByID(ctx, id)
	if err != nil {
		resp.Error = fmt.Errorf("reading data protection policy %s: %w", id, err)
		return
	}

	got := c.get(properties)
	if got == nil {
		resp.Error = fmt.Errorf(
			"data protection policy %s: remote %s: expected %t, got no value",
			id, c.field, c.want,
		)
		return
	}
	if *got != c.want {
		resp.Error = fmt.Errorf(
			"data protection policy %s: remote %s: expected %t, got %t",
			id, c.field, c.want, *got,
		)
	}
}

func checkRemotePolicyClipboardWebOrigin(want bool) statecheck.StateCheck {
	return policyRawBoolCheck{
		field: "enable_clipboard_web_origin",
		get:   func(p *policyRawProperties) *bool { return p.EnableClipboardWebOrigin },
		want:  want,
	}
}

func checkRemotePolicyEnableOCR(want bool) statecheck.StateCheck {
	return policyRawBoolCheck{
		field: "enable_ocr",
		get:   func(p *policyRawProperties) *bool { return p.EnableOCR },
		want:  want,
	}
}

// testAccCheckPolicyDestroy verifies every policy tracked in state was removed
// from the API after the test tears down.
func testAccCheckPolicyDestroy(s *terraform.State) error {
	ctx := context.Background()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "crowdstrike_data_protection_policy" {
			continue
		}

		policy, err := getPolicyByID(ctx, rs.Primary.ID)
		if err != nil {
			return err
		}
		if policy != nil {
			return fmt.Errorf("data protection policy %s still exists", rs.Primary.ID)
		}
	}

	return nil
}

// Unit tests over the resource's expand, flatten, platform mapping, and validation
// helpers. They run without credentials and exercise the code through the exports in
// export_test.go.

func TestWirePlatformName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		platformName string
		want         string
		wantErr      bool
	}{
		{
			name:         "Windows maps to win",
			platformName: dataprotection.PlatformWindows,
			want:         dataprotection.APIPlatformWin,
		},
		{
			name:         "Mac maps to mac",
			platformName: dataprotection.PlatformMac,
			want:         dataprotection.APIPlatformMac,
		},
		{name: "wire value is not accepted", platformName: "win", wantErr: true},
		{name: "lowercase is not accepted", platformName: "windows", wantErr: true},
		{name: "empty is not accepted", platformName: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, diagnostic := dataprotection.WirePlatformName(tt.platformName)

			if tt.wantErr {
				require.NotNil(t, diagnostic, "expected a diagnostic for an unmapped platform")
				assert.Empty(t, got, "an unmapped platform must not fall through to the input value")
				return
			}

			require.Nil(t, diagnostic)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSchemaPlatformName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		apiPlatformName string
		want            string
		wantErr         bool
	}{
		{
			name:            "win maps to Windows",
			apiPlatformName: dataprotection.APIPlatformWin,
			want:            dataprotection.PlatformWindows,
		},
		{
			name:            "mac maps to Mac",
			apiPlatformName: dataprotection.APIPlatformMac,
			want:            dataprotection.PlatformMac,
		},
		{name: "practitioner value is not accepted", apiPlatformName: "Windows", wantErr: true},
		{name: "unknown platform is reported", apiPlatformName: "linux", wantErr: true},
		{name: "empty is reported", apiPlatformName: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, diagnostic := dataprotection.SchemaPlatformName(tt.apiPlatformName)

			if tt.wantErr {
				require.NotNil(t, diagnostic, "expected a diagnostic for an unmapped wire platform")
				assert.Empty(t, got, "an unmapped wire value must never leak into state")
				return
			}

			require.Nil(t, diagnostic)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlatformMapsAreInverses(t *testing.T) {
	t.Parallel()

	for schemaValue, wireValue := range dataprotection.PlatformNameToAPI {
		back, ok := dataprotection.PlatformNameFromAPI[wireValue]
		require.True(t, ok, "platformNameFromAPI has no entry for %q", wireValue)
		assert.Equal(t, schemaValue, back)
	}

	assert.Len(t, dataprotection.PlatformNameFromAPI, len(dataprotection.PlatformNameToAPI))
}

// testBuiltinHeader stands in for whatever sentence the API reports in
// euj_header_text.headers[0]. It is deliberately not the real Falcon text: the
// provider reads the sentence from the API rather than holding a constant, so a test
// that reused the production value could not tell the two apart.
const testBuiltinHeader = "TEST BUILT-IN HEADER SENTENCE."

// defaultSettingsPlan is a plan carrying nothing but the static schema defaults,
// which is what the framework produces from a configuration that sets no setting
// at all, on a Windows policy. Every value here must match the Default declared in
// the schema, and the platform-scoped values must match what ModifyPlan applies
// for platformWindows.
func defaultSettingsPlan() dataprotection.DataProtectionPolicyResourceModel {
	return dataprotection.DataProtectionPolicyResourceModel{
		PlatformName:    types.StringValue(dataprotection.PlatformWindows),
		Classifications: types.SetNull(types.StringType),

		// These optional strings and collections have no Terraform default.
		BeExcludeDomains:                types.SetNull(types.StringType),
		BeCustomSplashMessage:           types.StringNull(),
		CustomAllowedActionNotification: types.StringNull(),
		CustomBlockedActionNotification: types.StringNull(),
		EujCompanyLogo:                  types.StringNull(),
		EujCustomHeaderText:             types.StringNull(),
		EujCustomDropdownOptions:        types.ListNull(types.StringType),

		EujBusinessPurposesEnabled: types.BoolValue(true),
		EujPersonalUseEnabled:      types.BoolValue(true),

		// The Windows platform defaults ModifyPlan applies.
		ScreenCapture:                            types.BoolValue(false),
		ScreenCapturePreEventSeconds:             types.StringValue("3"),
		ScreenCapturePostEventSeconds:            types.StringValue("3"),
		EvidenceStorage:                          types.BoolValue(false),
		EndUserEncryptionActivity:                types.BoolValue(false),
		EvidenceStorageMaxFreeSpacePercent:       types.Float64Value(2),
		EvidenceStorageMaxSizeGiB:                types.Float64Value(1),
		NetworkInspection:                        types.BoolValue(false),
		NetworkInspectionFilesExceedingSizeLimit: types.StringValue("allow"),
		EnableOCR:                                types.BoolNull(),

		ContextInspection:          types.BoolValue(true),
		ContentInspection:          types.BoolValue(true),
		ClipboardInspection:        types.BoolValue(false),
		ClipboardWebOrigin:         types.BoolValue(false),
		SimilarityDetection:        types.BoolValue(false),
		MinimumSimilarityThreshold: types.StringValue("80"),
		InspectionDepth:            types.StringValue("balanced"),
		InspectionConfidence:       types.StringValue("medium"),
		MaxFileSize:                types.Float64Value(dataprotection.MaxFileSizeDefaultBytes),
		MaxFileSizeUnit:            types.StringValue(dataprotection.MaxFileSizeUnitBytes),

		BeSplashScreen:                   types.BoolValue(true),
		BeUploadTimeoutSeconds:           types.Int32Value(40),
		BeUploadTimeoutResponse:          types.StringValue("allow"),
		BePasteTimeoutMilliseconds:       types.Int32Value(800),
		BePasteTimeoutResponse:           types.StringValue("allow"),
		BePasteClipboardMinSize:          types.Float64Value(32),
		BePasteClipboardMinSizeUnit:      types.StringValue("Bytes"),
		BePasteClipboardMaxSize:          types.Float64Value(0.0625),
		BePasteClipboardMaxSizeUnit:      types.StringValue("KiB"),
		BePasteClipboardBlockOverMaxSize: types.BoolValue(false),

		BrowsersWithoutActiveExtension: types.StringValue("allow"),
		BlockAllDataAccess:             types.BoolValue(false),

		EujRequireAdditionalDetails: types.BoolValue(true),
		EujDialogTimeout:            types.Int32Value(120),
	}
}

// TestExpandPolicyPropertiesSendsEveryDefaultedSetting is the regression guard for
// "the provider declares the defaults rather than relying on the server". Every
// setting the resource manages must appear on the wire for a configuration that
// sets none of them, otherwise the API's merge decides the value and a defaulted
// attribute silently stops being authoritative.
func TestExpandPolicyPropertiesSendsEveryDefaultedSetting(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	properties := dataprotection.ExpandPolicyProperties(
		context.Background(),
		dataprotection.NewPolicyWrite(defaultSettingsPlan(), testBuiltinHeader),
		&diags,
	)
	require.False(t, diags.HasError(), "expanding the defaults must not produce diagnostics")

	body, err := json.Marshal(properties)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))

	want := map[string]any{
		// Terraform owns the membership, so a null set reaches the wire as [].
		"classifications": []any{},

		"enable_context_inspection":     true,
		"enable_content_inspection":     true,
		"enable_clipboard_inspection":   false,
		"enable_clipboard_web_origin":   false,
		"similarity_detection":          false,
		"similarity_threshold":          "80",
		"inspection_depth":              "balanced",
		"min_confidence_level":          "medium",
		"max_file_size_to_inspect":      float64(104857600),
		"max_file_size_to_inspect_unit": "Bytes",

		"be_splash_enabled":                            true,
		"be_upload_timeout_duration_seconds":           float64(40),
		"be_upload_timeout_response":                   "allow",
		"be_paste_timeout_duration_milliseconds":       float64(800),
		"be_paste_timeout_response":                    "allow",
		"be_paste_clipboard_min_size":                  float64(32),
		"be_paste_clipboard_min_size_unit":             "Bytes",
		"be_paste_clipboard_max_size":                  0.0625,
		"be_paste_clipboard_max_size_unit":             "KiB",
		"be_paste_clipboard_over_size_behaviour_block": false,

		"browsers_without_active_extension": "allow",
		"block_all_data_access":             false,

		"euj_require_additional_details": true,
		"euj_dialog_timeout":             float64(120),

		// Null values that must explicitly clear their remote string are sent as "".
		"be_exclude_domains":  "",
		"euj_dialog_box_logo": "",

		// Each message source is derived from whether its paired text is set, and is
		// stated explicitly rather than left to the API's merge. The texts
		// themselves are absent, because the source is what reverts the policy to
		// Falcon's built-in message and the API rejects an empty notification text.
		"be_splash_message_source": dataprotection.MessageSourceDefault,
		"allow_notifications":      dataprotection.MessageSourceDefault,
		"block_notifications":      dataprotection.MessageSourceDefault,

		// The header structure is synthesized in full from the sentence the API
		// reported, with that sentence selected because no custom header is
		// configured.
		"euj_header_text": map[string]any{
			"headers": []any{
				map[string]any{"header": testBuiltinHeader, "default": true, "selected": true},
				map[string]any{"header": "", "default": false, "selected": false},
			},
		},

		// With no custom options this is byte-for-byte the server's own default
		// array. It is never sent empty, which the API rejects.
		"euj_dropdown_options": map[string]any{
			"justifications": []any{
				map[string]any{
					"justification": dataprotection.EujMandatoryBusinessPurposes,
					"id":            dataprotection.EujMandatoryBusinessPurposes,
					"default":       true,
					"selected":      true,
				},
				map[string]any{
					"justification": dataprotection.EujMandatoryPersonalUse,
					"id":            dataprotection.EujMandatoryPersonalUse,
					"default":       true,
					"selected":      true,
				},
			},
		},

		// Remaining Windows-only settings. enable_ocr is Mac-only and deliberately absent.
		"enable_screen_capture":                         false,
		"screen_capture_duration_pre_event":             "3",
		"screen_capture_duration_post_event":            "3",
		"evidence_download_enabled":                     false,
		"evidence_encrypted_enabled":                    false,
		"evidence_storage_free_disk_perc":               float64(2),
		"evidence_storage_max_size":                     float64(1),
		"enable_network_inspection":                     false,
		"network_inspection_files_exceeding_size_limit": "allow",
	}

	for key, value := range want {
		require.Contains(t, decoded, key, "the expander must send %s on every write", key)
		assert.Equal(t, value, decoded[key], "wrong value for %s", key)
	}

	assert.Len(t, decoded, len(want), "the expander sent a key this test does not know about: %v", decoded)
}

func TestValidateMaxFileSizeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		size    types.Float64
		unit    types.String
		wantErr bool
	}{
		{
			name:    "600 MB exceeds the byte ceiling",
			size:    types.Float64Value(600),
			unit:    types.StringValue(dataprotection.MaxFileSizeUnitMB),
			wantErr: true,
		},
		{
			name:    "525 MB exceeds the byte ceiling",
			size:    types.Float64Value(525),
			unit:    types.StringValue(dataprotection.MaxFileSizeUnitMB),
			wantErr: true,
		},
		{
			name:    "524289 KB exceeds the byte ceiling",
			size:    types.Float64Value(524289),
			unit:    types.StringValue(dataprotection.MaxFileSizeUnitKB),
			wantErr: true,
		},
		{
			name: "524.288 MB is exactly the ceiling",
			size: types.Float64Value(524.288),
			unit: types.StringValue(dataprotection.MaxFileSizeUnitMB),
		},
		{
			name: "524288 KB is exactly the ceiling",
			size: types.Float64Value(524288),
			unit: types.StringValue(dataprotection.MaxFileSizeUnitKB),
		},
		{
			name: "524288000 Bytes is exactly the ceiling",
			size: types.Float64Value(dataprotection.MaxFileSizeMaxBytes),
			unit: types.StringValue(dataprotection.MaxFileSizeUnitBytes),
		},
		{
			name: "a null size resolves to its default",
			size: types.Float64Null(),
			unit: types.StringValue(dataprotection.MaxFileSizeUnitBytes),
		},
		{
			name: "a null unit resolves to Bytes",
			size: types.Float64Value(dataprotection.MaxFileSizeMaxBytes),
			unit: types.StringNull(),
		},
		{
			name: "both null is the default pair",
			size: types.Float64Null(),
			unit: types.StringNull(),
		},
		{
			name: "an unknown size skips the check",
			size: types.Float64Unknown(),
			unit: types.StringValue(dataprotection.MaxFileSizeUnitMB),
		},
		{
			name: "an unknown unit skips the check",
			size: types.Float64Value(600),
			unit: types.StringUnknown(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			diags := dataprotection.ValidateMaxFileSizeBytes(tt.size, tt.unit)

			if !tt.wantErr {
				assert.False(t, diags.HasError(), "expected no error, got %v", diags.Errors())
				return
			}

			require.True(t, diags.HasError(), "expected the byte ceiling to reject this pair")
			detail := diags.Errors()[0].Detail()
			assert.Contains(t, detail, "max_file_size")
			assert.Contains(t, detail, "max_file_size_unit")
			assert.Contains(t, detail, "524288000")
			assert.Contains(t, detail, "Bytes")
		})
	}
}

// TestMessageSourceDerivesFromPresence locks the structural relationship that
// replaces the console's Default/Custom radio: configuring the text *is* the choice
// of custom messaging, so the provider never exposes the enum.
func TestMessageSourceDerivesFromPresence(t *testing.T) {
	t.Parallel()

	assert.Equal(t, dataprotection.MessageSourceCustom, dataprotection.MessageSource(types.StringValue("hello")))
	assert.Equal(t, dataprotection.MessageSourceDefault, dataprotection.MessageSource(types.StringNull()))
	assert.Equal(t, dataprotection.MessageSourceDefault, dataprotection.MessageSource(types.StringUnknown()))
}

// TestFlattenCustomMessage covers all four wire states a collapsed message pair can
// be in. Only `custom` with non-empty text is expressible as a value; the degenerate
// `custom` with "" must read back as null so Read never invents a value, and the next
// apply converges the remote to `default`.
func TestFlattenCustomMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		text   string
		want   types.String
	}{
		{
			"custom with text is the value",
			dataprotection.MessageSourceCustom,
			"be careful",
			types.StringValue("be careful"),
		},
		{"custom with empty text is null", dataprotection.MessageSourceCustom, "", types.StringNull()},
		{"default with empty text is null", dataprotection.MessageSourceDefault, "", types.StringNull()},
		{"default with leftover text is null", dataprotection.MessageSourceDefault, "stale", types.StringNull()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, dataprotection.FlattenCustomMessage(tt.source, tt.text))
		})
	}
}

// TestExcludeDomainsRoundTrip covers the Set-over-one-comma-separated-string
// contract. The join has to be deterministic, because the set has no order of its
// own and a shifting wire value would churn.
func TestExcludeDomainsRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	stringSet := func(values ...string) types.Set {
		elements := make([]attr.Value, 0, len(values))
		for _, value := range values {
			elements = append(elements, types.StringValue(value))
		}
		set, diags := types.SetValue(types.StringType, elements)
		require.False(t, diags.HasError())
		return set
	}

	t.Run("null set expands to the empty string", func(t *testing.T) {
		var diags diag.Diagnostics
		assert.Empty(t, dataprotection.ExpandExcludeDomains(ctx, types.SetNull(types.StringType), &diags))
		assert.False(t, diags.HasError())
	})

	t.Run("one element expands to the bare element", func(t *testing.T) {
		var diags diag.Diagnostics
		assert.Equal(
			t,
			"*://a.test/*",
			dataprotection.ExpandExcludeDomains(ctx, stringSet("*://a.test/*"), &diags),
		)
	})

	t.Run("elements join in a deterministic order", func(t *testing.T) {
		var diags diag.Diagnostics

		forward := stringSet("*://a.test/*", "*://b.test/*")
		reverse := stringSet("*://b.test/*", "*://a.test/*")

		assert.Equal(
			t,
			"*://a.test/*,*://b.test/*",
			dataprotection.ExpandExcludeDomains(ctx, forward, &diags),
		)
		assert.Equal(
			t,
			dataprotection.ExpandExcludeDomains(ctx, forward, &diags),
			dataprotection.ExpandExcludeDomains(ctx, reverse, &diags),
			"the wire value must be a function of the set, not of the order it was written in",
		)
	})

	t.Run("empty wire value flattens to null, not an empty set", func(t *testing.T) {
		got, diags := dataprotection.FlattenExcludeDomains(ctx, "")
		require.False(t, diags.HasError())
		assert.True(t, got.IsNull())
	})

	t.Run("comma-joined wire value flattens to the element set", func(t *testing.T) {
		got, diags := dataprotection.FlattenExcludeDomains(ctx, "*://b.test/*,*://a.test/*")
		require.False(t, diags.HasError())

		want := stringSet("*://a.test/*", "*://b.test/*")
		assert.True(t, want.Equal(got), "want %v, got %v", want, got)
	})
}

// TestEujHeaderTextRoundTrip covers the synthesized two-element structure. Slot 0
// must always carry whatever sentence the API reported, verbatim, because the API
// rejects any substitute with `400 invalid first header`.
func TestEujHeaderTextRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("null selects the built-in header", func(t *testing.T) {
		headerText := dataprotection.ExpandEujHeaderText(types.StringNull(), testBuiltinHeader)
		require.Len(t, headerText.Headers, 2)

		assert.Equal(t, testBuiltinHeader, *headerText.Headers[0].Header)
		assert.True(t, *headerText.Headers[0].Default)
		assert.True(t, *headerText.Headers[0].Selected)

		assert.Empty(t, *headerText.Headers[1].Header)
		assert.False(t, *headerText.Headers[1].Default)
		assert.False(t, *headerText.Headers[1].Selected)

		assert.True(t, dataprotection.FlattenEujHeaderText(headerText).IsNull())
	})

	t.Run("a configured header selects the custom slot and round-trips", func(t *testing.T) {
		headerText := dataprotection.ExpandEujHeaderText(
			types.StringValue("Justify this, please."),
			testBuiltinHeader,
		)
		require.Len(t, headerText.Headers, 2)

		assert.Equal(t, testBuiltinHeader, *headerText.Headers[0].Header,
			"the reported sentence must be sent verbatim even when it is not selected")
		assert.False(t, *headerText.Headers[0].Selected)
		assert.True(t, *headerText.Headers[1].Selected)

		assert.Equal(
			t,
			types.StringValue("Justify this, please."),
			dataprotection.FlattenEujHeaderText(headerText),
		)
	})

	t.Run("an unknown built-in sentence omits the field", func(t *testing.T) {
		assert.Nil(t, dataprotection.ExpandEujHeaderText(types.StringNull(), ""),
			"without a sentence from the API there is nothing valid to send, so the field is omitted")
		assert.Nil(t, dataprotection.ExpandEujHeaderText(types.StringValue("Justify this, please."), ""))
	})

	t.Run("the degenerate selected-but-empty custom slot flattens to null", func(t *testing.T) {
		got := dataprotection.FlattenEujHeaderText(&models.PolicymanagerEUJHeaderText{
			Headers: []*models.PolicymanagerEUJHeader{
				{Header: utils.Addr(testBuiltinHeader), Default: utils.Addr(true), Selected: utils.Addr(false)},
				{Header: utils.Addr(""), Default: utils.Addr(false), Selected: utils.Addr(true)},
			},
		})
		assert.True(t, got.IsNull(), "an empty custom header is not expressible, so it must read as null")
	})

	t.Run("a missing structure flattens to null", func(t *testing.T) {
		assert.True(t, dataprotection.FlattenEujHeaderText(nil).IsNull())
	})
}

// TestBuiltinHeaderText covers the reader that sources the sentence from a policy
// response rather than from a constant in the provider.
func TestBuiltinHeaderText(t *testing.T) {
	t.Parallel()

	t.Run("reads slot 0 verbatim", func(t *testing.T) {
		got := dataprotection.BuiltinHeaderText(&models.PolicymanagerEUJHeaderText{
			Headers: []*models.PolicymanagerEUJHeader{
				{Header: utils.Addr(testBuiltinHeader), Default: utils.Addr(true), Selected: utils.Addr(true)},
				{Header: utils.Addr("custom"), Default: utils.Addr(false), Selected: utils.Addr(false)},
			},
		})
		assert.Equal(t, testBuiltinHeader, got)
	})

	t.Run("reads slot 0 even when the custom slot is selected", func(t *testing.T) {
		got := dataprotection.BuiltinHeaderText(&models.PolicymanagerEUJHeaderText{
			Headers: []*models.PolicymanagerEUJHeader{
				{Header: utils.Addr(testBuiltinHeader), Default: utils.Addr(true), Selected: utils.Addr(false)},
				{Header: utils.Addr("custom"), Default: utils.Addr(false), Selected: utils.Addr(true)},
			},
		})
		assert.Equal(t, testBuiltinHeader, got)
	})

	for name, headerText := range map[string]*models.PolicymanagerEUJHeaderText{
		"a nil structure":   nil,
		"no headers":        {Headers: nil},
		"a nil slot 0":      {Headers: []*models.PolicymanagerEUJHeader{nil}},
		"a nil slot 0 text": {Headers: []*models.PolicymanagerEUJHeader{{Header: nil}}},
	} {
		t.Run(name+" reports not-known", func(t *testing.T) {
			assert.Empty(t, dataprotection.BuiltinHeaderText(headerText),
				"an unreadable response must not be mistaken for a known sentence")
		})
	}
}

// eujCustomList builds a euj_custom_dropdown_options value for the tests below.
func eujCustomList(t *testing.T, values ...string) types.List {
	t.Helper()

	if len(values) == 0 {
		return types.ListNull(types.StringType)
	}

	elements := make([]attr.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	list, diags := types.ListValue(types.StringType, elements)
	require.False(t, diags.HasError())

	return list
}

// TestEujDropdownOptionsExpand asserts the wire rules the API enforces on the
// justification array, which the schema cannot express because three attributes
// share the one field.
func TestEujDropdownOptionsExpand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("all three omitted produces the server's own default array", func(t *testing.T) {
		var diags diag.Diagnostics
		options := dataprotection.ExpandEujDropdownOptions(ctx, defaultSettingsPlan(), &diags)
		require.False(t, diags.HasError())
		require.Len(t, options.Justifications, 2)

		body, err := json.Marshal(options)
		require.NoError(t, err)
		assert.JSONEq(t, `{"justifications":[
			{"justification":"Business purposes","id":"Business purposes","default":true,"selected":true},
			{"justification":"Personal use","id":"Personal use","default":true,"selected":true}
		]}`, string(body))
	})

	t.Run("custom entries carry no id key at all", func(t *testing.T) {
		var diags diag.Diagnostics
		plan := defaultSettingsPlan()
		plan.EujBusinessPurposesEnabled = types.BoolValue(false)
		plan.EujPersonalUseEnabled = types.BoolValue(false)
		plan.EujCustomDropdownOptions = eujCustomList(t, "first", "second")

		options := dataprotection.ExpandEujDropdownOptions(ctx, plan, &diags)
		require.False(t, diags.HasError())
		require.Len(t, options.Justifications, 4)

		body, err := json.Marshal(options)
		require.NoError(t, err)

		var decoded struct {
			Justifications []map[string]any `json:"justifications"`
		}
		require.NoError(t, json.Unmarshal(body, &decoded))
		require.Len(t, decoded.Justifications, 4)

		// The two built-ins keep default:true and an id equal to their own text, and
		// are deselected rather than removed.
		assert.Equal(t, true, decoded.Justifications[0]["default"])
		assert.Equal(t, dataprotection.EujMandatoryBusinessPurposes, decoded.Justifications[0]["id"])
		assert.Equal(t, false, decoded.Justifications[0]["selected"])
		assert.Equal(t, dataprotection.EujMandatoryPersonalUse, decoded.Justifications[1]["id"])
		assert.Equal(t, false, decoded.Justifications[1]["selected"])

		for _, index := range []int{2, 3} {
			entry := decoded.Justifications[index]
			assert.NotContains(t, entry, "id",
				"custom entry %d must omit the id key entirely, not send null", index)
			assert.Equal(t, false, entry["default"])
			assert.Equal(t, true, entry["selected"],
				"selected must always be emitted explicitly, since omitting it reads as false")
		}
		assert.Equal(t, "first", decoded.Justifications[2]["justification"])
		assert.Equal(t, "second", decoded.Justifications[3]["justification"])
	})

	t.Run("one built-in enabled beside one custom", func(t *testing.T) {
		var diags diag.Diagnostics
		plan := defaultSettingsPlan()
		plan.EujPersonalUseEnabled = types.BoolValue(false)
		plan.EujCustomDropdownOptions = eujCustomList(t, "only")

		options := dataprotection.ExpandEujDropdownOptions(ctx, plan, &diags)
		require.False(t, diags.HasError())
		require.Len(t, options.Justifications, 3)
		assert.True(t, *options.Justifications[0].Selected)
		assert.False(t, *options.Justifications[1].Selected)
		assert.Equal(t, "only", *options.Justifications[2].Justification)
	})
}

// TestEujDropdownOptionsFlatten covers the reductions Read performs, including the
// remote shapes the schema cannot express.
func TestEujDropdownOptionsFlatten(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("no custom entries flattens to null rather than an empty list", func(t *testing.T) {
		businessPurposes, personalUse, custom, diags := dataprotection.FlattenEujDropdownOptions(ctx,
			&dataprotection.EujDropdownOptionsOverride{Justifications: []*dataprotection.EujOptionOverride{
				{Justification: utils.Addr(dataprotection.EujMandatoryBusinessPurposes), Selected: utils.Addr(true)},
				{Justification: utils.Addr(dataprotection.EujMandatoryPersonalUse), Selected: utils.Addr(false)},
			}})
		require.False(t, diags.HasError())

		assert.Equal(t, types.BoolValue(true), businessPurposes)
		assert.Equal(t, types.BoolValue(false), personalUse)
		assert.True(t, custom.IsNull())
	})

	t.Run("a console-written unselected custom entry is reported as present", func(t *testing.T) {
		// Dropping it would make the next apply delete a console-configured row
		// without that deletion ever appearing in a plan.
		_, _, custom, diags := dataprotection.FlattenEujDropdownOptions(ctx,
			&dataprotection.EujDropdownOptionsOverride{Justifications: []*dataprotection.EujOptionOverride{
				{Justification: utils.Addr(dataprotection.EujMandatoryBusinessPurposes), Selected: utils.Addr(true)},
				{Justification: utils.Addr(dataprotection.EujMandatoryPersonalUse), Selected: utils.Addr(true)},
				{Justification: utils.Addr("kept"), Selected: utils.Addr(false), ID: utils.Addr("item_id_92")},
			}})
		require.False(t, diags.HasError())

		elements := custom.Elements()
		require.Len(t, elements, 1)
		assert.Equal(t, types.StringValue("kept"), elements[0],
			"the id is discarded and the entry is reported as offered")
	})

	t.Run("a missing structure flattens to nulls", func(t *testing.T) {
		businessPurposes, personalUse, custom, diags := dataprotection.FlattenEujDropdownOptions(ctx, nil)
		require.False(t, diags.HasError())
		assert.True(t, businessPurposes.IsNull())
		assert.True(t, personalUse.IsNull())
		assert.True(t, custom.IsNull())
	})
}

// windowsOnlyWireKeys are fields the API accepts only on a Windows policy.
var windowsOnlyWireKeys = []string{
	"browsers_without_active_extension",
	"block_all_data_access",
	"enable_screen_capture",
	"screen_capture_duration_pre_event",
	"screen_capture_duration_post_event",
	"evidence_download_enabled",
	"evidence_encrypted_enabled",
	"evidence_storage_free_disk_perc",
	"evidence_storage_max_size",
	"enable_network_inspection",
	"network_inspection_files_exceeding_size_limit",
}

// TestExpandPlatformScopedSettings is the guard against sending a field on the
// platform whose API refuses it: every one returns
// `400 "<field> is not a field of Data Protection <platform> policy"`.
func TestExpandPlatformScopedSettings(t *testing.T) {
	t.Parallel()

	decode := func(t *testing.T, plan dataprotection.DataProtectionPolicyResourceModel) map[string]any {
		t.Helper()

		var diags diag.Diagnostics
		properties := dataprotection.ExpandPolicyProperties(
			context.Background(),
			dataprotection.NewPolicyWrite(plan, testBuiltinHeader),
			&diags,
		)
		require.False(t, diags.HasError())

		body, err := json.Marshal(properties)
		require.NoError(t, err)

		var decoded map[string]any
		require.NoError(t, json.Unmarshal(body, &decoded))

		return decoded
	}

	t.Run("Windows sends Windows-only fields and never enable_ocr", func(t *testing.T) {
		decoded := decode(t, defaultSettingsPlan())

		for _, key := range windowsOnlyWireKeys {
			assert.Contains(t, decoded, key)
		}
		assert.NotContains(t, decoded, "enable_ocr")
	})

	t.Run("Mac sends enable_ocr and none of the Windows fields", func(t *testing.T) {
		plan := defaultSettingsPlan()
		plan.PlatformName = types.StringValue(dataprotection.PlatformMac)
		plan.EnableOCR = types.BoolValue(true)

		// ModifyPlan nulls every Windows-only attribute on a Mac policy.
		plan.ScreenCapture = types.BoolNull()
		plan.ScreenCapturePreEventSeconds = types.StringNull()
		plan.ScreenCapturePostEventSeconds = types.StringNull()
		plan.EvidenceStorage = types.BoolNull()
		plan.EndUserEncryptionActivity = types.BoolNull()
		plan.EvidenceStorageMaxFreeSpacePercent = types.Float64Null()
		plan.EvidenceStorageMaxSizeGiB = types.Float64Null()
		plan.NetworkInspection = types.BoolNull()
		plan.NetworkInspectionFilesExceedingSizeLimit = types.StringNull()
		plan.BrowsersWithoutActiveExtension = types.StringNull()
		plan.BlockAllDataAccess = types.BoolNull()

		decoded := decode(t, plan)

		assert.Equal(t, true, decoded["enable_ocr"])
		for _, key := range windowsOnlyWireKeys {
			assert.NotContains(t, decoded, key,
				"%s is Windows only and the API rejects it on a Mac policy", key)
		}
	})
}

// TestPlatformScopedSettingsTable keeps the declaration honest. ModifyPlan and the
// ValidateConfig platform rules both drive off this table, so a record whose
// accessor returns the wrong field would silently stop being defaulted and
// validated. A missing accessor is a compile error, so what this checks is that each
// one reads a field of the same type as the declared default.
func TestPlatformScopedSettingsTable(t *testing.T) {
	t.Parallel()

	require.Len(t, dataprotection.PlatformScopedSettings, 12)

	ctx := context.Background()
	var model dataprotection.DataProtectionPolicyResourceModel

	for _, setting := range dataprotection.PlatformScopedSettings {
		t.Run(setting.Name(), func(t *testing.T) {
			assert.Contains(
				t,
				[]string{dataprotection.PlatformWindows, dataprotection.PlatformMac},
				setting.Platform(),
			)

			require.NotNil(t, setting.Value())
			require.NotNil(t, setting.Null())
			assert.True(t, setting.Null().IsNull(), "the null field must be a typed null")
			assert.Equal(t, setting.Value().Type(ctx), setting.Null().Type(ctx),
				"value and null must share a type or resp.Plan.SetAttribute will fail")

			// A zero model leaves every field null, so the accessor's type is what
			// is under test here, not its value.
			read := setting.Get(model)
			require.NotNil(t, read, "the get accessor must read a field")
			assert.Equal(t, setting.Value().Type(ctx), read.Type(ctx),
				"get must read the attribute the default is declared for")
		})
	}
}

// TestValidateEujEnabledOptions covers the one API justification rule a practitioner
// can still violate. The schema makes the other five unrepresentable.
func TestValidateEujEnabledOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		businessPurposes types.Bool
		personalUse      types.Bool
		custom           types.List
		wantErr          bool
	}{
		{
			name:             "both built-ins omitted resolve to enabled",
			businessPurposes: types.BoolNull(),
			personalUse:      types.BoolNull(),
		},
		{
			name:             "one built-in disabled and the other omitted is rejected",
			businessPurposes: types.BoolValue(false),
			personalUse:      types.BoolNull(),
			wantErr:          true,
		},
		{
			name:             "both built-ins disabled with two customs",
			businessPurposes: types.BoolValue(false),
			personalUse:      types.BoolValue(false),
			custom:           eujCustomList(t, "a", "b"),
		},
		{
			name:             "both built-ins disabled with one custom is rejected",
			businessPurposes: types.BoolValue(false),
			personalUse:      types.BoolValue(false),
			custom:           eujCustomList(t, "a"),
			wantErr:          true,
		},
		{
			name:             "both built-ins disabled with no customs is rejected",
			businessPurposes: types.BoolValue(false),
			personalUse:      types.BoolValue(false),
			wantErr:          true,
		},
		{
			name:             "an unknown custom list skips the rule",
			businessPurposes: types.BoolValue(false),
			personalUse:      types.BoolValue(false),
			custom:           types.ListUnknown(types.StringType),
		},
		{
			name:             "an unknown built-in skips the rule",
			businessPurposes: types.BoolUnknown(),
			personalUse:      types.BoolValue(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			custom := tt.custom
			if custom.IsNull() {
				custom = types.ListNull(types.StringType)
			}

			diags := dataprotection.ValidateEujEnabledOptions(
				dataprotection.DataProtectionPolicyResourceModel{
					EujBusinessPurposesEnabled: tt.businessPurposes,
					EujPersonalUseEnabled:      tt.personalUse,
					EujCustomDropdownOptions:   custom,
				},
			)

			if !tt.wantErr {
				assert.False(t, diags.HasError(), "expected no error, got %v", diags.Errors())
				return
			}

			require.True(t, diags.HasError())
			assert.Contains(t, diags.Errors()[0].Detail(), "at least 2")
		})
	}
}

// TestValidatePlatformScopedSettings covers the plan-time rejection that keeps the
// API's `<field> is not a field of Data Protection <platform> policy` out of apply.
func TestValidatePlatformScopedSettings(t *testing.T) {
	t.Parallel()

	t.Run("every Windows-only attribute is gated on Mac", func(t *testing.T) {
		var gated int
		for _, setting := range dataprotection.PlatformScopedSettings {
			if setting.Platform() != dataprotection.PlatformWindows {
				continue
			}
			gated++

			model := dataprotection.DataProtectionPolicyResourceModel{
				PlatformName: types.StringValue(dataprotection.PlatformMac),
			}
			setPlatformScopedValue(t, &model, setting.Name(), setting.Value())

			diags := dataprotection.ValidatePlatformScopedSettings(model)
			require.True(t, diags.HasError(), "%s is not gated on Mac", setting.Name())
			assert.Contains(t, diags.Errors()[0].Summary(), setting.Name())
			assert.Contains(t, diags.Errors()[0].Summary(), dataprotection.PlatformMac)
		}
		assert.Equal(t, 11, gated, "the plan declares eleven Windows-only settings")
	})

	t.Run("enable_ocr is gated on Windows", func(t *testing.T) {
		diags := dataprotection.ValidatePlatformScopedSettings(
			dataprotection.DataProtectionPolicyResourceModel{
				PlatformName: types.StringValue(dataprotection.PlatformWindows),
				EnableOCR:    types.BoolValue(true),
			},
		)
		require.True(t, diags.HasError())
		assert.Contains(t, diags.Errors()[0].Summary(), "enable_ocr")
	})

	t.Run("an unconfigured setting on the other platform is fine", func(t *testing.T) {
		diags := dataprotection.ValidatePlatformScopedSettings(
			dataprotection.DataProtectionPolicyResourceModel{
				PlatformName: types.StringValue(dataprotection.PlatformMac),
			},
		)
		assert.False(t, diags.HasError())
	})

	t.Run("an unknown platform_name skips the rules", func(t *testing.T) {
		diags := dataprotection.ValidatePlatformScopedSettings(
			dataprotection.DataProtectionPolicyResourceModel{
				PlatformName:  types.StringUnknown(),
				ScreenCapture: types.BoolValue(true),
			},
		)
		assert.False(t, diags.HasError())
	})
}

// setPlatformScopedValue assigns one platform-scoped attribute by name, so a test can
// drive the whole platformScopedSettings table without repeating itself.
func setPlatformScopedValue(
	t *testing.T,
	model *dataprotection.DataProtectionPolicyResourceModel,
	name string,
	value attr.Value,
) {
	t.Helper()

	asBool := func() types.Bool {
		typed, ok := value.(types.Bool)
		require.True(t, ok, "%s: expected a types.Bool, got %T", name, value)
		return typed
	}
	asString := func() types.String {
		typed, ok := value.(types.String)
		require.True(t, ok, "%s: expected a types.String, got %T", name, value)
		return typed
	}
	asFloat64 := func() types.Float64 {
		typed, ok := value.(types.Float64)
		require.True(t, ok, "%s: expected a types.Float64, got %T", name, value)
		return typed
	}

	switch name {
	case "screen_capture":
		model.ScreenCapture = asBool()
	case "screen_capture_pre_event_seconds":
		model.ScreenCapturePreEventSeconds = asString()
	case "screen_capture_post_event_seconds":
		model.ScreenCapturePostEventSeconds = asString()
	case "evidence_storage":
		model.EvidenceStorage = asBool()
	case "end_user_encryption_activity":
		model.EndUserEncryptionActivity = asBool()
	case "evidence_storage_max_free_space_percent":
		model.EvidenceStorageMaxFreeSpacePercent = asFloat64()
	case "evidence_storage_max_size_gib":
		model.EvidenceStorageMaxSizeGiB = asFloat64()
	case "network_inspection":
		model.NetworkInspection = asBool()
	case "network_inspection_files_exceeding_size_limit":
		model.NetworkInspectionFilesExceedingSizeLimit = asString()
	case "browsers_without_active_extension":
		model.BrowsersWithoutActiveExtension = asString()
	case "block_all_data_access":
		model.BlockAllDataAccess = asBool()
	case "enable_ocr":
		model.EnableOCR = asBool()
	default:
		t.Fatalf("setPlatformScopedValue has no case for %s", name)
	}
}

// TestRetryPolicyWrite covers the retry the update and delete paths share.
//
// The endpoint reports a lost optimistic-concurrency check as a 500, so a server
// error has to be replayed rather than reported. What matters is the boundaries: a
// non-retryable failure must not be replayed, the attempt ceiling must hold, the
// result and error a caller sees must come from the attempt the loop ended on, and a
// cancelled context must stop the loop instead of sleeping out its attempts.
//
// It shortens the package-level backoff so the loop does not sleep, which is why it
// is the one unit test here that does not call t.Parallel.
func TestRetryPolicyWrite(t *testing.T) {
	previous := dataprotection.SetPolicyWriteBackoff(0)
	t.Cleanup(func() { dataprotection.SetPolicyWriteBackoff(previous) })

	serverError := runtime.NewAPIError("update", "500 Internal Server Error", 500)
	rejected := runtime.NewAPIError("update", "400 Bad Request", 400)

	t.Run("a write that succeeds is issued once", func(t *testing.T) {
		var attempts int

		res, err := dataprotection.RetryPolicyWrite(
			context.Background(),
			"update",
			func() (string, error) {
				attempts++
				return "patched", nil
			},
		)

		assert.Equal(t, 1, attempts)
		assert.NoError(t, err)
		assert.Equal(t, "patched", res)
	})

	t.Run("a server error is replayed until it clears", func(t *testing.T) {
		var attempts int

		res, err := dataprotection.RetryPolicyWrite(
			context.Background(),
			"update",
			func() (string, error) {
				attempts++
				if attempts == 1 {
					return "", serverError
				}
				return "patched", nil
			},
		)

		assert.Equal(t, 2, attempts)
		assert.NoError(t, err, "the successful attempt's error is the one returned")
		assert.Equal(t, "patched", res, "the successful attempt's result is the one returned")
	})

	t.Run("a persistent server error stops at the attempt ceiling", func(t *testing.T) {
		var attempts int

		_, err := dataprotection.RetryPolicyWrite(
			context.Background(),
			"update",
			func() (string, error) {
				attempts++
				return "", serverError
			},
		)

		assert.Equal(t, dataprotection.PolicyWriteAttempts, attempts)
		assert.ErrorIs(t, err, serverError)
	})

	t.Run("a request the API rejected is not replayed", func(t *testing.T) {
		var attempts int

		_, err := dataprotection.RetryPolicyWrite(
			context.Background(),
			"update",
			func() (string, error) {
				attempts++
				return "", rejected
			},
		)

		assert.Equal(t, 1, attempts, "a 400 is the API's verdict on the request, not contention")
		assert.ErrorIs(t, err, rejected)
	})

	t.Run("a cancelled context ends the retries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		var attempts int

		_, err := dataprotection.RetryPolicyWrite(ctx, "delete", func() (string, error) {
			attempts++
			return "", serverError
		})

		assert.Equal(t, 1, attempts)
		assert.ErrorIs(t, err, serverError)
	})
}
