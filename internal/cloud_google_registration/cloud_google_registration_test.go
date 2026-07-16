package cloudgoogleregistration_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func generateGoogleCloudProjectID() string {
	return fmt.Sprintf("%sproj-%s", acctest.ResourcePrefix, sdkacctest.RandStringFromCharSet(8, sdkacctest.CharSetAlphaNum))
}

func generateGoogleCloudOrgID() string {
	return sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
}

func generateGoogleCloudProjectNumber() string {
	return sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
}

func TestAccCloudGoogleRegistrationResource_Complete(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rNameUpdated := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_complete(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("deployment_method"), knownvalue.StringExact("terraform-native")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("infra_project"), knownvalue.StringExact(infraProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project"), knownvalue.StringExact(wifProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("excluded_project_patterns"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("excluded_project_patterns").AtSliceIndex(0), knownvalue.StringExact("test-*")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("excluded_project_patterns").AtSliceIndex(1), knownvalue.StringExact("*-sandbox")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs-")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("-prod")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels"), knownvalue.MapSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtMapKey("environment"), knownvalue.StringExact("production")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtMapKey("managed-by"), knownvalue.StringExact("terraform")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.MapSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags").AtMapKey("compliance"), knownvalue.StringExact("required")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags").AtMapKey("owner"), knownvalue.StringExact("security-team")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_completeUpdated(rNameUpdated, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("deployment_method"), knownvalue.StringExact("infrastructure-manager")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("infrastructure_manager_region"), knownvalue.StringExact("us-central1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("infra_project"), knownvalue.StringExact(infraProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project"), knownvalue.StringExact(wifProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("excluded_project_patterns"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("excluded_project_patterns").AtSliceIndex(0), knownvalue.StringExact("dev-*")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs-")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("-stg")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels"), knownvalue.MapSizeExact(3)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtMapKey("environment"), knownvalue.StringExact("staging")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtMapKey("managed-by"), knownvalue.StringExact("terraform")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("labels").AtMapKey("team"), knownvalue.StringExact("security")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags"), knownvalue.MapSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tags").AtMapKey("compliance"), knownvalue.StringExact("optional")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_Project(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	projectID2 := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("deployment_method"), knownvalue.StringExact("terraform-native")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("infra_project"), knownvalue.StringExact(infraProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project"), knownvalue.StringExact(wifProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID, projectID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("infra_project"), knownvalue.StringExact(infraProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project"), knownvalue.StringExact(wifProjectID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_Organization(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	orgIDUpdated := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("organization")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization"), knownvalue.StringExact(orgID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgIDUpdated, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("organization")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization"), knownvalue.StringExact(orgIDUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_RealtimeVisibility(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_realtimeVisibility(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_realtimeVisibility(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("realtime_visibility").AtMapKey("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.enabled"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_RequiresReplace(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	projectID2 := generateGoogleCloudProjectID()
	folderID := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	folderID2 := sdkacctest.RandStringFromCharSet(12, acctest.CharSetNum)
	orgID := generateGoogleCloudOrgID()
	orgID2 := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(1)),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID, projectID2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("project")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("projects"), knownvalue.SetSizeExact(2)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_folder(rName, folderID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("folder")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("folders"), knownvalue.SetSizeExact(1)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_folder(rName, folderID2, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("folder")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("folders"), knownvalue.SetSizeExact(1)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("organization")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization"), knownvalue.StringExact(orgID)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID2, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("registration_scope"), knownvalue.StringExact("organization")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization"), knownvalue.StringExact(orgID2)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_RemoveLabelsAndTags(t *testing.T) {
	t.Skip("labels and tags currently cannot be nulled out due to API limitations")
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_withLabelsAndTags(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttr(resourceName, "labels.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "labels.environment", "test"),
					resource.TestCheckResourceAttr(resourceName, "labels.managed-by", "terraform"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.team", "platform"),
					resource.TestCheckResourceAttr(resourceName, "tags.cost-center", "engineering"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckNoResourceAttr(resourceName, "labels.%"),
					resource.TestCheckNoResourceAttr(resourceName, "tags.%"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_RemoveResourceNamePrefixAndSuffix(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_withResourceNamePrefixAndSuffix(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_prefix"), knownvalue.StringExact("cs-")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("resource_name_suffix"), knownvalue.StringExact("-prod")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "resource_name_prefix"),
					resource.TestCheckNoResourceAttr(resourceName, "resource_name_suffix"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_InfrastructureManagerMissingRegion(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGoogleRegistrationConfig_infrastructureManagerMissingRegion(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				ExpectError: regexp.MustCompile("infrastructure_manager_region is required "),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_ExcludedProjectPatternsValidation(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_excludedPatterns(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, `["Test-*"]`),
				ExpectError: regexp.MustCompile(
					`(?s).*Attribute excluded_project_patterns\[0\] must contain only lowercase letters.*got: Test-\*`,
				),
				PlanOnly: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_excludedPatterns(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, `["sys-.*-dev"]`),
				ExpectError: regexp.MustCompile(
					`(?s).*Attribute excluded_project_patterns\[0\] must contain only lowercase letters.*got: sys-`,
				),
				PlanOnly: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_excludedPatterns(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, `["test_dev"]`),
				ExpectError: regexp.MustCompile(
					`(?s).*Attribute excluded_project_patterns\[0\] must contain only lowercase letters.*got: test_dev`,
				),
				PlanOnly: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_excludedPatterns(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, `["*"]`),
				ExpectError: regexp.MustCompile(
					`(?s).*Attribute excluded_project_patterns\[0\] value must be none of:.*got: "\*"`,
				),
				PlanOnly: true,
			},
		},
	})
}

func testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber string, projectIDs ...string) string {
	projectsList := make([]string, len(projectIDs))
	for i, pid := range projectIDs {
		projectsList[i] = fmt.Sprintf("%q", pid)
	}

	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name = %[1]q
  projects            = [%[5]s]
  infra_project       = %[2]q
  wif_project         = %[3]q
  wif_project_number  = %[4]q
}
`, rName, infraProjectID, wifProjectID, wifProjectNumber, strings.Join(projectsList, ", "))
}

func testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name = %[1]q
  organization        = %[2]q
  infra_project       = %[3]q
  wif_project         = %[4]q
  wif_project_number  = %[5]q
}
`, rName, orgID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_realtimeVisibility(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name = %[1]q
  projects            = [%[2]q]
  infra_project       = %[3]q
  wif_project         = %[4]q
  wif_project_number  = %[5]q

  realtime_visibility = {
    enabled = %[6]t
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, enabled)
}

func testAccCloudGoogleRegistrationConfig_complete(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name              = %[1]q
  projects          = [%[2]q]
  infra_project     = %[3]q
  wif_project       = %[4]q
  wif_project_number = %[5]q
  deployment_method = "terraform-native"

  excluded_project_patterns = [
    "test-*",
    "*-sandbox"
  ]

  resource_name_prefix = "cs-"
  resource_name_suffix = "-prod"

  labels = {
    environment = "production"
    managed-by  = "terraform"
  }

  tags = {
    compliance = "required"
    owner      = "security-team"
  }

  realtime_visibility = {
    enabled = true
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_completeUpdated(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name                        = %[1]q
  projects                    = [%[2]q]
  infra_project               = %[3]q
  wif_project                 = %[4]q
  wif_project_number          = %[5]q
  deployment_method           = "infrastructure-manager"
  infrastructure_manager_region = "us-central1"

  excluded_project_patterns = [
    "dev-*"
  ]

  resource_name_prefix = "cs-"
  resource_name_suffix = "-stg"

  labels = {
    environment = "staging"
    managed-by  = "terraform"
    team        = "security"
  }

  tags = {
    compliance = "optional"
  }

  realtime_visibility = {
    enabled = false
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_withLabelsAndTags(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q
  wif_project_number = %[5]q

  labels = {
    environment = "test"
    managed-by  = "terraform"
  }

  tags = {
    team        = "platform"
    cost-center = "engineering"
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_withResourceNamePrefixAndSuffix(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name                 = %[1]q
  projects             = [%[2]q]
  infra_project        = %[3]q
  wif_project          = %[4]q
  wif_project_number   = %[5]q
  resource_name_prefix = "cs-"
  resource_name_suffix = "-prod"
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_folder(rName, folderID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name = %[1]q
  folders       = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q
  wif_project_number = %[5]q
}
`, rName, folderID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_infrastructureManagerMissingRegion(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name              = %[1]q
  projects          = [%[2]q]
  infra_project     = %[3]q
  wif_project       = %[4]q
  wif_project_number = %[5]q
  deployment_method = "infrastructure-manager"
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationConfig_excludedPatterns(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, patterns string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name                   = %[1]q
  projects               = [%[2]q]
  infra_project          = %[3]q
  wif_project            = %[4]q
  wif_project_number     = %[5]q
  excluded_project_patterns = %[6]s
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, patterns)
}

func TestAccCloudGoogleRegistrationResourceDSPM(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_dspm(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_dspm(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResourceVulnerabilityScanning(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_vulnerabilityScanning(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_vulnerabilityScanning(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResourceBothDSPMAndVulnScanning(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	resourceName := "crowdstrike_cloud_google_registration.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_bothFeatures(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("vulnerability_scanning").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_dspm(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("dspm").AtMapKey("enabled"), knownvalue.Bool(true)),
				},
			},
		},
	})
}

func testAccCloudGoogleRegistrationConfig_dspm(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name               = %[1]q
  projects           = [%[2]q]
  infra_project      = %[3]q
  wif_project        = %[4]q
  wif_project_number = %[5]q

  dspm = {
    enabled = %[6]t
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, enabled)
}

func testAccCloudGoogleRegistrationConfig_vulnerabilityScanning(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string, enabled bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name               = %[1]q
  projects           = [%[2]q]
  infra_project      = %[3]q
  wif_project        = %[4]q
  wif_project_number = %[5]q

  vulnerability_scanning = {
    enabled = %[6]t
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, enabled)
}

func testAccCloudGoogleRegistrationConfig_bothFeatures(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name               = %[1]q
  projects           = [%[2]q]
  infra_project      = %[3]q
  wif_project        = %[4]q
  wif_project_number = %[5]q

  dspm = {
    enabled = true
  }

  vulnerability_scanning = {
    enabled = true
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}
