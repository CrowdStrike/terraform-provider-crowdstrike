package cloudgoogleregistration_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "deployment_method", "terraform-native"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttr(resourceName, "excluded_project_patterns.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "excluded_project_patterns.0", "sys-test-.*"),
					resource.TestCheckResourceAttr(resourceName, "excluded_project_patterns.1", "sys-.*-sandbox$"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_prefix", "cs-"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_suffix", "-prod"),
					resource.TestCheckResourceAttr(resourceName, "labels.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "labels.environment", "production"),
					resource.TestCheckResourceAttr(resourceName, "labels.managed-by", "terraform"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.compliance", "required"),
					resource.TestCheckResourceAttr(resourceName, "tags.owner", "security-team"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_completeUpdated(rNameUpdated, projectID, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rNameUpdated),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "deployment_method", "infrastructure-manager"),
					resource.TestCheckResourceAttr(resourceName, "infrastructure_manager_region", "us-central1"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "excluded_project_patterns.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "excluded_project_patterns.0", "sys-dev-.*"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_prefix", "cs-"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_suffix", "-stg"),
					resource.TestCheckResourceAttr(resourceName, "labels.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "labels.environment", "staging"),
					resource.TestCheckResourceAttr(resourceName, "labels.managed-by", "terraform"),
					resource.TestCheckResourceAttr(resourceName, "labels.team", "security"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.compliance", "optional"),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "deployment_method", "terraform-native"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID, projectID2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "deployment_method", "terraform-native"),
					resource.TestCheckResourceAttr(resourceName, "infra_project", infraProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_Organization(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "organization"),
					resource.TestCheckResourceAttr(resourceName, "organization", orgID),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgIDUpdated, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "organization"),
					resource.TestCheckResourceAttr(resourceName, "organization", orgIDUpdated),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationResource_RealtimeVisibility(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_pool_id"),
					resource.TestCheckResourceAttrSet(resourceName, "wif_provider_id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_realtimeVisibility(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "realtime_visibility.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "wif_project_number", wifProjectNumber),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "realtime_visibility.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "1"),
				),
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID, projectID2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "project"),
					resource.TestCheckResourceAttr(resourceName, "projects.#", "2"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_folder(rName, folderID, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "folder"),
					resource.TestCheckResourceAttr(resourceName, "folders.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_folder(rName, folderID2, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "folder"),
					resource.TestCheckResourceAttr(resourceName, "folders.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "organization"),
					resource.TestCheckResourceAttr(resourceName, "organization", orgID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID2, infraProjectID, wifProjectID, wifProjectNumber),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "registration_scope", "organization"),
					resource.TestCheckResourceAttr(resourceName, "organization", orgID2),
				),
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "resource_name_prefix", "cs-"),
					resource.TestCheckResourceAttr(resourceName, "resource_name_suffix", "-prod"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
			},
			{
				Config: testAccCloudGoogleRegistrationConfig_project(rName, infraProjectID, wifProjectID, wifProjectNumber, projectID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckNoResourceAttr(resourceName, "resource_name_prefix"),
					resource.TestCheckNoResourceAttr(resourceName, "resource_name_suffix"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
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
    "sys-test-.*",
    "sys-.*-sandbox$"
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
    "sys-dev-.*"
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
