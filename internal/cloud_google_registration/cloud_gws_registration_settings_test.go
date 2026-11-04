package cloudgoogleregistration_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func generateGoogleServiceAccountUniqueID() string {
	return sdkacctest.RandStringFromCharSet(21, acctest.CharSetNum)
}

func TestAccCloudGwsRegistrationSettingsResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	wifProjectNumberUpdated := generateGoogleCloudProjectNumber()
	customerID := generateGoogleWorkspaceCustomerID()
	customerIDReplaced := generateGoogleWorkspaceCustomerID()
	saUniqueID := generateGoogleServiceAccountUniqueID()
	saUniqueIDUpdated := generateGoogleServiceAccountUniqueID()

	gcpResourceName := "crowdstrike_cloud_google_registration.test"
	gwsResourceName := "crowdstrike_cloud_gws_registration.test"
	resourceName := "crowdstrike_cloud_gws_registration_settings.test"

	registrationConfig := acctest.ConfigCompose(
		testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
		testAccCloudGwsRegistrationConfig_basic(),
	)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
				Check:  testAccAddGoogleWorkspace(gcpResourceName, customerID, orgID),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(`"00000000-0000-0000-0000-000000000000"`, wifProjectID, wifProjectNumber, saUniqueID, "aws-role"),
				),
				ExpectError: regexp.MustCompile(`has no Google\s+Workspace\s+registration\s+00000000-0000-0000-0000-000000000000`),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueID, "aws-role"),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sa_unique_id"), knownvalue.StringExact(saUniqueID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("project_number"), knownvalue.StringExact(wifProjectNumber)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sa_email"), knownvalue.StringRegexp(regexp.MustCompile(`^csgws-[0-9a-f]{11}@`+regexp.QuoteMeta(wifProjectID)+`\.iam\.gserviceaccount\.com$`))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_principal"), knownvalue.StringRegexp(regexp.MustCompile(`/subject/aws-role/`))),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "gcp_registration_id", gwsResourceName, "gcp_registration_id"),
					resource.TestCheckResourceAttrPair(resourceName, "registration_id", gwsResourceName, "id"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateIdFunc:                    testAccGcpRegistrationIDFunc(resourceName),
				ImportStateVerifyIdentifierAttribute: "gcp_registration_id",
			},
			{
				// A second state for a Workspace with settings deletes it on destroy, so Create refuses it.
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueID, "aws-role"),
					testAccCloudGwsRegistrationConfig_second(),
				),
				ExpectError: regexp.MustCompile(`already\s+has\s+settings`),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueIDUpdated, "aws-role-updated"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sa_unique_id"), knownvalue.StringExact(saUniqueIDUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_principal"), knownvalue.StringRegexp(regexp.MustCompile(`/subject/aws-role-updated/`))),
				},
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumberUpdated, saUniqueIDUpdated, "aws-role-updated"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ExpectError: regexp.MustCompile(`409 Conflict`),
			},
			{
				// The 409 writes nothing, so the stored settings still match the previous config.
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueIDUpdated, "aws-role-updated"),
				),
				PlanOnly: true,
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueIDUpdated, "aws-role-updated"),
				),
				Check:              testAccReplaceGoogleWorkspace(gcpResourceName, customerIDReplaced, orgID),
				ExpectNonEmptyPlan: true,
			},
			{
				// The refresh drops both resources of the deleted Workspace, so the apply adopts and configures the new one.
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGwsRegistrationSettingsConfig(gwsRegistrationIDRef, wifProjectID, wifProjectNumber, saUniqueIDUpdated, "aws-role-updated"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(gwsResourceName, plancheck.ResourceActionCreate),
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("sa_unique_id"), knownvalue.StringExact(saUniqueIDUpdated)),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "registration_id", gwsResourceName, "id"),
					testAccCheckCloudGwsRegistrationMatchesAPI(gwsResourceName),
				),
			},
			{
				Config: registrationConfig,
				Check:  testAccCheckCloudGwsRegistrationSettingsCleared(gcpResourceName),
			},
		},
	})
}

func TestAccCloudGwsRegistrationSettingsResource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGwsRegistrationSettingsConfig_literal("sa@project.iam.gserviceaccount.com", "12345", "principal://iam.googleapis.com/x", "12a"),
				ExpectError: regexp.MustCompile(`must be numeric`),
				PlanOnly:    true,
			},
			{
				Config:      testAccCloudGwsRegistrationSettingsConfig_literal("sa@project.iam.gserviceaccount.com", "12345", "https://iam.googleapis.com/x", "123"),
				ExpectError: regexp.MustCompile(`must start with\s+principal://iam.googleapis.com/`),
				PlanOnly:    true,
			},
		},
	})
}

func testAccCheckCloudGwsRegistrationSettingsCleared(gcpResourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[gcpResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", gcpResourceName)
		}

		workspace, err := testAccGetGoogleWorkspace(rs.Primary.ID)
		if err != nil {
			return err
		}
		identity := workspace.FederatedIdentity
		if identity == nil {
			return fmt.Errorf("Google Workspace registration %s has no federated identity", workspace.RegistrationID)
		}
		if identity.SaUniqueID != "" || identity.ProjectNumber != "" {
			return fmt.Errorf("Google Workspace registration settings were not cleared: sa_unique_id %q, project_number %q", identity.SaUniqueID, identity.ProjectNumber)
		}
		return nil
	}
}

const gwsRegistrationIDRef = "crowdstrike_cloud_gws_registration.test.id"

// testAccCloudGwsRegistrationSettingsConfig takes registrationID as an HCL expression.
func testAccCloudGwsRegistrationSettingsConfig(registrationID, wifProjectID, projectNumber, saUniqueID, subject string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_gws_registration_settings" "test" {
  gcp_registration_id = crowdstrike_cloud_gws_registration.test.gcp_registration_id
  registration_id     = %[5]s
  sa_email            = "${crowdstrike_cloud_gws_registration.test.service_account_id}@%[1]s.iam.gserviceaccount.com"
  sa_unique_id        = %[3]q
  wif_principal       = "principal://iam.googleapis.com/projects/%[2]s/locations/global/workloadIdentityPools/${crowdstrike_cloud_gws_registration.test.wif_pool_id}/subject/%[4]s/${crowdstrike_cloud_gws_registration.test.id}"
  project_number      = %[2]q
}
`, wifProjectID, projectNumber, saUniqueID, subject, registrationID)
}

func testAccCloudGwsRegistrationConfig_second() string {
	return `
resource "crowdstrike_cloud_gws_registration" "second" {
  gcp_registration_id = crowdstrike_cloud_google_registration.test.id
}
`
}

func testAccCloudGwsRegistrationSettingsConfig_literal(saEmail, saUniqueID, wifPrincipal, projectNumber string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_gws_registration_settings" "test" {
  gcp_registration_id = "00000000-0000-0000-0000-000000000000"
  registration_id     = "00000000-0000-0000-0000-000000000000"
  sa_email            = %[1]q
  sa_unique_id        = %[2]q
  wif_principal       = %[3]q
  project_number      = %[4]q
}
`, saEmail, saUniqueID, wifPrincipal, projectNumber)
}
