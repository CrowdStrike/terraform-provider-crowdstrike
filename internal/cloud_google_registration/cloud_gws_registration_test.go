package cloudgoogleregistration_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_google_cloud_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/go-openapi/swag"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func generateGoogleWorkspaceCustomerID() string {
	return "C0" + sdkacctest.RandStringFromCharSet(7, "abcdefghijklmnopqrstuvwxyz0123456789")
}

func TestAccCloudGwsRegistrationResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	customerID := generateGoogleWorkspaceCustomerID()

	gcpResourceName := "crowdstrike_cloud_google_registration.test"
	resourceName := "crowdstrike_cloud_gws_registration.test"

	registrationConfig := testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: registrationConfig,
				Check:  testAccAddGoogleWorkspace(gcpResourceName, customerID, orgID),
			},
			{
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGwsRegistrationConfig_basic()),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.StringRegexp(regexp.MustCompile(`^(aws-sts|gcp-oidc)$`))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("service_account_id"), knownvalue.StringRegexp(regexp.MustCompile(`^csgws-[0-9a-f]{11}$`))),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "gcp_registration_id", gcpResourceName, "id"),
					testAccCheckCloudGwsRegistrationMatchesAPI(resourceName),
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
				Config:      acctest.ConfigCompose(registrationConfig, testAccCloudGwsRegistrationConfig_literal("00000000-0000-0000-0000-000000000000")),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Google Cloud Registration ID Cannot\s+Change`),
			},
			{
				Config: registrationConfig,
				Check:  testAccCheckCloudGwsRegistrationDeleted(gcpResourceName),
			},
		},
	})
}

func TestAccCloudGwsRegistrationResource_NoWorkspace(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber),
					testAccCloudGwsRegistrationConfig_basic(),
				),
				ExpectError: regexp.MustCompile(`has no Google\s+Workspace\s+registration`),
			},
		},
	})
}

// testAccAddGoogleWorkspace adds a Workspace to the GCP registration in state, as the Falcon console does.
func testAccAddGoogleWorkspace(gcpResourceName, customerID, organizationID string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[gcpResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", gcpResourceName)
		}

		params := &cloud_google_cloud_registration.CloudRegistrationGcpUpdateRegistrationParams{
			Context: context.Background(),
			Ids:     rs.Primary.ID,
			Body: &models.DtoGCPRegistrationUpdateRequestExtV1{
				Resources: []*models.DtoUpdateGCPRegistrationRequest{
					{GoogleWorkspace: &models.DtoWorkspaceRequest{
						Enabled:        swag.Bool(true),
						CustomerID:     customerID,
						OrganizationID: organizationID,
					}},
				},
			},
		}

		_, err := testconfig.GetTestClient().CloudGoogleCloudRegistration.CloudRegistrationGcpUpdateRegistration(params)
		if err != nil {
			return fmt.Errorf("failed to add the Google Workspace to registration %s: %w", rs.Primary.ID, err)
		}
		return nil
	}
}

// testAccReplaceGoogleWorkspace deletes the Workspace and adds a new one, as a user can do in the Falcon console.
func testAccReplaceGoogleWorkspace(gcpResourceName, customerID, organizationID string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[gcpResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", gcpResourceName)
		}

		params := cloud_google_cloud_registration.NewCloudRegistrationGcpDeleteWorkspaceRegistrationParams().
			WithContext(context.Background()).
			WithGcpRegistrationID(rs.Primary.ID)

		if _, err := testconfig.GetTestClient().CloudGoogleCloudRegistration.CloudRegistrationGcpDeleteWorkspaceRegistration(params); err != nil {
			return fmt.Errorf("failed to delete the Google Workspace of registration %s: %w", rs.Primary.ID, err)
		}
		return testAccAddGoogleWorkspace(gcpResourceName, customerID, organizationID)(s)
	}
}

// testAccGetGoogleWorkspace reads the Workspace block of a GCP registration; no block is an error.
func testAccGetGoogleWorkspace(gcpRegistrationID string) (*models.DtoWorkspaceProperties, error) {
	params := cloud_google_cloud_registration.NewCloudRegistrationGcpGetRegistrationParams().
		WithContext(context.Background()).
		WithIds(gcpRegistrationID)

	res, err := testconfig.GetTestClient().CloudGoogleCloudRegistration.CloudRegistrationGcpGetRegistration(params)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google Cloud registration %s: %w", gcpRegistrationID, err)
	}
	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil ||
		res.Payload.Resources[0].GoogleWorkspace == nil {
		return nil, fmt.Errorf("Google Cloud registration %s has no Google Workspace block", gcpRegistrationID)
	}
	return res.Payload.Resources[0].GoogleWorkspace, nil
}

func testAccCheckCloudGwsRegistrationMatchesAPI(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", resourceName)
		}

		workspace, err := testAccGetGoogleWorkspace(rs.Primary.Attributes["gcp_registration_id"])
		if err != nil {
			return err
		}
		identity := workspace.FederatedIdentity
		if identity == nil {
			return fmt.Errorf("Google Workspace registration %s has no federated identity", workspace.RegistrationID)
		}

		for attribute, want := range map[string]string{
			"id":                  workspace.RegistrationID,
			"wif_pool_id":         identity.IdentityPoolID,
			"wif_provider_id":     identity.ProviderID,
			"wif_identity_source": identity.IdentitySource,
			"service_account_id":  identity.ServiceAccountID,
		} {
			if got := rs.Primary.Attributes[attribute]; got != want {
				return fmt.Errorf("%s is %q in state, but the API returns %q", attribute, got, want)
			}
		}
		return nil
	}
}

// testAccCheckCloudGwsRegistrationDeleted runs while the GCP registration exists, because its delete also deletes the Workspace.
func testAccCheckCloudGwsRegistrationDeleted(gcpResourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[gcpResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", gcpResourceName)
		}

		workspace, err := testAccGetGoogleWorkspace(rs.Primary.ID)
		if err != nil {
			return err
		}
		if workspace.RegistrationID != "" {
			return fmt.Errorf("Google Workspace registration %s still exists", workspace.RegistrationID)
		}
		return nil
	}
}

func testAccGcpRegistrationIDFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Resource not found: %s", resourceName)
		}
		return rs.Primary.Attributes["gcp_registration_id"], nil
	}
}

func testAccCloudGwsRegistrationConfig_basic() string {
	return `
resource "crowdstrike_cloud_gws_registration" "test" {
  gcp_registration_id = crowdstrike_cloud_google_registration.test.id
}
`
}

func testAccCloudGwsRegistrationConfig_literal(gcpRegistrationID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_gws_registration" "test" {
  gcp_registration_id = %q
}
`, gcpRegistrationID)
}
