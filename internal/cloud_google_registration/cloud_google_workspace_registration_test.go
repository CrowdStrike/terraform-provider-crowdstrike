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
	"github.com/hashicorp/terraform-plugin-testing/compare"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const googleWorkspaceResourceName = "crowdstrike_cloud_google_workspace_registration.test"

func generateGoogleWorkspaceCustomerID() string {
	return "C0" + sdkacctest.RandStringFromCharSet(7, "abcdefghijklmnopqrstuvwxyz0123456789")
}

func TestAccCloudGoogleWorkspaceRegistrationResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	orgIDUpdated := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	customerID := generateGoogleWorkspaceCustomerID()
	customerIDUpdated := generateGoogleWorkspaceCustomerID()

	gcpResourceName := "crowdstrike_cloud_google_registration.test"
	resourceName := googleWorkspaceResourceName

	registrationConfig := testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber)
	sameID := statecheck.CompareValue(compare.ValuesSame())
	newID := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerID, orgID)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("customer_id"), knownvalue.StringExact(customerID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization_id"), knownvalue.StringExact(orgID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_pool_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_provider_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("wif_identity_source"), knownvalue.StringRegexp(regexp.MustCompile(`^(aws-sts|gcp-oidc)$`))),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("service_account_id"), knownvalue.StringRegexp(regexp.MustCompile(`^csgws-[0-9a-f]{11}$`))),
					sameID.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(resourceName, "registration_id", gcpResourceName, "id"),
					testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI(),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateIdFunc:                    testAccImportIDFunc(resourceName, "registration_id"),
				ImportStateVerifyIdentifierAttribute: "registration_id",
			},
			{
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerID, orgIDUpdated)),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("organization_id"), knownvalue.StringExact(orgIDUpdated)),
					sameID.AddStateValue(resourceName, tfjsonpath.New("id")),
					newID.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
				Check: testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI(),
			},
			{
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerIDUpdated, orgIDUpdated)),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("customer_id"), knownvalue.StringExact(customerIDUpdated)),
					newID.AddStateValue(resourceName, tfjsonpath.New("id")),
				},
				Check: testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI(),
			},
			{
				Config:             acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerIDUpdated, orgIDUpdated)),
				Check:              testAccDeleteGoogleWorkspace(gcpResourceName),
				ExpectNonEmptyPlan: true,
			},
			{
				// The refresh drops the deleted Workspace, so the apply creates a new one.
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerIDUpdated, orgIDUpdated)),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionCreate),
					},
				},
				Check: testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI(),
			},
			{
				Config: registrationConfig,
				Check:  testAccCheckCloudGoogleWorkspaceRegistrationDeleted(gcpResourceName),
			},
		},
	})
}

func TestAccCloudGoogleWorkspaceRegistrationResource_Adopt(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	orgID := generateGoogleCloudOrgID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	customerID := generateGoogleWorkspaceCustomerID()
	customerIDUpdated := generateGoogleWorkspaceCustomerID()

	gcpResourceName := "crowdstrike_cloud_google_registration.test"
	resourceName := googleWorkspaceResourceName

	registrationConfig := testAccCloudGoogleRegistrationConfig_organization(rName, orgID, infraProjectID, wifProjectID, wifProjectNumber)
	var consoleWorkspaceID string

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: registrationConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccAddGoogleWorkspace(gcpResourceName, customerID, orgID),
					testAccGetGoogleWorkspaceID(gcpResourceName, &consoleWorkspaceID),
				),
			},
			{
				// The resource adopts the Workspace from the console and changes its customer ID, which has no settings yet.
				Config: acctest.ConfigCompose(registrationConfig, testAccCloudGoogleWorkspaceRegistrationConfig("test", customerIDUpdated, orgID)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("customer_id"), knownvalue.StringExact(customerIDUpdated)),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrWith(resourceName, "id", func(value string) error {
						if value != consoleWorkspaceID {
							return fmt.Errorf("id is %q, but the Workspace from the console is %q", value, consoleWorkspaceID)
						}
						return nil
					}),
					testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI(),
				),
			},
			{
				Config: registrationConfig,
				Check:  testAccCheckCloudGoogleWorkspaceRegistrationDeleted(gcpResourceName),
			},
		},
	})
}

func TestAccCloudGoogleWorkspaceRegistrationResource_Validation(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testAccCloudGoogleWorkspaceRegistrationConfig_literal("c01abc2de", "123456789012"),
				ExpectError: regexp.MustCompile(`must be an uppercase C followed by lowercase\s+letters\s+and\s+digits`),
				PlanOnly:    true,
			},
			{
				Config:      testAccCloudGoogleWorkspaceRegistrationConfig_literal("C01ABC2DE", "123456789012"),
				ExpectError: regexp.MustCompile(`must be an uppercase C followed by lowercase\s+letters\s+and\s+digits`),
				PlanOnly:    true,
			},
			{
				Config:      testAccCloudGoogleWorkspaceRegistrationConfig_literal("C01abc2de", "organizations/123456789012"),
				ExpectError: regexp.MustCompile(`must be numeric`),
				PlanOnly:    true,
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

// testAccDeleteGoogleWorkspace deletes the Workspace of the GCP registration in state, as a user can do in the Falcon console.
func testAccDeleteGoogleWorkspace(gcpResourceName string) resource.TestCheckFunc {
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
		return nil
	}
}

// testAccReplaceGoogleWorkspace deletes the Workspace and adds a new one, as a user can do in the Falcon console.
func testAccReplaceGoogleWorkspace(gcpResourceName, customerID, organizationID string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		testAccDeleteGoogleWorkspace(gcpResourceName),
		testAccAddGoogleWorkspace(gcpResourceName, customerID, organizationID),
	)
}

// testAccGetGoogleWorkspaceID stores the Workspace ID of the GCP registration in state.
func testAccGetGoogleWorkspaceID(gcpResourceName string, workspaceID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[gcpResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", gcpResourceName)
		}

		workspace, err := testAccGetGoogleWorkspace(rs.Primary.ID)
		if err != nil {
			return err
		}
		if workspace.RegistrationID == "" {
			return fmt.Errorf("Google Cloud registration %s has no Google Workspace registration", rs.Primary.ID)
		}
		*workspaceID = workspace.RegistrationID
		return nil
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

// testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI compares the state of the test Workspace resource to the API.
func testAccCheckCloudGoogleWorkspaceRegistrationMatchesAPI() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[googleWorkspaceResourceName]
		if !ok {
			return fmt.Errorf("Resource not found: %s", googleWorkspaceResourceName)
		}

		workspace, err := testAccGetGoogleWorkspace(rs.Primary.Attributes["registration_id"])
		if err != nil {
			return err
		}
		identity := workspace.FederatedIdentity
		if identity == nil {
			return fmt.Errorf("Google Workspace registration %s has no federated identity", workspace.RegistrationID)
		}

		for attribute, want := range map[string]string{
			"id":                  workspace.RegistrationID,
			"customer_id":         workspace.CustomerID,
			"organization_id":     workspace.OrganizationID,
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

// testAccCheckCloudGoogleWorkspaceRegistrationDeleted runs while the GCP registration exists, because its delete also deletes the Workspace.
func testAccCheckCloudGoogleWorkspaceRegistrationDeleted(gcpResourceName string) resource.TestCheckFunc {
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

func testAccImportIDFunc(resourceName, attribute string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Resource not found: %s", resourceName)
		}
		return rs.Primary.Attributes[attribute], nil
	}
}

// testAccCloudGoogleWorkspaceRegistrationConfig adds a Workspace resource with the given name to the test GCP registration.
func testAccCloudGoogleWorkspaceRegistrationConfig(name, customerID, organizationID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_workspace_registration" %[1]q {
  registration_id = crowdstrike_cloud_google_registration.test.id
  customer_id     = %[2]q
  organization_id = %[3]q
}
`, name, customerID, organizationID)
}

func testAccCloudGoogleWorkspaceRegistrationConfig_literal(customerID, organizationID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_workspace_registration" "test" {
  registration_id = "00000000-0000-0000-0000-000000000000"
  customer_id     = %[1]q
  organization_id = %[2]q
}
`, customerID, organizationID)
}
