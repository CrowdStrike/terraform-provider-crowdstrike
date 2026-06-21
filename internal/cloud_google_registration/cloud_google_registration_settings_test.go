package cloudgoogleregistration_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCloudGoogleRegistrationSettingsResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	rtvdEnabled := true

	projectResourceName := "crowdstrike_cloud_google_registration.test"
	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"

	registrationConfig := cloudGoogleRegistrationConfig(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, rtvdEnabled)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_basic(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_sink_name"), knownvalue.StringExact("test-sink")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_topic_id"), knownvalue.StringExact("test-topic")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_subscription_name"), knownvalue.StringExact("test-subscription")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("wif_pool_name"), knownvalue.StringExact("test-pool")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("wif_provider_name"), knownvalue.StringExact("test-provider")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
				),
			},
			{
				ResourceName:      settingsResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[settingsResourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", settingsResourceName)
					}
					return rs.Primary.Attributes["registration_id"], nil
				},
				ImportStateVerifyIdentifierAttribute: "registration_id",
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_withoutSettings(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_sink_name"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_topic_id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_subscription_name"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "wif_pool_name"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "wif_provider_name"),
				),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_updated(),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_sink_name"), knownvalue.StringExact("test-sink-updated")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_topic_id"), knownvalue.StringExact("test-topic-updated")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("log_ingestion_subscription_name"), knownvalue.StringExact("test-subscription-updated")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("wif_pool_name"), knownvalue.StringExact("test-pool-updated")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("wif_provider_name"), knownvalue.StringExact("test-provider-updated")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResource_IOANotEnabled(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	rtvdEnabled := false

	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"
	projectResourceName := "crowdstrike_cloud_google_registration.test"

	registrationConfig := cloudGoogleRegistrationConfig(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, rtvdEnabled)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_basic(),
				),
				ExpectError: regexp.MustCompile(`realtime_visibility with IOA`),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_withoutSettings(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_sink_name"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_topic_id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_subscription_name"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResourceAgentlessScanning(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"
	projectResourceName := "crowdstrike_cloud_google_registration.test"

	registrationConfig := cloudGoogleRegistrationConfigWithDSPM(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanning(projectID),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("wif_principal"), knownvalue.StringExact("principal://test-wif-principal")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("deployment_version"), knownvalue.StringExact("1.0.0")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("network_configuration_type"), knownvalue.StringExact("managed")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "agentless_scanning_settings.regions.#", "1"),
					resource.TestCheckResourceAttr(settingsResourceName, "agentless_scanning_settings.infra.%", "1"),
					resource.TestCheckResourceAttr(settingsResourceName, fmt.Sprintf("agentless_scanning_settings.infra.%s.scanner_sa_email", projectID), "scanner@test.iam.gserviceaccount.com"),
					resource.TestCheckResourceAttr(settingsResourceName, fmt.Sprintf("agentless_scanning_settings.infra.%s.client_credentials_secret_name", projectID), "csscanning-falcon-credentials"),
				),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningUpdated(projectID),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("deployment_version"), knownvalue.StringExact("1.1.0")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsResourceName, "agentless_scanning_settings.regions.#", "2"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResourceAgentlessScanningNotEnabled(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()
	rtvdEnabled := false

	registrationConfig := cloudGoogleRegistrationConfig(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, rtvdEnabled)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanning(projectID),
				),
				ExpectError: regexp.MustCompile(`Agentless Scanning Not Enabled`),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResourceAgentlessScanningCrossProject(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"

	registrationConfig := cloudGoogleRegistrationConfigWithDSPM(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningWithCrossProject(infraProjectID),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("host_project_id"), knownvalue.StringExact(infraProjectID)),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsResourceName, "agentless_scanning_settings.infra.%", "1"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResourceAgentlessScanningCustomNetwork(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"

	registrationConfig := cloudGoogleRegistrationConfigWithDSPM(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningWithCustomNetwork(projectID),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("network_configuration_type"), knownvalue.StringExact("custom")),
					statecheck.ExpectKnownValue(settingsResourceName, tfjsonpath.New("agentless_scanning_settings").AtMapKey("custom_network").AtMapKey("vpc_name"), knownvalue.StringExact("customer-vpc")),
				},
			},
		},
	})
}

func TestAccCloudGoogleRegistrationSettingsResourceAgentlessScanningImport(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()
	wifProjectNumber := generateGoogleCloudProjectNumber()

	settingsResourceName := "crowdstrike_cloud_google_registration_settings.test"

	registrationConfig := cloudGoogleRegistrationConfigWithDSPM(rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationSettingsConfig_agentlessScanning(projectID),
				),
			},
			{
				ResourceName:      settingsResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[settingsResourceName]
					if !ok {
						return "", fmt.Errorf("Resource not found: %s", settingsResourceName)
					}
					return rs.Primary.Attributes["registration_id"], nil
				},
				ImportStateVerifyIdentifierAttribute: "registration_id",
			},
		},
	})
}

func cloudGoogleRegistrationConfig(
	rName,
	projectID,
	infraProjectID,
	wifProjectID,
	wifProjectNumber string,
	rtvdEnabled bool,
) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name               = %[1]q
  projects           = [%[2]q]
  infra_project      = %[3]q
  wif_project        = %[4]q
  wif_project_number = %[5]q

  realtime_visibility = {
    enabled = %[6]t 
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber, rtvdEnabled)
}

func testAccCloudGoogleRegistrationSettingsConfig_basic() string {
	return `
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink"
  log_ingestion_topic_id          = "test-topic"
  log_ingestion_subscription_name = "test-subscription"
  wif_pool_name                   = "test-pool"
  wif_provider_name               = "test-provider"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}

func testAccCloudGoogleRegistrationSettingsConfig_withoutSettings() string {
	return `
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}

func testAccCloudGoogleRegistrationSettingsConfig_updated() string {
	return `
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink-updated"
  log_ingestion_topic_id          = "test-topic-updated"
  log_ingestion_subscription_name = "test-subscription-updated"
  wif_pool_name                   = "test-pool-updated"
  wif_provider_name               = "test-provider-updated"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}

func cloudGoogleRegistrationConfigWithDSPM(
	rName,
	projectID,
	infraProjectID,
	wifProjectID,
	wifProjectNumber string,
) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name               = %[1]q
  projects           = [%[2]q]
  infra_project      = %[3]q
  wif_project        = %[4]q
  wif_project_number = %[5]q

  dspm = {
    enabled = true
  }
}
`, rName, projectID, infraProjectID, wifProjectID, wifProjectNumber)
}

func testAccCloudGoogleRegistrationSettingsConfig_agentlessScanning(projectID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id
  wif_pool_name   = "test-pool"
  wif_provider_name = "test-provider"

  agentless_scanning_settings = {
    wif_principal              = "principal://test-wif-principal"
    deployment_version         = "1.0.0"
    regions                    = ["us-east1"]
    network_configuration_type = "managed"

    infra = {
      %[1]q = {
        scanner_sa_email               = "scanner@test.iam.gserviceaccount.com"
        client_credentials_secret_name = "csscanning-falcon-credentials"
        network = {
          vpc_name = "test-vpc"
          subnets  = { "us-east1" = "test-subnet-us-east1" }
        }
      }
    }
  }

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, projectID)
}

func testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningUpdated(projectID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id
  wif_pool_name   = "test-pool"
  wif_provider_name = "test-provider"

  agentless_scanning_settings = {
    wif_principal              = "principal://test-wif-principal"
    deployment_version         = "1.1.0"
    regions                    = ["us-east1", "us-west1"]
    network_configuration_type = "managed"

    infra = {
      %[1]q = {
        scanner_sa_email               = "scanner@test.iam.gserviceaccount.com"
        client_credentials_secret_name = "csscanning-falcon-credentials"
        network = {
          vpc_name = "test-vpc"
          subnets  = {
            "us-east1" = "test-subnet-us-east1"
            "us-west1" = "test-subnet-us-west1"
          }
        }
      }
    }
  }

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, projectID)
}

func testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningWithCrossProject(infraProjectID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id
  wif_pool_name   = "test-pool"
  wif_provider_name = "test-provider"

  agentless_scanning_settings = {
    wif_principal              = "principal://test-wif-principal"
    deployment_version         = "1.0.0"
    regions                    = ["us-east1"]
    host_project_id            = %[1]q
    network_configuration_type = "managed"

    infra = {
      %[1]q = {
        scanner_sa_email               = "scanner@test.iam.gserviceaccount.com"
        client_credentials_secret_name = "csscanning-falcon-credentials"
        network = {
          vpc_name = "test-vpc"
          subnets  = { "us-east1" = "test-subnet-us-east1" }
        }
      }
    }
  }

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, infraProjectID)
}

func testAccCloudGoogleRegistrationSettingsConfig_agentlessScanningWithCustomNetwork(projectID string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id
  wif_pool_name   = "test-pool"
  wif_provider_name = "test-provider"

  agentless_scanning_settings = {
    wif_principal              = "principal://test-wif-principal"
    deployment_version         = "1.0.0"
    regions                    = ["us-east1"]
    host_project_id            = %[1]q
    network_configuration_type = "custom"

    custom_network = {
      vpc_name = "customer-vpc"
      subnets  = { "us-east1" = "customer-subnet-us-east1" }
    }

    infra = {
      %[1]q = {
        scanner_sa_email               = "scanner@test.iam.gserviceaccount.com"
        client_credentials_secret_name = "csscanning-falcon-credentials"
        network = {
          vpc_name = "customer-vpc"
          subnets  = { "us-east1" = "customer-subnet-us-east1" }
        }
      }
    }
  }

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, projectID)
}
