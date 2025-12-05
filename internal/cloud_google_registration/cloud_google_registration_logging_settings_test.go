package cloudgoogleregistration_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccCloudGoogleRegistrationLoggingSettingsResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()

	projectResourceName := "crowdstrike_cloud_google_registration.test"
	settingsResourceName := "crowdstrike_cloud_google_registration_logging_settings.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationLoggingSettingsConfig_basic(
					rName,
					projectID,
					infraProjectID,
					wifProjectID,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_sink_name", "test-sink"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_topic_id", "test-topic"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_subscription_name", "test-subscription"),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project_number", "123456789012"),
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
				Config: testAccCloudGoogleRegistrationLoggingSettingsConfig_withoutLoggingParams(
					rName,
					projectID,
					infraProjectID,
					wifProjectID,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project_number", "123456789012"),
				),
			},
			{
				Config: testAccCloudGoogleRegistrationLoggingSettingsConfig_updated(
					rName,
					projectID,
					infraProjectID,
					wifProjectID,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_sink_name", "test-sink-updated"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_topic_id", "test-topic-updated"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_subscription_name", "test-subscription-updated"),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project", wifProjectID),
					resource.TestCheckResourceAttr(settingsResourceName, "wif_project_number", "123456789012"),
				),
			},
		},
	})
}

func TestAccCloudGoogleRegistrationLoggingSettingsResource_IOANotEnabled(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	projectID := generateGoogleCloudProjectID()
	infraProjectID := generateGoogleCloudProjectID()
	wifProjectID := generateGoogleCloudProjectID()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccCloudGoogleRegistrationLoggingSettingsConfig_noIOA(
					rName,
					projectID,
					infraProjectID,
					wifProjectID,
				),
				ExpectError: regexp.MustCompile(`realtime_visibility with IOA`),
			},
		},
	})
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_basic(
	rName,
	projectID,
	infraProjectID,
	wifProjectID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q

  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink"
  log_ingestion_topic_id          = "test-topic"
  log_ingestion_subscription_name = "test-subscription"
  wif_project                     = %[4]q
  wif_project_number              = "123456789012"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, rName, projectID, infraProjectID, wifProjectID)
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_withoutLoggingParams(
	rName,
	projectID,
	infraProjectID,
	wifProjectID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q

  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id    = crowdstrike_cloud_google_registration.test.id
  wif_project        = %[4]q
  wif_project_number = "123456789012"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, rName, projectID, infraProjectID, wifProjectID)
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_updated(
	rName,
	projectID,
	infraProjectID,
	wifProjectID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q

  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink-updated"
  log_ingestion_topic_id          = "test-topic-updated"
  log_ingestion_subscription_name = "test-subscription-updated"
  wif_project                     = %[4]q
  wif_project_number              = "123456789012"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, rName, projectID, infraProjectID, wifProjectID)
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_noIOA(
	rName,
	projectID,
	infraProjectID,
	wifProjectID string,
) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q
}

resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink"
  log_ingestion_topic_id          = "test-topic"
  log_ingestion_subscription_name = "test-subscription"
  wif_project                     = %[4]q
  wif_project_number              = "123456789012"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`, rName, projectID, infraProjectID, wifProjectID)
}
