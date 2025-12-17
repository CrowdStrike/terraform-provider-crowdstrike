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
	rtvdEnabled := true

	projectResourceName := "crowdstrike_cloud_google_registration.test"
	settingsResourceName := "crowdstrike_cloud_google_registration_logging_settings.test"

	registrationConfig := cloudGoogleRegistrationConfig(rName, projectID, infraProjectID, wifProjectID, rtvdEnabled)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationLoggingSettingsConfig_basic(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_sink_name", "test-sink"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_topic_id", "test-topic"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_subscription_name", "test-subscription"),
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
					testAccCloudGoogleRegistrationLoggingSettingsConfig_withoutLoggingParams(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_sink_name"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_topic_id"),
					resource.TestCheckNoResourceAttr(settingsResourceName, "log_ingestion_subscription_name"),
				),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationLoggingSettingsConfig_updated(),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(settingsResourceName, "registration_id", projectResourceName, "id"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_sink_name", "test-sink-updated"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_topic_id", "test-topic-updated"),
					resource.TestCheckResourceAttr(settingsResourceName, "log_ingestion_subscription_name", "test-subscription-updated"),
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
	rtvdEnabled := false

	settingsResourceName := "crowdstrike_cloud_google_registration_logging_settings.test"
	projectResourceName := "crowdstrike_cloud_google_registration.test"

	registrationConfig := cloudGoogleRegistrationConfig(rName, projectID, infraProjectID, wifProjectID, rtvdEnabled)

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationLoggingSettingsConfig_basic(),
				),
				ExpectError: regexp.MustCompile(`realtime_visibility with IOA`),
			},
			{
				Config: acctest.ConfigCompose(
					registrationConfig,
					testAccCloudGoogleRegistrationLoggingSettingsConfig_withoutLoggingParams(),
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

func cloudGoogleRegistrationConfig(
	rName,
	projectID,
	infraProjectID,
	wifProjectID string,
	rtvdEnabled bool,
) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_google_registration" "test" {
  name          = %[1]q
  projects      = [%[2]q]
  infra_project = %[3]q
  wif_project   = %[4]q

  realtime_visibility = {
    enabled = %[5]t 
  }
}
`, rName, projectID, infraProjectID, wifProjectID, rtvdEnabled)
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_basic() string {
	return `
resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink"
  log_ingestion_topic_id          = "test-topic"
  log_ingestion_subscription_name = "test-subscription"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_withoutLoggingParams() string {
	return `
resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id = crowdstrike_cloud_google_registration.test.id

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}

func testAccCloudGoogleRegistrationLoggingSettingsConfig_updated() string {
	return `
resource "crowdstrike_cloud_google_registration_logging_settings" "test" {
  registration_id                 = crowdstrike_cloud_google_registration.test.id
  log_ingestion_sink_name         = "test-sink-updated"
  log_ingestion_topic_id          = "test-topic-updated"
  log_ingestion_subscription_name = "test-subscription-updated"

  depends_on = [crowdstrike_cloud_google_registration.test]
}
`
}
