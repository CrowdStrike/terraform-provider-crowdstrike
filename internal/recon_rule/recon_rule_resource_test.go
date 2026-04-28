package reconrule_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccReconRuleResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_CVE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filter"), knownvalue.StringExact("(phrase:'tf-acc-test')")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("breach_monitoring_enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("breach_monitor_only"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("substring_matching_enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("status"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_timestamp"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("updated_timestamp"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccReconRuleResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameUpdated := fmt.Sprintf("%s-updated", rName)
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
				},
			},
			{
				Config: testAccReconRuleConfig_updated(rNameUpdated),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_CVE")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("filter"), knownvalue.StringExact("(phrase:'tf-acc-updated')")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("low")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("public")),
				},
			},
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("priority"), knownvalue.StringExact("high")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("permissions"), knownvalue.StringExact("private")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccReconRuleResource_topicRequiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_CVE")),
				},
			},
			{
				Config: testAccReconRuleConfig_differentTopic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("topic"), knownvalue.StringExact("SA_AUTHOR")),
				},
			},
		},
	})
}

func TestAccReconRuleResource_lookbackPeriodRequiresReplace(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_withLookback(rName, 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("lookback_period"), knownvalue.Int64Exact(1)),
				},
			},
			{
				Config: testAccReconRuleConfig_withLookback(rName, 7),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("lookback_period"), knownvalue.Int64Exact(7)),
				},
			},
		},
	})
}

func TestAccReconRuleResource_validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_topic",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "INVALID_TOPIC"
  filter      = "test"
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute topic value must be one of`),
		},
		{
			name: "invalid_priority",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "critical"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute priority value must be one of`),
		},
		{
			name: "invalid_permissions",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "high"
  permissions = "restricted"
}`,
			expectError: regexp.MustCompile(`Attribute permissions value must be one of`),
		},
		{
			name: "breach_monitor_only_without_breach_monitoring",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name                      = "test"
  topic                     = "SA_DOMAIN"
  filter                    = "test"
  priority                  = "high"
  permissions               = "private"
  breach_monitor_only       = true
  breach_monitoring_enabled = false
}`,
			expectError: regexp.MustCompile(`breach_monitor_only can only be set to true when breach_monitoring_enabled`),
		},
		{
			name: "empty_name",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = ""
  topic       = "SA_ALIAS"
  filter      = "test"
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute name string length must be at least 1`),
		},
		{
			name: "empty_filter",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name        = "test"
  topic       = "SA_ALIAS"
  filter      = ""
  priority    = "high"
  permissions = "private"
}`,
			expectError: regexp.MustCompile(`Attribute filter string length must be at least 1`),
		},
		{
			name: "breach_monitoring_on_wrong_topic",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name                      = "test"
  topic                     = "SA_ALIAS"
  filter                    = "test"
  priority                  = "high"
  permissions               = "private"
  breach_monitoring_enabled = true
}`,
			expectError: regexp.MustCompile(`breach_monitoring_enabled can only be set to true for SA_DOMAIN and SA_EMAIL`),
		},
		// substring_matching_enabled on non-TSQ topics produces a warning, not an
		// error, because the API allows it (needed for clean imports).

		{
			name: "match_on_tsq_result_types_on_wrong_topic",
			config: `
resource "crowdstrike_recon_rule" "test" {
  name                      = "test"
  topic                     = "SA_ALIAS"
  filter                    = "test"
  priority                  = "high"
  permissions               = "private"
  match_on_tsq_result_types = ["basedomains"]
}`,
			expectError: regexp.MustCompile(`match_on_tsq_result_types can only be set for the SA_TYPOSQUATTING`),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
						PlanOnly:    true,
					},
				},
			})
		})
	}
}

func TestAccReconRuleResource_withNotifications(t *testing.T) {
	recipient := os.Getenv("TF_ACC_RECON_NOTIFICATION_EMAIL")
	if recipient == "" {
		t.Skip("Skipping: TF_ACC_RECON_NOTIFICATION_EMAIL must be set to a valid CrowdStrike user email")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccReconRuleConfig_withNotification(rName, recipient),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("type"), knownvalue.StringExact("email")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("content_format"), knownvalue.StringExact("standard")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("frequency"), knownvalue.StringExact("daily")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("trigger_matchless"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("status"), knownvalue.StringExact("enabled")),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccReconRuleResource_updateNotifications(t *testing.T) {
	recipient := os.Getenv("TF_ACC_RECON_NOTIFICATION_EMAIL")
	if recipient == "" {
		t.Skip("Skipping: TF_ACC_RECON_NOTIFICATION_EMAIL must be set to a valid CrowdStrike user email")
	}

	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_recon_rule.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with one notification.
			{
				Config: testAccReconRuleConfig_withNotification(rName, recipient),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("frequency"), knownvalue.StringExact("daily")),
				},
			},
			// Update to change notification settings.
			{
				Config: testAccReconRuleConfig_withNotificationUpdated(rName, recipient),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("frequency"), knownvalue.StringExact("weekly")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification").AtSliceIndex(0).AtMapKey("content_format"), knownvalue.StringExact("enhanced")),
				},
			},
			// Remove all notifications.
			{
				Config: testAccReconRuleConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("notification"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
}

// Filter syntax reference: FQL using `phrase` condition, derived from existing
// rules retrieved via the Recon API.
func testAccReconRuleConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_CVE"
  filter      = "(phrase:'tf-acc-test')"
  priority    = "high"
  permissions = "private"
}`, name)
}

func testAccReconRuleConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_CVE"
  filter      = "(phrase:'tf-acc-updated')"
  priority    = "low"
  permissions = "public"
}`, name)
}

func testAccReconRuleConfig_withLookback(name string, lookback int) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name            = %[1]q
  topic           = "SA_CVE"
  filter          = "(phrase:'tf-acc-test')"
  priority        = "high"
  permissions     = "private"
  lookback_period = %[2]d
}`, name, lookback)
}

func testAccReconRuleConfig_differentTopic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_AUTHOR"
  filter      = "(phrase:'tf-acc-test')"
  priority    = "high"
  permissions = "private"
}`, name)
}

func testAccReconRuleConfig_withNotification(name, recipient string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_CVE"
  filter      = "(phrase:'tf-acc-test')"
  priority    = "high"
  permissions = "private"

  notification {
    content_format = "standard"
    frequency      = "daily"
    recipients     = [%[2]q]
  }
}`, name, recipient)
}

func testAccReconRuleConfig_withNotificationUpdated(name, recipient string) string {
	return fmt.Sprintf(`
resource "crowdstrike_recon_rule" "test" {
  name        = %[1]q
  topic       = "SA_CVE"
  filter      = "(phrase:'tf-acc-test')"
  priority    = "high"
  permissions = "private"

  notification {
    content_format = "enhanced"
    frequency      = "weekly"
    recipients     = [%[2]q]
  }
}`, name, recipient)
}
