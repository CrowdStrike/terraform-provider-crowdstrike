package installtoken_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens_settings"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/clientoverrides"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// TestAccInstallTokenSettingsResource_basic runs serially because the settings are
// shared by the whole CID. The CID's original settings are restored afterwards.
func TestAccInstallTokenSettingsResource_basic(t *testing.T) {
	resourceName := "crowdstrike_install_token_settings.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck: func() {
			acctest.PreCheck(t)
			original := readInstallTokenSettings(t)
			t.Cleanup(func() { restoreInstallTokenSettings(t, original) })
		},
		CheckDestroy: testAccCheckInstallTokensNotRequired,
		Steps: []resource.TestStep{
			{
				Config: testAccInstallTokenSettingsConfig(true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.StringExact("install_token_settings")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tokens_required"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("max_active_tokens"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("last_updated"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccInstallTokenSettingsConfigWithMax(false, 49),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tokens_required"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("max_active_tokens"), knownvalue.Int64Exact(49)),
				},
			},
			{
				Config: testAccInstallTokenSettingsConfigWithMax(true, 50),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tokens_required"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("max_active_tokens"), knownvalue.Int64Exact(50)),
				},
			},
			{
				// Removing max_active_tokens from the config keeps the current limit.
				Config: testAccInstallTokenSettingsConfig(false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("tokens_required"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("max_active_tokens"), knownvalue.Int64Exact(50)),
				},
			},
		},
	})
}

// testAccCheckInstallTokensNotRequired checks that destroying the resource turned the
// token requirement off.
func testAccCheckInstallTokensNotRequired(_ *terraform.State) error {
	settings, err := getInstallTokenSettings()
	if err != nil {
		return err
	}

	if settings.TokensRequired == nil || *settings.TokensRequired {
		return fmt.Errorf("expected tokens_required to be false after destroy, got %v", settings.TokensRequired)
	}

	return nil
}

func readInstallTokenSettings(t *testing.T) *models.APICustomerSettingsResourceV1 {
	t.Helper()

	settings, err := getInstallTokenSettings()
	if err != nil {
		t.Fatal(err)
	}

	return settings
}

func getInstallTokenSettings() (*models.APICustomerSettingsResourceV1, error) {
	c := testconfig.GetTestClient()
	if c == nil {
		return nil, fmt.Errorf("test client not initialized; PreCheck must run first")
	}

	res, err := c.InstallationTokens.CustomerSettingsRead(
		&installation_tokens.CustomerSettingsReadParams{Context: context.Background()},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to read install token settings: %w", err)
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil {
		return nil, fmt.Errorf("install token settings read returned no data")
	}

	return res.Payload.Resources[0], nil
}

// restoreInstallTokenSettings puts the CID's installation token settings back to what
// they were before the test. It only writes when the settings changed, then reads them
// back so a restore that did not take effect is reported.
func restoreInstallTokenSettings(t *testing.T, original *models.APICustomerSettingsResourceV1) {
	t.Helper()

	c := testconfig.GetTestClient()
	if c == nil || original == nil {
		return
	}

	current, err := getInstallTokenSettings()
	if err != nil {
		t.Errorf("failed to check install token settings before restoring them: %s", err)
		return
	}

	if installTokenSettingsEqual(current, original) {
		return
	}

	_, err = c.InstallationTokensSettings.CustomerSettingsUpdate(
		&installation_tokens_settings.CustomerSettingsUpdateParams{
			Context: context.Background(),
			Body: &models.APICustomerSettingsPatchRequestV1{
				TokensRequired:  installTokensRequired(original),
				MaxActiveTokens: original.MaxActiveTokens,
			},
		},
		clientoverrides.SendInstallTokensRequired,
	)
	if err != nil {
		t.Errorf("failed to restore install token settings: %s", err)
		return
	}

	restored, err := getInstallTokenSettings()
	if err != nil {
		t.Errorf("failed to verify restored install token settings: %s", err)
		return
	}

	if !installTokenSettingsEqual(restored, original) {
		t.Errorf(
			"install token settings were not restored: want tokens_required=%t max_active_tokens=%d, got tokens_required=%t max_active_tokens=%d",
			installTokensRequired(original), original.MaxActiveTokens,
			installTokensRequired(restored), restored.MaxActiveTokens,
		)
	}
}

func installTokenSettingsEqual(a, b *models.APICustomerSettingsResourceV1) bool {
	return installTokensRequired(a) == installTokensRequired(b) && a.MaxActiveTokens == b.MaxActiveTokens
}

func installTokensRequired(settings *models.APICustomerSettingsResourceV1) bool {
	return settings.TokensRequired != nil && *settings.TokensRequired
}

func testAccInstallTokenSettingsConfig(tokensRequired bool) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token_settings" "test" {
  tokens_required = %[1]t
}`, tokensRequired)
}

func testAccInstallTokenSettingsConfigWithMax(tokensRequired bool, maxActiveTokens int) string {
	return fmt.Sprintf(`
resource "crowdstrike_install_token_settings" "test" {
  tokens_required   = %[1]t
  max_active_tokens = %[2]d
}`, tokensRequired, maxActiveTokens)
}
