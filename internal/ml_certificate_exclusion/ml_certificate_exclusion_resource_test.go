package mlcertificateexclusion_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	initialIssuer     = "CN=Initial Issuer,O=Example Corp,C=US"
	initialSerial     = "1111111111"
	initialSubject    = "CN=Initial Subject,O=Example Corp,C=US"
	initialThumbprint = "aaaa1111bbbb2222cccc3333dddd4444eeee5555"
	initialValidFrom  = "2024-01-01T00:00:00Z"
	initialValidTo    = "2026-01-01T00:00:00Z"

	updatedIssuer     = "CN=Updated Issuer,O=Example Corp,C=US"
	updatedSerial     = "2222222222"
	updatedSubject    = "CN=Updated Subject,O=Example Corp,C=US"
	updatedThumbprint = "ffff6666aaaa7777bbbb8888cccc9999dddd0000"
	updatedValidFrom  = "2024-06-01T00:00:00Z"
	updatedValidTo    = "2027-06-01T00:00:00Z"
)

func TestAccMLCertificateExclusionResource_basic(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ml_certificate_exclusion.test"
	hg1 := "crowdstrike_host_group.test1"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLCertificateExclusionConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("modified_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("issuer"), knownvalue.StringExact(initialIssuer)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("serial"), knownvalue.StringExact(initialSerial)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("subject"), knownvalue.StringExact(initialSubject)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("thumbprint"), knownvalue.StringExact(initialThumbprint)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_from"), knownvalue.StringExact(initialValidFrom)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_to"), knownvalue.StringExact(initialValidTo)),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccMLCertificateExclusionResource_update(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ml_certificate_exclusion.test"
	hg1 := "crowdstrike_host_group.test1"

	modifiedByStays := statecheck.CompareValue(compare.ValuesSame())
	modifiedOnChanges := statecheck.CompareValue(compare.ValuesDiffer())

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLCertificateExclusionConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("issuer"), knownvalue.StringExact(initialIssuer)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("serial"), knownvalue.StringExact(initialSerial)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("subject"), knownvalue.StringExact(initialSubject)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("thumbprint"), knownvalue.StringExact(initialThumbprint)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_from"), knownvalue.StringExact(initialValidFrom)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_to"), knownvalue.StringExact(initialValidTo)),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_updated(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName+"-updated")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.StringExact("updated description")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.StringExact("updated comment")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("issuer"), knownvalue.StringExact(updatedIssuer)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("serial"), knownvalue.StringExact(updatedSerial)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("subject"), knownvalue.StringExact(updatedSubject)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("thumbprint"), knownvalue.StringExact(updatedThumbprint)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_from"), knownvalue.StringExact(updatedValidFrom)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_to"), knownvalue.StringExact(updatedValidTo)),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_basic(rName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_by"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_on"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("description"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("comment"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("issuer"), knownvalue.StringExact(initialIssuer)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("serial"), knownvalue.StringExact(initialSerial)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("subject"), knownvalue.StringExact(initialSubject)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("thumbprint"), knownvalue.StringExact(initialThumbprint)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_from"), knownvalue.StringExact(initialValidFrom)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("certificate").AtMapKey("valid_to"), knownvalue.StringExact(initialValidTo)),
					modifiedByStays.AddStateValue(resourceName, tfjsonpath.New("modified_by")),
					modifiedOnChanges.AddStateValue(resourceName, tfjsonpath.New("modified_on")),
				},
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccMLCertificateExclusionResource_hostGroups(t *testing.T) {
	rName := acctest.RandomResourceName()
	resourceName := "crowdstrike_ml_certificate_exclusion.test"
	hg1 := "crowdstrike_host_group.test1"
	hg2 := "crowdstrike_host_group.test2"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccMLCertificateExclusionConfig_hostGroups(rName, "[crowdstrike_host_group.test1.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg1, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_hostGroups(rName, `["all"]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_hostGroups(rName, "[crowdstrike_host_group.test1.id, crowdstrike_host_group.test2.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(2)),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_hostGroups(rName, "[crowdstrike_host_group.test2.id]"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetSizeExact(1)),
					statecheck.CompareValuePairs(
						resourceName, tfjsonpath.New("host_groups").AtSliceIndex(0),
						hg2, tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccMLCertificateExclusionConfig_hostGroups(rName, `["all"]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("applied_globally"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("host_groups"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("all"),
					})),
				},
			},
		},
	})
}

func TestAccMLCertificateExclusionResource_validateConfig(t *testing.T) {
	rName := acctest.RandomResourceName()

	cases := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name:        `host_groups mixing "all" with specific IDs rejected`,
			config:      testAccMLCertificateExclusionConfig_hostGroups(rName, `["all", crowdstrike_host_group.test1.id]`),
			expectError: regexp.MustCompile("(?s)`host_groups` cannot include `all` with additional host group IDs"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func testAccMLCertificateExclusionConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test1" {
  name        = "%[1]s-hg1"
  description = "test host group for ml_certificate_exclusion tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ml_certificate_exclusion" "test" {
  name        = %[1]q
  enabled     = true
  host_groups = [crowdstrike_host_group.test1.id]

  certificate = {
    issuer     = %[2]q
    serial     = %[3]q
    subject    = %[4]q
    thumbprint = %[5]q
    valid_from = %[6]q
    valid_to   = %[7]q
  }
}
`, rName, initialIssuer, initialSerial, initialSubject, initialThumbprint, initialValidFrom, initialValidTo)
}

func testAccMLCertificateExclusionConfig_updated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test1" {
  name        = "%[1]s-hg1"
  description = "test host group for ml_certificate_exclusion tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ml_certificate_exclusion" "test" {
  name        = "%[1]s-updated"
  description = "updated description"
  comment     = "updated comment"
  enabled     = false
  host_groups = [crowdstrike_host_group.test1.id]

  certificate = {
    issuer     = %[2]q
    serial     = %[3]q
    subject    = %[4]q
    thumbprint = %[5]q
    valid_from = %[6]q
    valid_to   = %[7]q
  }
}
`, rName, updatedIssuer, updatedSerial, updatedSubject, updatedThumbprint, updatedValidFrom, updatedValidTo)
}

func testAccMLCertificateExclusionConfig_hostGroups(rName, hostGroups string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_host_group" "test1" {
  name        = "%[1]s-hg1"
  description = "test host group for ml_certificate_exclusion tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_host_group" "test2" {
  name        = "%[1]s-hg2"
  description = "test host group for ml_certificate_exclusion tests"
  type        = "staticByID"
  host_ids    = []
}

resource "crowdstrike_ml_certificate_exclusion" "test" {
  name        = %[1]q
  enabled     = true
  host_groups = %[2]s

  certificate = {
    issuer     = %[3]q
    serial     = %[4]q
    subject    = %[5]q
    thumbprint = %[6]q
    valid_from = %[7]q
    valid_to   = %[8]q
  }
}
`, rName, hostGroups, initialIssuer, initialSerial, initialSubject, initialThumbprint, initialValidFrom, initialValidTo)
}
