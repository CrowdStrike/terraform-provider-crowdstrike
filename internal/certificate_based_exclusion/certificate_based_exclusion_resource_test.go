package certificatebasedexclusion_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

type certificateBasedExclusionTestConfig struct {
	Name        string
	Description string
	Comment     string
	HostGroupID string
	Certificate certificateFields
}

type certificateFields struct {
	Issuer     string
	Serial     string
	Subject    string
	Thumbprint string
	ValidFrom  string
	ValidTo    string
}

func (c certificateBasedExclusionTestConfig) String() string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_certificate_based_exclusion" "test" {
  name            = %q
  description     = %q
  comment         = %q
  applied_globally = false
  host_groups     = [%q]

  certificate {
    issuer     = %q
    serial     = %q
    subject    = %q
    thumbprint = %q
    valid_from = %q
    valid_to   = %q
  }
}
`,
		c.Name,
		c.Description,
		c.Comment,
		c.HostGroupID,
		c.Certificate.Issuer,
		c.Certificate.Serial,
		c.Certificate.Subject,
		c.Certificate.Thumbprint,
		c.Certificate.ValidFrom,
		c.Certificate.ValidTo,
	)
}

func TestAccCertificateBasedExclusionResource_Basic(t *testing.T) {
	hostGroupID := os.Getenv(string(acctest.RequireHostGroupID))
	resourceName := "crowdstrike_certificate_based_exclusion.test"
	baseName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	initial := certificateBasedExclusionTestConfig{
		Name:        baseName,
		Description: "Initial certificate based exclusion",
		Comment:     "Created during acceptance testing",
		HostGroupID: hostGroupID,
		Certificate: certificateFields{
			Issuer:     "CN=Terraform Test Issuer 1,O=Example Corp,C=US",
			Serial:     sdkacctest.RandStringFromCharSet(16, acctest.CharSetNum),
			Subject:    "CN=Terraform Test Subject 1,O=Example Corp,C=US",
			Thumbprint: fmt.Sprintf("thumbprint-%s", sdkacctest.RandString(12)),
			ValidFrom:  "2024-01-01T00:00:00Z",
			ValidTo:    "2026-01-01T00:00:00Z",
		},
	}

	updated := certificateBasedExclusionTestConfig{
		Name:        baseName + "-updated",
		Description: "Updated certificate based exclusion",
		Comment:     "Updated during acceptance testing",
		HostGroupID: hostGroupID,
		Certificate: certificateFields{
			Issuer:     "CN=Terraform Test Issuer 2,O=Example Corp,C=US",
			Serial:     sdkacctest.RandStringFromCharSet(16, acctest.CharSetNum),
			Subject:    "CN=Terraform Test Subject 2,O=Example Corp,C=US",
			Thumbprint: fmt.Sprintf("thumbprint-%s", sdkacctest.RandString(12)),
			ValidFrom:  "2024-06-01T00:00:00Z",
			ValidTo:    "2027-06-01T00:00:00Z",
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireHostGroupID) },
		Steps: []resource.TestStep{
			{
				Config: initial.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "name", initial.Name),
					resource.TestCheckResourceAttr(resourceName, "description", initial.Description),
					resource.TestCheckResourceAttr(resourceName, "comment", initial.Comment),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroupID),
					resource.TestCheckResourceAttr(resourceName, "certificate.issuer", initial.Certificate.Issuer),
					resource.TestCheckResourceAttr(resourceName, "certificate.serial", initial.Certificate.Serial),
					resource.TestCheckResourceAttr(resourceName, "certificate.subject", initial.Certificate.Subject),
					resource.TestCheckResourceAttr(resourceName, "certificate.thumbprint", initial.Certificate.Thumbprint),
					resource.TestCheckResourceAttr(resourceName, "certificate.valid_from", "2024-01-01T00:00:00.000Z"),
					resource.TestCheckResourceAttr(resourceName, "certificate.valid_to", "2026-01-01T00:00:00.000Z"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_on"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_on"),
				),
			},
			{
				Config: updated.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
					resource.TestCheckResourceAttr(resourceName, "name", updated.Name),
					resource.TestCheckResourceAttr(resourceName, "description", updated.Description),
					resource.TestCheckResourceAttr(resourceName, "comment", updated.Comment),
					resource.TestCheckResourceAttr(resourceName, "applied_globally", "false"),
					resource.TestCheckResourceAttr(resourceName, "host_groups.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "host_groups.*", hostGroupID),
					resource.TestCheckResourceAttr(resourceName, "certificate.issuer", updated.Certificate.Issuer),
					resource.TestCheckResourceAttr(resourceName, "certificate.serial", updated.Certificate.Serial),
					resource.TestCheckResourceAttr(resourceName, "certificate.subject", updated.Certificate.Subject),
					resource.TestCheckResourceAttr(resourceName, "certificate.thumbprint", updated.Certificate.Thumbprint),
					resource.TestCheckResourceAttr(resourceName, "certificate.valid_from", "2024-06-01T00:00:00.000Z"),
					resource.TestCheckResourceAttr(resourceName, "certificate.valid_to", "2027-06-01T00:00:00.000Z"),
				),
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

func TestAccCertificateBasedExclusionResource_Validation(t *testing.T) {
	hostGroupID := os.Getenv(string(acctest.RequireHostGroupID))

	testCases := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "both_applied_globally_and_host_groups",
			config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_certificate_based_exclusion" "test" {
  name             = %q
  applied_globally = true
  host_groups      = [%q]

  certificate {
    issuer     = "CN=Validator Issuer,O=Example Corp,C=US"
    serial     = "1234567890"
    subject    = "CN=Validator Subject,O=Example Corp,C=US"
    thumbprint = "validator-thumbprint"
    valid_from = "2024-01-01T00:00:00Z"
    valid_to   = "2026-01-01T00:00:00Z"
  }
}
`, sdkacctest.RandomWithPrefix(acctest.ResourcePrefix), hostGroupID),
			expectError: regexp.MustCompile("Cannot specify both applied_globally=true and host_groups"),
		},
		{
			name: "neither_applied_globally_nor_host_groups",
			config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_certificate_based_exclusion" "test" {
  name = %q

  certificate {
    issuer     = "CN=Validator Issuer,O=Example Corp,C=US"
    serial     = "1234567890"
    subject    = "CN=Validator Subject,O=Example Corp,C=US"
    thumbprint = "validator-thumbprint"
    valid_from = "2024-01-01T00:00:00Z"
    valid_to   = "2026-01-01T00:00:00Z"
  }
}
`, sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)),
			expectError: regexp.MustCompile("Must specify either applied_globally=true or provide host_groups"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t, acctest.RequireHostGroupID) },
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
