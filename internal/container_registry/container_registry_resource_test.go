package containerregistry_test

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

// importStateVerifyIgnore lists the attributes that cannot be verified on
// import for the ECR test, with the reason each one differs between the
// post-apply state and the post-import re-read:
//
//   - credential.aws_iam_role, credential.aws_external_id: write-only inputs the
//     API never returns, so they are null after import.
//   - credential.aws_gov_using_commercial_connection: Computed with a false
//     default, so it is "false" after apply but null after import (the API does
//     not return it).
//   - url_uniqueness_key: a create-only input; the read endpoint returns only
//     url_uniqueness_alias, never the key.
//   - state, state_changed_at, updated_at: server-driven and change
//     asynchronously as the registry moves through its assessment lifecycle, so
//     they can differ in the seconds between apply and the import re-read.
var importStateVerifyIgnore = []string{
	"credential.aws_iam_role",
	"credential.aws_external_id",
	"credential.aws_gov_using_commercial_connection",
	"url_uniqueness_key",
	"state",
	"state_changed_at",
	"updated_at",
}

// TF_ACC_ECR_AWS_IAM_ROLE must be the role in YOUR AWS account, not
// CrowdStrike's; pointing at CrowdStrike's account yields a self-referential
// connection that passes validation but assesses nothing.
func requireECRCreds(t *testing.T) (role, externalID, url string) {
	t.Helper()
	role = os.Getenv("TF_ACC_ECR_AWS_IAM_ROLE")
	externalID = os.Getenv("TF_ACC_ECR_AWS_EXTERNAL_ID")
	url = os.Getenv("TF_ACC_ECR_REGISTRY_URL")
	if role == "" || externalID == "" || url == "" {
		t.Skip("Set TF_ACC_ECR_AWS_IAM_ROLE, TF_ACC_ECR_AWS_EXTERNAL_ID, and TF_ACC_ECR_REGISTRY_URL to run ECR-backed tests")
	}
	return role, externalID, url
}

func TestAccContainerRegistryResource_ECR(t *testing.T) {
	role, externalID, url := requireECRCreds(t)

	rName := acctest.RandomResourceName()
	rNameUpdated := rName + "-updated"
	resourceName := "crowdstrike_container_registry.test"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccContainerRegistryECRConfig(rName, rName, url, role, externalID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url"), knownvalue.StringExact(url)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ecr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url_uniqueness_key"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url_uniqueness_alias"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("refresh_interval"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("aws_iam_role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("aws_external_id"), knownvalue.StringExact(externalID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("credential_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("credential_created_at"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("username"), knownvalue.Null()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("password"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnore,
			},
			{
				Config: testAccContainerRegistryECRConfig(rName, rNameUpdated, url, role, externalID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url_uniqueness_key"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("credential").AtMapKey("aws_iam_role"), knownvalue.StringExact(role)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnore,
			},
		},
	})
}

func TestAccContainerRegistryResource_ValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		config      string
		expectError *regexp.Regexp
		// nonEmptyPlan is set for success-path cases that create resources, so
		// a PlanOnly step produces a non-empty (create) plan rather than an
		// error.
		nonEmptyPlan bool
	}{
		"dockerhub_missing_password": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"
  credential = {
    username = "user"
  }
}
`,
			expectError: regexp.MustCompile(`password is required for dockerhub registry type`),
		},
		"ecr_missing_aws_iam_role": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"
  type = "ecr"
  credential = {
    aws_external_id = "ext"
  }
}
`,
			expectError: regexp.MustCompile(`aws_iam_role is required for ecr registry type`),
		},
		"github_missing_domain_url_and_credential_type": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://ghcr.io"
  type = "github"
  credential = {
    username = "u"
    password = "p"
  }
}
`,
			expectError: regexp.MustCompile(`(?s)domain_url is required for github registry type.*credential_type is required for github registry type|credential_type is required for github registry type.*domain_url is required for github registry type`),
		},
		"gar_missing_service_account_json": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://us-docker.pkg.dev/"
  type = "gar"
  credential = {
    project_id = "p"
    scope_name = "s"
  }
}
`,
			expectError: regexp.MustCompile(`service_account_json is required for gar registry type`),
		},
		"gcr_missing_service_account_json": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://gcr.io/"
  type = "gcr"
  credential = {
    project_id = "p"
  }
}
`,
			expectError: regexp.MustCompile(`service_account_json is required for gcr registry type`),
		},
		"gar_incomplete_service_account_json": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://us-docker.pkg.dev/"
  type = "gar"
  credential = {
    project_id = "p"
    scope_name = "s"
    service_account_json = {
      type = "service_account"
    }
  }
}
`,
			expectError: regexp.MustCompile(`service_account_json.private_key is required for gar registry type`),
		},
		"acr_neither_cert_nor_password": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    username = "u"
  }
}
`,
			expectError: regexp.MustCompile(`Invalid Credential for acr`),
		},
		"acr_cert_and_password_conflict": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    username  = "u"
    password  = "p"
    cert      = "MIIBASE64=="
    auth_type = "cert"
    tenant_id = "tid"
    client    = "cid"
  }
}
`,
			expectError: regexp.MustCompile(`Conflicting Credentials for acr`),
		},
		"acr_cert_missing_subfields": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    cert = "MIIBASE64=="
  }
}
`,
			expectError: regexp.MustCompile(`(?s)(auth_type|tenant_id|client) is required for acr registry type`),
		},
		"acr_password_missing_username": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    password = "p"
  }
}
`,
			expectError: regexp.MustCompile(`username is required for acr registry type`),
		},
		// Regression for #418: a password derived from another resource is
		// unknown at plan time. acr validation must not fire while cert or
		// password is unknown, so this config plans without a false "Invalid
		// Credential for acr" error.
		"acr_password_derived_value": {
			config: acctest.ProviderConfig + `
resource "terraform_data" "pw" {
  input = "supersecret"
}
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    username = "u"
    password = terraform_data.pw.id
  }
}
`,
			expectError:  nil,
			nonEmptyPlan: true,
		},
		// Regression for #418: a derived cert (the method discriminator) must
		// not trigger a false error while unknown.
		"acr_cert_derived_value": {
			config: acctest.ProviderConfig + `
resource "terraform_data" "cert" {
  input = "MIIBASE64=="
}
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    cert      = terraform_data.cert.id
    auth_type = "cert"
    tenant_id = "tid"
    client    = "cid"
  }
}
`,
			expectError:  nil,
			nonEmptyPlan: true,
		},
		// A required cert-auth sub-field (tenant_id) derived from another
		// resource is unknown at plan time. Validation must not report it as
		// missing while unknown; the error may only fire once the value is
		// known and actually absent.
		"acr_cert_derived_subfield": {
			config: acctest.ProviderConfig + `
resource "terraform_data" "tenant" {
  input = "tid"
}
resource "crowdstrike_container_registry" "test" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"
  credential = {
    cert      = "MIIBASE64=="
    auth_type = "cert"
    tenant_id = terraform_data.tenant.id
    client    = "cid"
  }
}
`,
			expectError:  nil,
			nonEmptyPlan: true,
		},
		"oracle_missing_password": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://iad.ocir.io/"
  type = "oracle"
  credential = {
    username = "u"
  }
}
`,
			expectError: regexp.MustCompile(`password is required for oracle registry type`),
		},
		"oracle_compartments_without_scope_name": {
			config: acctest.ProviderConfig + `
resource "crowdstrike_container_registry" "test" {
  url  = "https://iad.ocir.io/"
  type = "oracle"
  credential = {
    username        = "u"
    password        = "p"
    compartment_ids = ["ocid1.compartment.oc1..aaaaaa1"]
  }
}
`,
			expectError: regexp.MustCompile(`scope_name is required for oracle registry type`),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:             tc.config,
						PlanOnly:           true,
						ExpectError:        tc.expectError,
						ExpectNonEmptyPlan: tc.nonEmptyPlan,
					},
				},
			})
		})
	}
}

func testAccContainerRegistryECRConfig(uniquenessKey, alias, url, role, externalID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_container_registry" "test" {
  url                = %[3]q
  type               = "ecr"
  user_defined_alias = %[2]q
  url_uniqueness_key = %[1]q

  credential = {
    aws_iam_role    = %[4]q
    aws_external_id = %[5]q
  }
}
`, uniquenessKey, alias, url, role, externalID)
}
