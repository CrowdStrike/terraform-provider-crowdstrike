package falconcontainerimage_test

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

const resourceName = "crowdstrike_falcon_container_image.test"

// credentialImportIgnoreFields lists all write-only credential sub-attributes that
// the API does not return, so import verification must skip them.
var credentialImportIgnoreFields = []string{
	"credential.username",
	"credential.password",
	"credential.aws_iam_role",
	"credential.aws_external_id",
	"credential.aws_gov_using_commercial_connection",
	"credential.domain_url",
	"credential.credential_type",
	"credential.project_id",
	"credential.scope_name",
	"credential.cert",
	"credential.auth_type",
	"credential.tenant_id",
	"credential.client",
	"credential.compartment_ids",
	"credential.service_account_json",
}

// ---------------------------------------------------------------------------
// DockerHub tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_DockerHub(t *testing.T) {
	rName := acctest.RandomResourceName()
	username := os.Getenv("TEST_DOCKERHUB_USERNAME")
	password := os.Getenv("TEST_DOCKERHUB_TOKEN")

	if username == "" || password == "" {
		t.Skip("TEST_DOCKERHUB_USERNAME and TEST_DOCKERHUB_TOKEN must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigDockerHub(rName, rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("dockerhub")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// TestAccFalconContainerImageResource_UserDefinedAliasNoDrift verifies that removing
// user_defined_alias from config after it has been set does not produce a plan diff.
// The API cannot clear an alias once set, so Computed+UseStateForUnknown must absorb it.
func TestAccFalconContainerImageResource_UserDefinedAliasNoDrift(t *testing.T) {
	rName := acctest.RandomResourceName()
	username := os.Getenv("TEST_DOCKERHUB_USERNAME")
	password := os.Getenv("TEST_DOCKERHUB_TOKEN")

	if username == "" || password == "" {
		t.Skip("TEST_DOCKERHUB_USERNAME and TEST_DOCKERHUB_TOKEN must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with alias set.
			{
				Config: testAccFalconContainerImageConfigDockerHub(rName, rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			// Remove alias from config — API retains it; Terraform must not plan a diff.
			{
				Config:             testAccFalconContainerImageConfigDockerHubNoAlias(rName, username, password),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// ECR tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_ECR(t *testing.T) {
	rName := acctest.RandomResourceName()
	awsIAMRole := os.Getenv("TEST_AWS_IAM_ROLE")
	awsExternalID := os.Getenv("TEST_AWS_EXTERNAL_ID")
	ecrURL := os.Getenv("TEST_ECR_URL")

	if awsIAMRole == "" || awsExternalID == "" || ecrURL == "" {
		t.Skip("TEST_AWS_IAM_ROLE, TEST_AWS_EXTERNAL_ID, and TEST_ECR_URL must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigECR(rName, ecrURL, awsIAMRole, awsExternalID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("ecr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// ACR tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_ACRCert(t *testing.T) {
	rName := acctest.RandomResourceName()
	acrURL := os.Getenv("TEST_ACR_URL")
	cert := os.Getenv("TEST_ACR_CERT_BASE64")
	tenantID := os.Getenv("TEST_ACR_TENANT_ID")
	clientID := os.Getenv("TEST_ACR_CLIENT_ID")

	if acrURL == "" || cert == "" || tenantID == "" || clientID == "" {
		t.Skip("TEST_ACR_URL, TEST_ACR_CERT_BASE64, TEST_ACR_TENANT_ID, and TEST_ACR_CLIENT_ID must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigACRCert(rName, acrURL, cert, tenantID, clientID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("acr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

func TestAccFalconContainerImageResource_ACRPassword(t *testing.T) {
	rName := acctest.RandomResourceName()
	acrURL := os.Getenv("TEST_ACR_PASSWORD_URL")
	username := os.Getenv("TEST_ACR_USERNAME")
	password := os.Getenv("TEST_ACR_PASSWORD")

	if acrURL == "" || username == "" || password == "" {
		t.Skip("TEST_ACR_PASSWORD_URL, TEST_ACR_USERNAME, and TEST_ACR_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigACRPassword(rName, acrURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("acr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// GAR / GCR tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_GAR(t *testing.T) {
	rName := acctest.RandomResourceName()
	garURL := os.Getenv("TEST_GAR_URL")
	projectID := os.Getenv("TEST_GCP_PROJECT_ID")
	scopeName := os.Getenv("TEST_GAR_SCOPE_NAME")
	privateKeyID := os.Getenv("TEST_GCP_PRIVATE_KEY_ID")
	privateKey := os.Getenv("TEST_GCP_PRIVATE_KEY")
	clientEmail := os.Getenv("TEST_GCP_CLIENT_EMAIL")
	clientID := os.Getenv("TEST_GCP_CLIENT_ID")

	if garURL == "" || projectID == "" || scopeName == "" ||
		privateKeyID == "" || privateKey == "" || clientEmail == "" || clientID == "" {
		t.Skip("TEST_GAR_URL, TEST_GCP_PROJECT_ID, TEST_GAR_SCOPE_NAME, TEST_GCP_PRIVATE_KEY_ID, TEST_GCP_PRIVATE_KEY, TEST_GCP_CLIENT_EMAIL, and TEST_GCP_CLIENT_ID must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigGAR(rName, rName, garURL, projectID, scopeName, privateKeyID, privateKey, clientEmail, clientID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("gar")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

func TestAccFalconContainerImageResource_GCR(t *testing.T) {
	rName := acctest.RandomResourceName()
	gcrURL := os.Getenv("TEST_GCR_URL")
	projectID := os.Getenv("TEST_GCP_PROJECT_ID")
	privateKeyID := os.Getenv("TEST_GCP_PRIVATE_KEY_ID")
	privateKey := os.Getenv("TEST_GCP_PRIVATE_KEY")
	clientEmail := os.Getenv("TEST_GCP_CLIENT_EMAIL")
	clientID := os.Getenv("TEST_GCP_CLIENT_ID")

	if gcrURL == "" || projectID == "" ||
		privateKeyID == "" || privateKey == "" || clientEmail == "" || clientID == "" {
		t.Skip("TEST_GCR_URL, TEST_GCP_PROJECT_ID, TEST_GCP_PRIVATE_KEY_ID, TEST_GCP_PRIVATE_KEY, TEST_GCP_CLIENT_EMAIL, and TEST_GCP_CLIENT_ID must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigGCR(rName, rName, gcrURL, projectID, privateKeyID, privateKey, clientEmail, clientID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("gcr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// GitHub / GitLab tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_GitHub(t *testing.T) {
	rName := acctest.RandomResourceName()
	username := os.Getenv("TEST_GITHUB_USERNAME")
	pat := os.Getenv("TEST_GITHUB_PAT")
	domainURL := os.Getenv("TEST_GITHUB_DOMAIN_URL")

	if username == "" || pat == "" || domainURL == "" {
		t.Skip("TEST_GITHUB_USERNAME, TEST_GITHUB_PAT, and TEST_GITHUB_DOMAIN_URL must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigGitHub(rName, rName, username, pat, domainURL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("github")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

func TestAccFalconContainerImageResource_GitLab(t *testing.T) {
	rName := acctest.RandomResourceName()
	username := os.Getenv("TEST_GITLAB_USERNAME")
	pat := os.Getenv("TEST_GITLAB_PAT")
	domainURL := os.Getenv("TEST_GITLAB_DOMAIN_URL")

	if username == "" || pat == "" || domainURL == "" {
		t.Skip("TEST_GITLAB_USERNAME, TEST_GITLAB_PAT, and TEST_GITLAB_DOMAIN_URL must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigGitLab(rName, rName, username, pat, domainURL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("gitlab")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Oracle test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Oracle(t *testing.T) {
	rName := acctest.RandomResourceName()
	oracleURL := os.Getenv("TEST_ORACLE_URL")
	username := os.Getenv("TEST_ORACLE_USERNAME")
	password := os.Getenv("TEST_ORACLE_PASSWORD")
	scopeName := os.Getenv("TEST_ORACLE_SCOPE_NAME")
	compartmentID := os.Getenv("TEST_ORACLE_COMPARTMENT_ID")

	if oracleURL == "" || username == "" || password == "" || scopeName == "" || compartmentID == "" {
		t.Skip("TEST_ORACLE_URL, TEST_ORACLE_USERNAME, TEST_ORACLE_PASSWORD, TEST_ORACLE_SCOPE_NAME, and TEST_ORACLE_COMPARTMENT_ID must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigOracle(rName, oracleURL, username, password, scopeName, compartmentID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("oracle")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Generic Docker test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Docker(t *testing.T) {
	rName := acctest.RandomResourceName()
	dockerURL := os.Getenv("TEST_DOCKER_REGISTRY_URL")
	username := os.Getenv("TEST_DOCKER_USERNAME")
	password := os.Getenv("TEST_DOCKER_PASSWORD")

	if dockerURL == "" || username == "" || password == "" {
		t.Skip("TEST_DOCKER_REGISTRY_URL, TEST_DOCKER_USERNAME, and TEST_DOCKER_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigDocker(rName, dockerURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("docker")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Artifactory test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Artifactory(t *testing.T) {
	rName := acctest.RandomResourceName()
	artifactoryURL := os.Getenv("TEST_ARTIFACTORY_URL")
	username := os.Getenv("TEST_ARTIFACTORY_USERNAME")
	password := os.Getenv("TEST_ARTIFACTORY_PASSWORD")

	if artifactoryURL == "" || username == "" || password == "" {
		t.Skip("TEST_ARTIFACTORY_URL, TEST_ARTIFACTORY_USERNAME, and TEST_ARTIFACTORY_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigArtifactory(rName, artifactoryURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("artifactory")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Harbor test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Harbor(t *testing.T) {
	rName := acctest.RandomResourceName()
	harborURL := os.Getenv("TEST_HARBOR_URL")
	username := os.Getenv("TEST_HARBOR_USERNAME")
	password := os.Getenv("TEST_HARBOR_PASSWORD")

	if harborURL == "" || username == "" || password == "" {
		t.Skip("TEST_HARBOR_URL, TEST_HARBOR_USERNAME, and TEST_HARBOR_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigHarbor(rName, harborURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("harbor")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// ICR test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_ICR(t *testing.T) {
	rName := acctest.RandomResourceName()
	icrURL := os.Getenv("TEST_ICR_URL")
	username := os.Getenv("TEST_ICR_USERNAME")
	password := os.Getenv("TEST_ICR_PASSWORD")

	if icrURL == "" || username == "" || password == "" {
		t.Skip("TEST_ICR_URL, TEST_ICR_USERNAME, and TEST_ICR_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigICR(rName, icrURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("icr")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Mirantis test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Mirantis(t *testing.T) {
	rName := acctest.RandomResourceName()
	mirantisURL := os.Getenv("TEST_MIRANTIS_URL")
	username := os.Getenv("TEST_MIRANTIS_USERNAME")
	password := os.Getenv("TEST_MIRANTIS_PASSWORD")

	if mirantisURL == "" || username == "" || password == "" {
		t.Skip("TEST_MIRANTIS_URL, TEST_MIRANTIS_USERNAME, and TEST_MIRANTIS_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigMirantis(rName, mirantisURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("mirantis")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Nexus test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Nexus(t *testing.T) {
	rName := acctest.RandomResourceName()
	nexusURL := os.Getenv("TEST_NEXUS_URL")
	username := os.Getenv("TEST_NEXUS_USERNAME")
	password := os.Getenv("TEST_NEXUS_PASSWORD")

	if nexusURL == "" || username == "" || password == "" {
		t.Skip("TEST_NEXUS_URL, TEST_NEXUS_USERNAME, and TEST_NEXUS_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigNexus(rName, nexusURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("nexus")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// OpenShift test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_OpenShift(t *testing.T) {
	rName := acctest.RandomResourceName()
	openshiftURL := os.Getenv("TEST_OPENSHIFT_URL")
	username := os.Getenv("TEST_OPENSHIFT_USERNAME")
	password := os.Getenv("TEST_OPENSHIFT_PASSWORD")

	if openshiftURL == "" || username == "" || password == "" {
		t.Skip("TEST_OPENSHIFT_URL, TEST_OPENSHIFT_USERNAME, and TEST_OPENSHIFT_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigOpenShift(rName, openshiftURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("openshift")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Quay.io test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Quay(t *testing.T) {
	rName := acctest.RandomResourceName()
	quayURL := os.Getenv("TEST_QUAY_URL")
	username := os.Getenv("TEST_QUAY_USERNAME")
	password := os.Getenv("TEST_QUAY_PASSWORD")

	if quayURL == "" || username == "" || password == "" {
		t.Skip("TEST_QUAY_URL, TEST_QUAY_USERNAME, and TEST_QUAY_PASSWORD must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigQuay(rName, quayURL, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("quay.io")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Update test
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Update(t *testing.T) {
	rName := acctest.RandomResourceName()
	rNameUpdated := rName + "-updated"
	username := os.Getenv("TEST_DOCKERHUB_USERNAME")
	password := os.Getenv("TEST_DOCKERHUB_TOKEN")

	if username == "" || password == "" {
		t.Skip("TEST_DOCKERHUB_USERNAME and TEST_DOCKERHUB_TOKEN must be set for this test")
	}

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccFalconContainerImageConfigDockerHub(rName, rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url"), knownvalue.StringExact("https://registry-1.docker.io/")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("dockerhub")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rName)),
				},
			},
			// Only user_defined_alias changes — url_uniqueness_key stays constant so no replace occurs.
			{
				Config: testAccFalconContainerImageConfigDockerHub(rNameUpdated, rName, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("url"), knownvalue.StringExact("https://registry-1.docker.io/")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("type"), knownvalue.StringExact("dockerhub")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("user_defined_alias"), knownvalue.StringExact(rNameUpdated)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("state"), knownvalue.NotNull()),
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: credentialImportIgnoreFields,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// ValidateConfig plan-only tests
// ---------------------------------------------------------------------------

func TestAccFalconContainerImageResource_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "ecr_missing_aws_iam_role",
			config: testAccFalconContainerImageValidationConfig(
				"https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
				"ecr",
				`aws_external_id = "ext-id"`,
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "ecr_missing_aws_external_id",
			config: testAccFalconContainerImageValidationConfig(
				"https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
				"ecr",
				`aws_iam_role = "arn:aws:iam::123456789012:role/FalconRole"`,
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "dockerhub_missing_username",
			config: testAccFalconContainerImageValidationConfig(
				"https://registry-1.docker.io/",
				"dockerhub",
				`password = "mytoken"`,
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "dockerhub_missing_password",
			config: testAccFalconContainerImageValidationConfig(
				"https://registry-1.docker.io/",
				"dockerhub",
				`username = "myuser"`,
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "github_missing_domain_url",
			config: testAccFalconContainerImageValidationConfig(
				"https://ghcr.io/",
				"github",
				"username = \"myuser\"\npassword = \"mytoken\"\ncredential_type = \"PAT\"",
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "github_missing_credential_type",
			config: testAccFalconContainerImageValidationConfig(
				"https://ghcr.io/",
				"github",
				"username = \"myuser\"\npassword = \"mytoken\"\ndomain_url = \"https://github.com\"",
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "gar_missing_service_account_json",
			config: testAccFalconContainerImageValidationConfig(
				"https://us-docker.pkg.dev/",
				"gar",
				"project_id = \"my-project\"\nscope_name = \"us-docker.pkg.dev/my-project\"",
			),
			expectError: regexp.MustCompile(`Missing Required Credential Field`),
		},
		{
			name: "acr_neither_auth_method",
			config: testAccFalconContainerImageValidationConfig(
				"https://myregistry.azurecr.io/",
				"acr",
				`username = "myuser"`,
			),
			expectError: regexp.MustCompile(`Invalid ACR Credentials`),
		},
		{
			name: "oracle_empty_compartment_ids",
			config: testAccFalconContainerImageValidationConfig(
				"https://iad.ocir.io/",
				"oracle",
				"username = \"mytenancy/myuser\"\npassword = \"mytoken\"\nscope_name = \"iad.ocir.io/mytenancy\"\ncompartment_ids = []",
			),
			expectError: regexp.MustCompile(`compartment_ids must contain at least one`),
		},
		{
			name: "whitespace_url_uniqueness_key",
			config: acctest.ProviderConfig + `
resource "crowdstrike_falcon_container_image" "test" {
  url                = "https://registry-1.docker.io/"
  type               = "dockerhub"
  url_uniqueness_key = "   "

  credential = {
    username = "myuser"
    password = "mytoken"
  }
}`,
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
		{
			name: "whitespace_user_defined_alias",
			config: acctest.ProviderConfig + `
resource "crowdstrike_falcon_container_image" "test" {
  url                = "https://registry-1.docker.io/"
  type               = "dockerhub"
  user_defined_alias = "   "

  credential = {
    username = "myuser"
    password = "mytoken"
  }
}`,
			expectError: regexp.MustCompile(`must not be empty or contain only whitespace`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				PreCheck:                 func() { acctest.PreCheck(t) },
				Steps: []resource.TestStep{
					{
						Config:      tt.config,
						ExpectError: tt.expectError,
						PlanOnly:    true,
					},
				},
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

func testAccFalconContainerImageConfigDockerHub(alias, uniquenessKey, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[2]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, uniquenessKey, username, password)
}

func testAccFalconContainerImageConfigDockerHubNoAlias(uniquenessKey, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"

  url_uniqueness_key = %[1]q

  credential = {
    username = %[2]q
    password = %[3]q
  }
}
`, uniquenessKey, username, password)
}

func testAccFalconContainerImageConfigECR(alias, url, iamRole, externalID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "ecr"

  user_defined_alias = %[1]q

  credential = {
    aws_iam_role    = %[3]q
    aws_external_id = %[4]q
  }
}
`, alias, url, iamRole, externalID)
}

func testAccFalconContainerImageConfigACRCert(alias, url, cert, tenantID, clientID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "acr"

  user_defined_alias = %[1]q

  credential = {
    cert      = %[3]q
    auth_type = "cert"
    tenant_id = %[4]q
    client    = %[5]q
  }
}
`, alias, url, cert, tenantID, clientID)
}

func testAccFalconContainerImageConfigACRPassword(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "acr"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigGAR(alias, uniquenessKey, url, projectID, scopeName, privateKeyID, privateKey, clientEmail, clientID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[3]q
  type = "gar"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[2]q

  credential = {
    project_id = %[4]q
    scope_name = %[5]q

    service_account_json = {
      type           = "service_account"
      private_key_id = %[6]q
      private_key    = %[7]q
      client_email   = %[8]q
      client_id      = %[9]q
      project_id     = %[4]q
    }
  }
}
`, alias, uniquenessKey, url, projectID, scopeName, privateKeyID, privateKey, clientEmail, clientID)
}

func testAccFalconContainerImageConfigGCR(alias, uniquenessKey, url, projectID, privateKeyID, privateKey, clientEmail, clientID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[3]q
  type = "gcr"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[2]q

  credential = {
    project_id = %[4]q

    service_account_json = {
      type           = "service_account"
      private_key_id = %[5]q
      private_key    = %[6]q
      client_email   = %[7]q
      client_id      = %[8]q
      project_id     = %[4]q
    }
  }
}
`, alias, uniquenessKey, url, projectID, privateKeyID, privateKey, clientEmail, clientID)
}

func testAccFalconContainerImageConfigGitHub(alias, uniquenessKey, username, pat, domainURL string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = "https://ghcr.io/"
  type = "github"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[2]q

  credential = {
    username        = %[3]q
    password        = %[4]q
    domain_url      = %[5]q
    credential_type = "PAT"
  }
}
`, alias, uniquenessKey, username, pat, domainURL)
}

func testAccFalconContainerImageConfigGitLab(alias, uniquenessKey, username, pat, domainURL string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = "https://registry.gitlab.com/"
  type = "gitlab"

  user_defined_alias = %[1]q
  url_uniqueness_key = %[2]q

  credential = {
    username        = %[3]q
    password        = %[4]q
    domain_url      = %[5]q
    credential_type = "PAT"
  }
}
`, alias, uniquenessKey, username, pat, domainURL)
}

func testAccFalconContainerImageConfigOracle(alias, url, username, password, scopeName, compartmentID string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "oracle"

  user_defined_alias = %[1]q

  credential = {
    username   = %[3]q
    password   = %[4]q
    scope_name = %[5]q
    compartment_ids = [%[6]q]
  }
}
`, alias, url, username, password, scopeName, compartmentID)
}

func testAccFalconContainerImageConfigDocker(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "docker"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigArtifactory(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "artifactory"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigHarbor(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "harbor"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigICR(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "icr"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigMirantis(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "mirantis"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigNexus(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "nexus"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigOpenShift(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "openshift"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageConfigQuay(alias, url, username, password string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[2]q
  type = "quay.io"

  user_defined_alias = %[1]q

  credential = {
    username = %[3]q
    password = %[4]q
  }
}
`, alias, url, username, password)
}

func testAccFalconContainerImageValidationConfig(url, registryType, credentialBlock string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_falcon_container_image" "test" {
  url  = %[1]q
  type = %[2]q

  credential = {
    %[3]s
  }
}
`, url, registryType, credentialBlock)
}
