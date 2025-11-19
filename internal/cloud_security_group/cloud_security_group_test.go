package cloudsecuritygroup_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// groupConfig represents a complete cloud security group configuration for testing.
type groupConfig struct {
	Name           string
	Description    *string
	BusinessImpact *string
	BusinessUnit   *string
	Environment    *string
	Owners         []string

	// Cloud provider configs
	AWSAccountIDs   []string
	AWSRegions      []string
	AWSTags         []string
	AzureAccountIDs []string
	AzureRegions    []string
	AzureTags       []string
	GCPAccountIDs   []string
	GCPRegions      []string

	// Image selectors
	Images []imageSelector
}

// imageSelector represents a container image selector.
type imageSelector struct {
	Registry   string
	Repository string
	Tag        *string
}

// String generates Terraform configuration from groupConfig.
func (config *groupConfig) String() string {
	var configStr string

	configStr += fmt.Sprintf(`
resource "crowdstrike_cloud_security_group" "test" {
  name = %q
`, config.Name)

	if config.Description != nil {
		configStr += fmt.Sprintf("  description = %q\n", *config.Description)
	}

	if config.BusinessImpact != nil {
		configStr += fmt.Sprintf("  business_impact = %q\n", *config.BusinessImpact)
	}

	if config.BusinessUnit != nil {
		configStr += fmt.Sprintf("  business_unit = %q\n", *config.BusinessUnit)
	}

	if config.Environment != nil {
		configStr += fmt.Sprintf("  environment = %q\n", *config.Environment)
	}

	if len(config.Owners) > 0 {
		configStr += "  owners = ["
		for i, owner := range config.Owners {
			if i > 0 {
				configStr += ", "
			}
			configStr += fmt.Sprintf("%q", owner)
		}
		configStr += "]\n"
	}

	// AWS configuration
	if len(config.AWSAccountIDs) > 0 {
		configStr += "  aws = {\n"
		configStr += "    account_ids = ["
		for i, id := range config.AWSAccountIDs {
			if i > 0 {
				configStr += ", "
			}
			configStr += fmt.Sprintf("%q", id)
		}
		configStr += "]\n"

		if len(config.AWSRegions) > 0 || len(config.AWSTags) > 0 {
			configStr += "    filters = {\n"
			if len(config.AWSRegions) > 0 {
				configStr += "      region = ["
				for i, region := range config.AWSRegions {
					if i > 0 {
						configStr += ", "
					}
					configStr += fmt.Sprintf("%q", region)
				}
				configStr += "]\n"
			}
			if len(config.AWSTags) > 0 {
				configStr += "      tags = ["
				for i, tag := range config.AWSTags {
					if i > 0 {
						configStr += ", "
					}
					configStr += fmt.Sprintf("%q", tag)
				}
				configStr += "]\n"
			}
			configStr += "    }\n"
		}
		configStr += "  }\n"
	}

	// Azure configuration
	if len(config.AzureAccountIDs) > 0 {
		configStr += "  azure = {\n"
		configStr += "    account_ids = ["
		for i, id := range config.AzureAccountIDs {
			if i > 0 {
				configStr += ", "
			}
			configStr += fmt.Sprintf("%q", id)
		}
		configStr += "]\n"

		if len(config.AzureRegions) > 0 || len(config.AzureTags) > 0 {
			configStr += "    filters = {\n"
			if len(config.AzureRegions) > 0 {
				configStr += "      region = ["
				for i, region := range config.AzureRegions {
					if i > 0 {
						configStr += ", "
					}
					configStr += fmt.Sprintf("%q", region)
				}
				configStr += "]\n"
			}
			if len(config.AzureTags) > 0 {
				configStr += "      tags = ["
				for i, tag := range config.AzureTags {
					if i > 0 {
						configStr += ", "
					}
					configStr += fmt.Sprintf("%q", tag)
				}
				configStr += "]\n"
			}
			configStr += "    }\n"
		}
		configStr += "  }\n"
	}

	// GCP configuration
	if len(config.GCPAccountIDs) > 0 {
		configStr += "  gcp = {\n"
		configStr += "    account_ids = ["
		for i, id := range config.GCPAccountIDs {
			if i > 0 {
				configStr += ", "
			}
			configStr += fmt.Sprintf("%q", id)
		}
		configStr += "]\n"

		if len(config.GCPRegions) > 0 {
			configStr += "    filters = {\n"
			configStr += "      region = ["
			for i, region := range config.GCPRegions {
				if i > 0 {
					configStr += ", "
				}
				configStr += fmt.Sprintf("%q", region)
			}
			configStr += "]\n"
			configStr += "    }\n"
		}
		configStr += "  }\n"
	}

	// Image selectors
	if len(config.Images) > 0 {
		configStr += "  images = [\n"
		for _, img := range config.Images {
			configStr += "    {\n"
			configStr += fmt.Sprintf("      registry = %q\n", img.Registry)
			configStr += fmt.Sprintf("      repository = %q\n", img.Repository)
			if img.Tag != nil {
				configStr += fmt.Sprintf("      tag = %q\n", *img.Tag)
			}
			configStr += "    },\n"
		}
		configStr += "  ]\n"
	}

	configStr += "}\n"

	return configStr
}

// TestChecks generates all test checks based on the group configuration.
func (config *groupConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	// Basic checks
	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "name", config.Name),
		resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "created_at"),
		resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "updated_at"),
		resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "created_by"),
	)

	// Optional field checks
	if config.Description != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "description", *config.Description))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "description"))
	}

	if config.BusinessImpact != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "business_impact", *config.BusinessImpact))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "business_impact"))
	}

	if config.BusinessUnit != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "business_unit", *config.BusinessUnit))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "business_unit"))
	}

	if config.Environment != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "environment", *config.Environment))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "environment"))
	}

	if len(config.Owners) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "owners.#", fmt.Sprintf("%d", len(config.Owners))))
		for i, owner := range config.Owners {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", fmt.Sprintf("owners.%d", i), owner))
		}
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "owners"))
	}

	if len(config.AWSAccountIDs) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "aws.account_ids.#", fmt.Sprintf("%d", len(config.AWSAccountIDs))))
		if len(config.AWSRegions) > 0 {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "aws.filters.region.#", fmt.Sprintf("%d", len(config.AWSRegions))))
		}
		if len(config.AWSTags) > 0 {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "aws.filters.tags.#", fmt.Sprintf("%d", len(config.AWSTags))))
		}
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "aws"))
	}

	if len(config.AzureAccountIDs) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "azure.account_ids.#", fmt.Sprintf("%d", len(config.AzureAccountIDs))))
		if len(config.AzureRegions) > 0 {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "azure.filters.region.#", fmt.Sprintf("%d", len(config.AzureRegions))))
		}
		if len(config.AzureTags) > 0 {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "azure.filters.tags.#", fmt.Sprintf("%d", len(config.AzureTags))))
		}
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "azure"))
	}

	if len(config.GCPAccountIDs) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "gcp.account_ids.#", fmt.Sprintf("%d", len(config.GCPAccountIDs))))
		if len(config.GCPRegions) > 0 {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "gcp.filters.region.#", fmt.Sprintf("%d", len(config.GCPRegions))))
		}
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "gcp"))
	}

	if len(config.Images) > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "images.#", fmt.Sprintf("%d", len(config.Images))))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_cloud_security_group.test", "images"))
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// TestAccCloudSecurityGroupResource_Basic tests basic creation and updates.
func TestAccCloudSecurityGroupResource_Basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name:          rName,
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: (&groupConfig{
					Name:          rName,
					AWSAccountIDs: []string{"123456789012"},
				}).TestChecks(),
			},
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name:          rName + "-updated",
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: (&groupConfig{
					Name:          rName + "-updated",
					AWSAccountIDs: []string{"123456789012"},
				}).TestChecks(),
			},
			{
				ResourceName:      "crowdstrike_cloud_security_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccCloudSecurityGroupResource_Description tests description state transitions.
func TestAccCloudSecurityGroupResource_Description(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_description",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "with_description",
			config: &groupConfig{
				Name:        rName,
				Description: utils.Addr("Test description"),
			},
		},
		{
			name: "updated_description",
			config: &groupConfig{
				Name:        rName,
				Description: utils.Addr("Updated description"),
			},
		},
		{
			name: "removed_description",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_BusinessImpact tests business impact state transitions.
func TestAccCloudSecurityGroupResource_BusinessImpact(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "high",
			config: &groupConfig{
				Name:           rName,
				BusinessImpact: utils.Addr("high"),
			},
		},
		{
			name: "moderate",
			config: &groupConfig{
				Name:           rName,
				BusinessImpact: utils.Addr("moderate"),
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "low",
			config: &groupConfig{
				Name:           rName,
				BusinessImpact: utils.Addr("low"),
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_BusinessUnit tests business unit state transitions.
func TestAccCloudSecurityGroupResource_BusinessUnit(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_business_unit",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "engineering",
			config: &groupConfig{
				Name:         rName,
				BusinessUnit: utils.Addr("Engineering"),
			},
		},
		{
			name: "operations",
			config: &groupConfig{
				Name:         rName,
				BusinessUnit: utils.Addr("Operations"),
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_Environment tests environment state transitions.
func TestAccCloudSecurityGroupResource_Environment(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "dev",
			config: &groupConfig{
				Name:        rName,
				Environment: utils.Addr("dev"),
			},
		},
		{
			name: "test",
			config: &groupConfig{
				Name:        rName,
				Environment: utils.Addr("test"),
			},
		},
		{
			name: "stage",
			config: &groupConfig{
				Name:        rName,
				Environment: utils.Addr("stage"),
			},
		},
		{
			name: "prod",
			config: &groupConfig{
				Name:        rName,
				Environment: utils.Addr("prod"),
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_Owners tests owners state transitions.
func TestAccCloudSecurityGroupResource_Owners(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_owners",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "single_owner",
			config: &groupConfig{
				Name:   rName,
				Owners: []string{"test1@example.com"},
			},
		},
		{
			name: "multiple_owners",
			config: &groupConfig{
				Name:   rName,
				Owners: []string{"test1@example.com", "test2@example.com", "test3@example.com"},
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_AWS tests AWS configuration and state transitions.
func TestAccCloudSecurityGroupResource_AWS(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_aws",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "basic_aws",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012"},
			},
		},
		{
			name: "with_regions",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012"},
				AWSRegions:    []string{"us-east-1", "us-west-2"},
			},
		},
		{
			name: "with_tags",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012"},
				AWSRegions:    []string{"us-east-1", "us-west-2"},
				AWSTags:       []string{"Environment=Production", "Team=Platform"},
			},
		},
		{
			name: "multiple_accounts",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012", "210987654321"},
				AWSRegions:    []string{"us-east-1", "us-west-2"},
				AWSTags:       []string{"Environment=Production", "Team=Platform"},
			},
		},
		{
			name: "remove_filters",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012", "210987654321"},
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_Azure tests Azure configuration and state transitions.
func TestAccCloudSecurityGroupResource_Azure(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_azure",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "basic_azure",
			config: &groupConfig{
				Name:            rName,
				AzureAccountIDs: []string{"12345678-1234-1234-1234-123456789012"},
			},
		},
		{
			name: "with_filters",
			config: &groupConfig{
				Name:            rName,
				AzureAccountIDs: []string{"12345678-1234-1234-1234-123456789012"},
				AzureRegions:    []string{"eastus", "westus"},
				AzureTags:       []string{"Environment=Production"},
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_GCP tests GCP configuration and state transitions.
func TestAccCloudSecurityGroupResource_GCP(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_gcp",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "basic_gcp",
			config: &groupConfig{
				Name:          rName,
				GCPAccountIDs: []string{"my-project-id"},
			},
		},
		{
			name: "with_regions",
			config: &groupConfig{
				Name:          rName,
				GCPAccountIDs: []string{"my-project-id"},
				GCPRegions:    []string{"us-central1", "us-east1"},
			},
		},
		{
			name: "multiple_projects",
			config: &groupConfig{
				Name:          rName,
				GCPAccountIDs: []string{"my-project-id", "another-project"},
				GCPRegions:    []string{"us-central1", "us-east1"},
			},
		},
		{
			name: "remove_regions",
			config: &groupConfig{
				Name:          rName,
				GCPAccountIDs: []string{"my-project-id", "another-project"},
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_MultiCloud tests multiple cloud providers.
func TestAccCloudSecurityGroupResource_MultiCloud(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "aws_and_azure",
			config: &groupConfig{
				Name:            rName,
				AWSAccountIDs:   []string{"123456789012"},
				AzureAccountIDs: []string{"12345678-1234-1234-1234-123456789012"},
			},
		},
		{
			name: "all_three_clouds",
			config: &groupConfig{
				Name:            rName,
				AWSAccountIDs:   []string{"123456789012"},
				AzureAccountIDs: []string{"12345678-1234-1234-1234-123456789012"},
				GCPAccountIDs:   []string{"my-project-id"},
			},
		},
		{
			name: "aws_and_gcp",
			config: &groupConfig{
				Name:          rName,
				AWSAccountIDs: []string{"123456789012"},
				GCPAccountIDs: []string{"my-project-id"},
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_Images tests image selector configuration.
func TestAccCloudSecurityGroupResource_Images(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "no_images",
			config: &groupConfig{
				Name: rName,
			},
		},
		{
			name: "single_image_no_tag",
			config: &groupConfig{
				Name: rName,
				Images: []imageSelector{
					{
						Registry:   "docker.io",
						Repository: "library/nginx",
					},
				},
			},
		},
		{
			name: "single_image_with_tag",
			config: &groupConfig{
				Name: rName,
				Images: []imageSelector{
					{
						Registry:   "docker.io",
						Repository: "library/nginx",
						Tag:        utils.Addr("latest"),
					},
				},
			},
		},
		{
			name: "multiple_images",
			config: &groupConfig{
				Name: rName,
				Images: []imageSelector{
					{
						Registry:   "docker.io",
						Repository: "library/nginx",
						Tag:        utils.Addr("latest"),
					},
					{
						Registry:   "gcr.io",
						Repository: "my-project/my-app",
						Tag:        utils.Addr("v1.0.0"),
					},
				},
			},
		},
		{
			name: "single_image_different",
			config: &groupConfig{
				Name: rName,
				Images: []imageSelector{
					{
						Registry:   "gcr.io",
						Repository: "my-project/my-app",
						Tag:        utils.Addr("v1.0.0"),
					},
				},
			},
		},
		{
			name: "removed",
			config: &groupConfig{
				Name: rName,
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_CompleteConfiguration tests all attributes together.
func TestAccCloudSecurityGroupResource_CompleteConfiguration(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	tests := []struct {
		name   string
		config *groupConfig
	}{
		{
			name: "complete",
			config: &groupConfig{
				Name:           rName,
				Description:    utils.Addr("Complete test group"),
				BusinessImpact: utils.Addr("high"),
				BusinessUnit:   utils.Addr("Engineering"),
				Environment:    utils.Addr("prod"),
				Owners:         []string{"owner1@example.com", "owner2@example.com"},
				AWSAccountIDs:  []string{"123456789012"},
				AWSRegions:     []string{"us-east-1"},
				AWSTags:        []string{"Environment=Production"},
				Images: []imageSelector{
					{
						Registry:   "docker.io",
						Repository: "library/nginx",
						Tag:        utils.Addr("latest"),
					},
				},
			},
		},
		{
			name: "updated",
			config: &groupConfig{
				Name:            rName + "-updated",
				Description:     utils.Addr("Updated description"),
				BusinessImpact:  utils.Addr("low"),
				BusinessUnit:    utils.Addr("Operations"),
				Environment:     utils.Addr("dev"),
				Owners:          []string{"newowner@example.com"},
				AzureAccountIDs: []string{"12345678-1234-1234-1234-123456789012"},
				AzureRegions:    []string{"eastus"},
				Images: []imageSelector{
					{
						Registry:   "gcr.io",
						Repository: "project/app",
					},
				},
			},
		},
		{
			name: "minimal",
			config: &groupConfig{
				Name:          rName + "-updated",
				AWSAccountIDs: []string{"123456789012"},
			},
		},
	}

	var steps []resource.TestStep
	for _, tt := range tests {
		steps = append(steps, resource.TestStep{
			Config: acctest.ProviderConfig + tt.config.String(),
			Check:  tt.config.TestChecks(),
		})
		steps = append(steps, resource.TestStep{
			ResourceName:      "crowdstrike_cloud_security_group.test",
			ImportState:       true,
			ImportStateVerify: true,
		})
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccCloudSecurityGroupResource_Validation tests validation errors.
func TestAccCloudSecurityGroupResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "empty_name",
			config: `
resource "crowdstrike_cloud_security_group" "test" {
  name = ""
  aws = {
    account_ids = ["123456789012"]
  }
}`,
			expectError: regexp.MustCompile("Attribute name string length must be between 1 and 100"),
		},
		{
			name: "name_too_long",
			config: fmt.Sprintf(`
resource "crowdstrike_cloud_security_group" "test" {
  name = "%s"
  aws = {
    account_ids = ["123456789012"]
  }
}`, sdkacctest.RandString(101)),
			expectError: regexp.MustCompile("Attribute name string length must be between 1 and 100"),
		},
		{
			name: "invalid_business_impact",
			config: `
resource "crowdstrike_cloud_security_group" "test" {
  name = "test"
  business_impact = "critical"
  aws = {
    account_ids = ["123456789012"]
  }
}`,
			expectError: regexp.MustCompile("Attribute business_impact value must be one of"),
		},
		{
			name: "invalid_environment",
			config: `
resource "crowdstrike_cloud_security_group" "test" {
  name = "test"
  environment = "production"
  aws = {
    account_ids = ["123456789012"]
  }
}`,
			expectError: regexp.MustCompile("Attribute environment value must be one of"),
		},
		{
			name: "invalid_owner_email",
			config: `
resource "crowdstrike_cloud_security_group" "test" {
  name = "test"
  owners = ["not-an-email"]
  aws = {
    account_ids = ["123456789012"]
  }
}`,
			expectError: regexp.MustCompile("must be a valid email address"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      acctest.ProviderConfig + tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

// TestAccCloudSecurityGroupResource_EdgeCases tests edge cases and boundaries.
func TestAccCloudSecurityGroupResource_EdgeCases(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Maximum length name
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name:          sdkacctest.RandString(100),
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "id"),
				),
			},
			{
				ResourceName:      "crowdstrike_cloud_security_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Maximum length description
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name:          rName,
					Description:   utils.Addr(sdkacctest.RandString(1000)),
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "id"),
				),
			},
			{
				ResourceName:      "crowdstrike_cloud_security_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Maximum length business unit
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name:          rName,
					BusinessUnit:  utils.Addr(sdkacctest.RandString(100)),
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("crowdstrike_cloud_security_group.test", "id"),
				),
			},
			{
				ResourceName:      "crowdstrike_cloud_security_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Many owners
			{
				Config: acctest.ProviderConfig + (&groupConfig{
					Name: rName,
					Owners: []string{
						"owner1@example.com",
						"owner2@example.com",
						"owner3@example.com",
						"owner4@example.com",
						"owner5@example.com",
					},
					AWSAccountIDs: []string{"123456789012"},
				}).String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_cloud_security_group.test", "owners.#", "5"),
				),
			},
			{
				ResourceName:      "crowdstrike_cloud_security_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
