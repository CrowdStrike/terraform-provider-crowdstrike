package itautomation_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const precedenceResourceName = "crowdstrike_it_automation_policy_precedence.test"

type precedenceConfig struct {
	Platform          string
	Enforcement       string
	IDs               []string
	ExistingPolicyIDs []string
}

func (config *precedenceConfig) String() string {
	var allIDs []string

	platformLower := strings.ToLower(config.Platform)
	for i := range len(config.IDs) {
		allIDs = append(allIDs, fmt.Sprintf("crowdstrike_it_automation_policy.%s_%d.id", platformLower, i+1))
	}

	for _, existingID := range config.ExistingPolicyIDs {
		allIDs = append(allIDs, fmt.Sprintf("%q", existingID))
	}

	idsBlock := ""
	if len(allIDs) > 0 {
		idsBlock = fmt.Sprintf("\n  ids = [%s]\n", strings.Join(allIDs, ", "))
	}

	return fmt.Sprintf(`
resource "crowdstrike_it_automation_policy_precedence" "test" {
  platform_name = %q
  enforcement   = %q%s
}
`, config.Platform, config.Enforcement, idsBlock)
}

func (config *precedenceConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(precedenceResourceName, "id"),
		resource.TestCheckResourceAttrSet(precedenceResourceName, "last_updated"),
		resource.TestCheckResourceAttr(precedenceResourceName, "platform_name", config.Platform),
		resource.TestCheckResourceAttr(precedenceResourceName, "enforcement", config.Enforcement),
	)

	totalIDs := len(config.IDs) + len(config.ExistingPolicyIDs)
	if totalIDs > 0 {
		checks = append(checks,
			resource.TestCheckResourceAttr(precedenceResourceName, "ids.#", fmt.Sprintf("%d", totalIDs)),
		)
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func shuffleIDs(ids []string) []string {
	shuffled := make([]string, len(ids))
	copy(shuffled, ids)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

func TestAccITAutomationPolicyPrecedenceResource_Windows(t *testing.T) {
	sdk := createSDKFixtures(t)
	defer sdk.Cleanup(t)

	numPolicies := 3
	policyIDs := make([]string, numPolicies)
	for i := range numPolicies {
		policyIDs[i] = fmt.Sprintf("placeholder-%d", i)
	}

	fixtures := getTestFixtures()
	baseConfig := acctest.ProviderConfig + fixtures.WindowsHostGroupsOnly() + fixtures.WindowsPoliciesOnly()

	existingPolicyIDs := sdk.GetExistingPolicyIDs(t, "Windows")

	dynamicInitialConfig := precedenceConfig{
		Platform:    "Windows",
		Enforcement: "dynamic",
		IDs:         policyIDs,
	}
	dynamicReorderedConfig := precedenceConfig{
		Platform:    "Windows",
		Enforcement: "dynamic",
		IDs:         shuffleIDs(policyIDs),
	}
	strictInitialConfig := precedenceConfig{
		Platform:          "Windows",
		Enforcement:       "strict",
		IDs:               policyIDs,
		ExistingPolicyIDs: existingPolicyIDs,
	}
	strictReorderedConfig := precedenceConfig{
		Platform:          "Windows",
		Enforcement:       "strict",
		IDs:               shuffleIDs(policyIDs),
		ExistingPolicyIDs: existingPolicyIDs,
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: baseConfig + dynamicInitialConfig.String(),
				Check:  dynamicInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + dynamicReorderedConfig.String(),
				Check:  dynamicReorderedConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictInitialConfig.String(),
				Check:  strictInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictReorderedConfig.String(),
				Check:  strictReorderedConfig.TestChecks(),
			},
		},
	})
}

func TestAccITAutomationPolicyPrecedenceResource_Linux(t *testing.T) {
	sdk := createSDKFixtures(t)
	defer sdk.Cleanup(t)

	numPolicies := 3
	policyIDs := make([]string, numPolicies)
	for i := range numPolicies {
		policyIDs[i] = fmt.Sprintf("placeholder-%d", i)
	}

	fixtures := getTestFixtures()
	baseConfig := acctest.ProviderConfig + fixtures.LinuxHostGroupsOnly() + fixtures.LinuxPoliciesOnly()

	existingPolicyIDs := sdk.GetExistingPolicyIDs(t, "Linux")

	dynamicInitialConfig := precedenceConfig{
		Platform:    "Linux",
		Enforcement: "dynamic",
		IDs:         policyIDs,
	}
	dynamicReorderedConfig := precedenceConfig{
		Platform:    "Linux",
		Enforcement: "dynamic",
		IDs:         shuffleIDs(policyIDs),
	}
	strictInitialConfig := precedenceConfig{
		Platform:          "Linux",
		Enforcement:       "strict",
		IDs:               policyIDs,
		ExistingPolicyIDs: existingPolicyIDs,
	}
	strictReorderedConfig := precedenceConfig{
		Platform:          "Linux",
		Enforcement:       "strict",
		IDs:               shuffleIDs(policyIDs),
		ExistingPolicyIDs: existingPolicyIDs,
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: baseConfig + dynamicInitialConfig.String(),
				Check:  dynamicInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + dynamicReorderedConfig.String(),
				Check:  dynamicReorderedConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictInitialConfig.String(),
				Check:  strictInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictReorderedConfig.String(),
				Check:  strictReorderedConfig.TestChecks(),
			},
		},
	})
}

func TestAccITAutomationPolicyPrecedenceResource_Mac(t *testing.T) {
	sdk := createSDKFixtures(t)
	defer sdk.Cleanup(t)

	numPolicies := 3
	policyIDs := make([]string, numPolicies)
	for i := range numPolicies {
		policyIDs[i] = fmt.Sprintf("placeholder-%d", i)
	}

	fixtures := getTestFixtures()
	baseConfig := acctest.ProviderConfig + fixtures.MacHostGroupsOnly() + fixtures.MacPoliciesOnly()

	existingPolicyIDs := sdk.GetExistingPolicyIDs(t, "Mac")

	dynamicInitialConfig := precedenceConfig{
		Platform:    "Mac",
		Enforcement: "dynamic",
		IDs:         policyIDs,
	}
	dynamicReorderedConfig := precedenceConfig{
		Platform:    "Mac",
		Enforcement: "dynamic",
		IDs:         shuffleIDs(policyIDs),
	}
	strictInitialConfig := precedenceConfig{
		Platform:          "Mac",
		Enforcement:       "strict",
		IDs:               policyIDs,
		ExistingPolicyIDs: existingPolicyIDs,
	}
	strictReorderedConfig := precedenceConfig{
		Platform:          "Mac",
		Enforcement:       "strict",
		IDs:               shuffleIDs(policyIDs),
		ExistingPolicyIDs: existingPolicyIDs,
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.12.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: baseConfig + dynamicInitialConfig.String(),
				Check:  dynamicInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + dynamicReorderedConfig.String(),
				Check:  dynamicReorderedConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictInitialConfig.String(),
				Check:  strictInitialConfig.TestChecks(),
			},
			{
				Config: baseConfig + strictReorderedConfig.String(),
				Check:  strictReorderedConfig.TestChecks(),
			},
		},
	})
}
