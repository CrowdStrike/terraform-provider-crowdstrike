package cloudsecurity_test

import (
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
)

type dataRuleConfig struct {
	cloudProvider string
	ruleName      string
	resourceType  string
	benchmark     string
	framework     string
	service       string
}

var awsConfig = dataRuleConfig{
	cloudProvider: "AWS",
	ruleName:      "Auto Scaling group launch configuration not configured with a customer created IAM role",
	resourceType:  "AWS::AutoScaling::LaunchConfiguration",
	benchmark:     "*CIS*",
	framework:     "CIS",
	service:       "Auto Scaling",
}

var azureConfig = dataRuleConfig{
	cloudProvider: "Azure",
	ruleName:      "Virtual Machine allows public internet access to Docker (port 2375/2376)",
	resourceType:  "Microsoft.Compute/virtualMachines",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Virtual Machines",
}

var gcpConfig = dataRuleConfig{
	cloudProvider: "GCP",
	ruleName:      "GKE Cluster insecure kubelet read only port is enabled",
	resourceType:  "container.googleapis.com/Cluster",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Google Kubernetes Engine",
}

// skipIfRegoNotEnabled skips the test if the ENABLE_REGO_TESTS environment variable is not set.
// This is used for tests that use custom Rego logic, which requires the custom policy feature
// flag to be enabled in the CrowdStrike environment.
// To enable these tests, set: export ENABLE_REGO_TESTS=1.
func skipIfRegoNotEnabled(t *testing.T) {
	if os.Getenv("ENABLE_REGO_TESTS") == "" {
		t.Skip("Skipping test: ENABLE_REGO_TESTS environment variable not set. These tests require the custom policy feature flag to be enabled for your CID.")
	}
}

type control struct {
	authority string
	code      string
}

type ruleBaseConfig struct {
	ruleNamePrefix  string
	description     []string
	subdomain       string
	domain          string
	severity        []string
	remediationInfo [][]string
	controls        []control
	logic           []string
	alertInfo       [][]string
	attackTypes     [][]string
}

type ruleCustomConfig struct {
	ruleBaseConfig
	parentId      string
	cloudProvider string
	cloudPlatform string
	resourceType  string
	parentRule    dataRuleConfig
}

var commonConfig = ruleBaseConfig{
	ruleNamePrefix: acctest.ResourcePrefix,
	description: []string{
		"This is a description",
		"This is an updated description",
	},
	subdomain: "IOM",
	domain:    "CSPM",
	severity:  []string{"critical", "informational"},
	remediationInfo: [][]string{
		{"This is the first step", "This is the second step"},
		{"This is the first step", "This is the second step", "This is the third step."},
	},
	controls: []control{
		{
			authority: "CIS",
			code:      "791",
		},
		{
			authority: "CIS",
			code:      "98",
		},
	},
	logic: []string{
		"package crowdstrike\ndefault result = \"pass\"\nresult = \"fail\" if {\n input.tags[_] == \"catch-me\"\n }",
		"package crowdstrike\ndefault result = \"pass\"\nresult = \"fail\" if {\n input.tags[_] == \"catch-me-again\"\n }",
	},
	alertInfo: [][]string{
		{
			"List all Auto Scaling Groups in the account.",
			"Check if multiple instance types are included in the configuration.",
			"Check if multiple availability zones are configured.",
		},
		{
			"Check if multiple instance types are included in the configuration.",
			"List all Auto Scaling Groups in the account.",
			"Check if multiple availability zones are configured.",
			"Alert when any of the above conditions are met.",
		},
	},
	attackTypes: [][]string{
		{"Look it's an attack type"},
		{"Look it's an attack type", "This is a second attack type"},
	},
}

var awsCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "0473a26b-7f29-43c7-9581-105f8c9c0b7d",
	cloudProvider:  "AWS",
	cloudPlatform:  "AWS",
	resourceType:   "AWS::EC2::Instance",
	parentRule:     awsConfig,
}

var azureCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "1c9516e9-490b-461c-8644-9239ff3cf0d3",
	cloudProvider:  "Azure",
	cloudPlatform:  "Azure",
	resourceType:   "Microsoft.Compute/virtualMachines",
	parentRule:     azureConfig,
}

var gcpCopyConfig = ruleCustomConfig{
	ruleBaseConfig: commonConfig,
	parentId:       "0260ffa9-eb65-42f4-a02a-7456d280049a",
	cloudProvider:  "GCP",
	cloudPlatform:  "GCP",
	resourceType:   "sqladmin.googleapis.com/Instance",
	parentRule:     gcpConfig,
}
