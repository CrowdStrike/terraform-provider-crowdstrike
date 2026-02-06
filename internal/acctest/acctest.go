package acctest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/provider"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

const (
	ProviderConfig = `
provider "crowdstrike" {}
`
	CharSetNum     = "0123456789"
	ResourcePrefix = "tf-acc-test-"
)

type OptionalEnvVar string

const (
	RequireHostGroupID    OptionalEnvVar = "HOST_GROUP_ID"
	RequireIOARuleGroupID OptionalEnvVar = "IOA_RULE_GROUP_ID"
)

// ConfigCompose can be called to concatenate multiple strings to build test configurations.
func ConfigCompose(config ...string) string {
	var str strings.Builder

	for _, conf := range config {
		str.WriteString(conf)
	}

	return str.String()
}

// RandomResourceName generates a random resource name with the standard prefix.
func RandomResourceName() string {
	return sdkacctest.RandomWithPrefix(ResourcePrefix)
}

// ProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"crowdstrike": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func PreCheck(t *testing.T, optionalEnvVars ...OptionalEnvVar) {
	t.Helper()

	requiredEnvVars := []string{
		"FALCON_CLIENT_ID",
		"FALCON_CLIENT_SECRET",
	}

	for _, optVar := range optionalEnvVars {
		requiredEnvVars = append(requiredEnvVars, string(optVar))
	}

	for _, envVar := range requiredEnvVars {
		if v := os.Getenv(envVar); v == "" {
			t.Fatalf("%s must be set for acceptance tests", envVar)
		}
	}

	// Configure client only once using sync.Once in testconfig
	cloud := os.Getenv("FALCON_CLOUD")
	if cloud == "" {
		cloud = "autodiscover"
	}

	clientId := os.Getenv("FALCON_CLIENT_ID")
	clientSecret := os.Getenv("FALCON_CLIENT_SECRET")

	ctx := context.Background()
	if err := testconfig.InitializeTestClient(ctx, cloud, clientId, clientSecret); err != nil {
		t.Fatalf("failed to configure Falcon client: %s", err)
	}
}
