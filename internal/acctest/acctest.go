package acctest

import (
	"net/http"
	"os"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
)

const (
	ProviderConfig = `
provider "crowdstrike" {}
`
	CharSetNum = "0123456789"
)

type OptionalEnvVar string

const (
	RequireHostGroupID    OptionalEnvVar = "HOST_GROUP_ID"
	RequireIOARuleGroupID OptionalEnvVar = "IOA_RULE_GROUP_ID"
)

// ProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"crowdstrike": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func PreCheck(t *testing.T, optionalEnvVars ...OptionalEnvVar) {
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
}

func FalconTestClient(t *testing.T) *client.CrowdStrikeAPISpecification {
	cloud := os.Getenv("FALCON_CLOUD")
	clientId := os.Getenv("FALCON_CLIENT_ID")
	clientSecret := os.Getenv("FALCON_CLIENT_SECRET")

	if cloud == "" {
		cloud = "autodiscover"
	}

	apiConfig := falcon.ApiConfig{
		Cloud:             falcon.Cloud(cloud),
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		UserAgentOverride: "terraform-provider-crowdstrike/test",
		Context:           t.Context(),
		HostOverride:      os.Getenv("HOST_OVERRIDE"),
		TransportDecorator: falcon.TransportDecorator(func(r http.RoundTripper) http.RoundTripper {
			return logging.NewLoggingHTTPTransport(r)
		}),
	}

	client, err := falcon.NewClient(&apiConfig)
	if err != nil {
		t.Fatalf("Unable to create falcon client: %s", err)
	}

	return client
}
