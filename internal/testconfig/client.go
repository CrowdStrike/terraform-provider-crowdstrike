package testconfig

import (
	"context"
	"net/http"
	"os"
	"sync"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
)

var (
	// clientConfigure ensures the Falcon client is only created once.
	clientConfigure sync.Once

	// cachedClient is the cached Falcon client used across all test providers.
	cachedClient *client.CrowdStrikeAPISpecification

	// clientError stores any error from client initialization.
	clientError error
)

// InitializeTestClient initializes the test client once using sync.Once.
// This function is called from PreCheck and ensures that only one client is configured.
func InitializeTestClient(ctx context.Context, cloud, clientId, clientSecret string) error {
	clientConfigure.Do(func() {
		tflog.Info(ctx, "Creating Falcon test client")
		apiConfig := falcon.ApiConfig{
			Cloud:             falcon.Cloud(cloud),
			ClientId:          clientId,
			ClientSecret:      clientSecret,
			UserAgentOverride: "terraform-provider-crowdstrike/test",
			Context:           context.Background(),
			HostOverride:      os.Getenv("HOST_OVERRIDE"),
			TransportDecorator: falcon.TransportDecorator(func(r http.RoundTripper) http.RoundTripper {
				return logging.NewLoggingHTTPTransport(r)
			}),
		}

		client, err := falcon.NewClient(&apiConfig)
		if err != nil {
			clientError = err
			tflog.Error(ctx, "Failed to create test client", map[string]interface{}{"error": err.Error()})
			return
		}

		cachedClient = client
		tflog.Info(ctx, "Test client created successfully")
	})

	return clientError
}

// GetTestClient returns the cached test client for use in provider Configure during tests.
// Returns nil if the client has not been initialized yet.
func GetTestClient() *client.CrowdStrikeAPISpecification {
	return cachedClient
}
