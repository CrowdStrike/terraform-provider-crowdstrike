package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func TestProviderGetSchema(t *testing.T) {
	providerServer, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("unexpected error creating provider server: %s", err)
	}

	_, err = providerServer.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("unexpected error getting provider schema: %s", err)
	}
}
