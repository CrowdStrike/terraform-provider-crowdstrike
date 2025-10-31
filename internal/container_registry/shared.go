package containerregistry

import (
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// containerRegistryScopes defines the required API scopes for container registry operations.
var containerRegistryScopes = []scopes.Scope{
	{
		Name:  "Falcon Container Image",
		Read:  true,
		Write: true,
	},
}

// SupportedRegistryTypes defines the list of supported registry types.
var SupportedRegistryTypes = []string{
	"dockerhub", "ecr", "gcr", "gar", "acr", "artifactory",
	"docker", "github", "gitlab", "icr", "mirantis", "nexus",
	"openshift", "oracle", "quay.io", "harbor",
}

// CommonRegistryFields holds the common field values from an API registry response.
type CommonRegistryFields struct {
	ID                  types.String
	Type                types.String
	URL                 types.String
	UserDefinedAlias    types.String
	RefreshInterval     types.Int64
	LastRefreshedAt     types.String
	NextRefreshAt       types.String
	State               types.String
	StateChangedAt      types.String
	CreatedAt           types.String
	UpdatedAt           types.String
	CredentialExpired   types.Bool
	CredentialExpiredAt types.String
	CredentialCreatedAt types.String
	CredentialUpdatedAt types.String
}

// mapCommonRegistryFields extracts common fields from API registry response.
func mapCommonRegistryFields(registry *models.DomainExternalAPIRegistry) CommonRegistryFields {
	if registry == nil {
		return CommonRegistryFields{}
	}

	fields := CommonRegistryFields{
		ID:               stringFromPointer(registry.ID),
		Type:             stringFromPointer(registry.Type),
		URL:              stringFromPointer(registry.URL),
		UserDefinedAlias: stringFromPointer(registry.UserDefinedAlias),
		RefreshInterval:  int64FromPointer(registry.RefreshInterval),
		LastRefreshedAt:  stringFromPointer(registry.LastRefreshedAt),
		NextRefreshAt:    stringFromPointer(registry.NextRefreshAt),
		State:            stringFromPointer(registry.State),
		StateChangedAt:   stringFromPointer(registry.StateChangedAt),
		CreatedAt:        stringFromPointer(registry.CreatedAt),
		UpdatedAt:        stringFromPointer(registry.UpdatedAt),
	}

	// Handle credential information
	if registry.Credential != nil {
		fields.CredentialExpired = boolFromPointer(registry.Credential.Expired)
		fields.CredentialExpiredAt = stringFromPointer(registry.Credential.ExpiredAt)
		fields.CredentialCreatedAt = stringFromPointer(registry.Credential.CreatedAt)
		fields.CredentialUpdatedAt = stringFromPointer(registry.Credential.UpdatedAt)
	}

	return fields
}
