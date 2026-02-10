package config

import (
	"github.com/crowdstrike/gofalcon/falcon/client"
)

type ProviderConfig struct {
	ClientId string
	Client   *client.CrowdStrikeAPISpecification
}
