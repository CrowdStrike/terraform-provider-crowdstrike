package clientoverrides

import (
	"github.com/crowdstrike/gofalcon/falcon/client"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/runtime/yamlpc"
)

// YAMLMime is the YAML media type CrowdStrike endpoints accept. go-openapi's
// runtime.YAMLMime is application/x-yaml, which the Fusion SOAR workflow
// update endpoint rejects with 415 Unsupported Media Type.
const YAMLMime = "application/yaml"

// RegisterYAMLProducer lets operations send application/yaml request bodies.
//
// gofalcon's transport registers request producers only for the go-openapi
// defaults, so an operation that selects application/yaml fails before the
// request is sent with "none of producers ... registered". Register it once,
// right after the client is created and before it is shared, because the
// producer map is read without locking on every request.
func RegisterYAMLProducer(apiClient *client.CrowdStrikeAPISpecification) {
	runtime, ok := apiClient.Transport.(*httptransport.Runtime)
	if !ok {
		return
	}

	runtime.Producers[YAMLMime] = yamlpc.YAMLProducer()
}
