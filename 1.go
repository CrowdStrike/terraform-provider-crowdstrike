package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
)

func main() {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     os.Getenv("FALCON_CLIENT_ID"),
		ClientSecret: os.Getenv("FALCON_CLIENT_SECRET"),
		Context:      context.Background(),
	})
	if err != nil {
		panic(err)
	}

	res, err := client.PreventionPolicies.GetPreventionPolicies(
		&prevention_policies.GetPreventionPoliciesParams{
			Ids:     []string{"021ec3f769cd43a4906138be5348e1c7"},
			Context: context.Background(),
		},
	)

	type toggle struct {
		Enabled bool `json:"enabled"`
	}

	type mlSLider struct {
		Detection  string `json:"detection"`
		Prevention string `json:"prevention"`
	}

	for _, c := range res.Payload.Resources[0].PreventionSettings {
		fmt.Printf("Category: %s\n\n", *c.Name)
		for _, s := range c.Settings {
			fmt.Printf("Name: %s\n", *s.Name)
			fmt.Printf("Type: %s\n", *s.Type)
			fmt.Printf("ID: %s\n", *s.ID)
			fmt.Printf("Description: %s\n", s.Description)
			if strings.EqualFold(*s.Type, "toggle") {
				v, _ := s.Value.(map[string]interface{})
				enabled := v["enabled"].(bool)
				fmt.Printf("Value: %t\n", enabled)
			} else if strings.EqualFold(*s.Type, "mlslider") {
				v, _ := s.Value.(map[string]interface{})
				detection := v["detection"].(string)
				prevention := v["prevention"].(string)
				fmt.Printf("Value: detection %s, prevention %s\n", detection, prevention)
			}
			fmt.Printf("Unconverted Value: %s\n", s.Value)
			fmt.Println("-------")
		}
	}
}
