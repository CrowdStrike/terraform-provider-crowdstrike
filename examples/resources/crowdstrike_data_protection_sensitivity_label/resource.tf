terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

resource "crowdstrike_data_protection_sensitivity_label" "confidential" {
  name                     = "confidential"
  display_name             = "Confidential"
  external_id              = "purview-confidential"
  label_provider           = "microsoft"
  plugins_configuration_id = "plugin-config-id"
  co_authoring             = true
  synced                   = true
}
