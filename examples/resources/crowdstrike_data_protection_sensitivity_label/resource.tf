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

# Standard sensitivity label (user-defined)
resource "crowdstrike_data_protection_sensitivity_label" "standard" {
  name           = "Confidential"
  label_provider = "microsoft"
}

# Synced sensitivity label (from upstream provider connector)
resource "crowdstrike_data_protection_sensitivity_label" "synced" {
  name                     = "Confidential"
  external_id              = "a1b2c3d4-label-id-from-provider"
  label_provider           = "microsoft"
  plugins_configuration_id = "plugin-config-id"
}
