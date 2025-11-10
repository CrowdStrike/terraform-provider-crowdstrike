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

# Get all prevention policies
data "crowdstrike_prevention_policies" "all" {
  sort = "name.asc"
}

# Get enabled Windows prevention policies using individual attributes
data "crowdstrike_prevention_policies" "windows_enabled" {
  platform = "Windows"
  enabled  = true
  sort     = "name.asc"
}

# Get specific prevention policies by their IDs
data "crowdstrike_prevention_policies" "specific_policies" {
  ids = [
    "037a1708a8504b3a9cdbfdefba05f932", # Windows platform default
    "4979a243c0d84342a66692f4810348ef", # Mac platform default
    "9913bc2788a449678ab1269f44942463"  # Linux platform default
  ]
}

# Get enabled Linux prevention policies using FQL filter
data "crowdstrike_prevention_policies" "enabled_linux" {
  filter = "platform_name:'Linux'+enabled:true"
  sort   = "name.asc"
}
