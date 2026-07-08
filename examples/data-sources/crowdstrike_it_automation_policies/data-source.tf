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

# Look up all Windows IT Automation policies
data "crowdstrike_it_automation_policies" "windows" {
  platform_name = "Windows"
}

# Look up enabled Linux policies by name
data "crowdstrike_it_automation_policies" "prod" {
  platform_name = "Linux"
  name          = "prod*"
  enabled       = true
}

# Look up specific policies by ID
data "crowdstrike_it_automation_policies" "specific" {
  ids = ["f64b95555ef54ea682619ce880d267cc"]
}

# Look up all IT Automation policies across every platform, sorted by precedence
data "crowdstrike_it_automation_policies" "all" {
  sort = "precedence|asc"
}
