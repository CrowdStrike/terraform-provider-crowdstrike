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

# Get all correlation rules
data "crowdstrike_correlation_rules" "all" {}

# Get only active correlation rules using individual attributes
data "crowdstrike_correlation_rules" "active" {
  status = "active"
}

# Get rules by name pattern using individual attributes
data "crowdstrike_correlation_rules" "by_name" {
  name   = "AWS-*"
  status = "active"
}

# Get rules using raw FQL filter
data "crowdstrike_correlation_rules" "by_fql" {
  filter = "status:'active'+name:'AWS-*'"
}

output "active_rule_count" {
  value = length(data.crowdstrike_correlation_rules.active.rules)
}

output "active_rule_names" {
  value = [for r in data.crowdstrike_correlation_rules.active.rules : r.name]
}
