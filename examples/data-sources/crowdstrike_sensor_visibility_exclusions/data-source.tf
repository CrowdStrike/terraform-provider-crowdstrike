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

# Get all sensor visibility exclusions
data "crowdstrike_sensor_visibility_exclusions" "all" {
  sort = "value.asc"
}

# Get globally applied exclusions using individual attributes
data "crowdstrike_sensor_visibility_exclusions" "global_exclusions" {
  applied_globally = true
  sort             = "created_on.desc"
}

# Get exclusions created by specific users with wildcard matching
data "crowdstrike_sensor_visibility_exclusions" "admin_exclusions" {
  created_by = "admin*"
  sort       = "value.asc"
}

# Get exclusions for specific paths using wildcard matching
data "crowdstrike_sensor_visibility_exclusions" "windows_exclusions" {
  value = "C:\\Program Files\\*"
  sort  = "last_modified.desc"
}

# Get specific exclusions by their IDs
data "crowdstrike_sensor_visibility_exclusions" "specific_exclusions" {
  ids = [
    "037a1708a8504b3a9cdbfdefba05f932",
    "4979a243c0d84342a66692f4810348ef"
  ]
}

# Get globally applied exclusions using FQL filter
data "crowdstrike_sensor_visibility_exclusions" "fql_global" {
  filter = "applied_globally:true"
  sort   = "value.asc"
}

# Get exclusions modified by specific user using FQL filter
data "crowdstrike_sensor_visibility_exclusions" "fql_modified_by_admin" {
  filter = "modified_by:'admin@company.com'"
  sort   = "last_modified.desc"
}

# Combined filters using individual attributes
data "crowdstrike_sensor_visibility_exclusions" "combined_filters" {
  applied_globally = false
  created_by       = "*admin*"
  value            = "/opt/*"
  sort             = "created_on.desc"
}
