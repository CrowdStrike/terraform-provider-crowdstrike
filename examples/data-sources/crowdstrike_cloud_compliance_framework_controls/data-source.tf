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

# retrieve all controls under a named benchmark
data "crowdstrike_cloud_compliance_framework_controls" "all" {
  benchmark = "CIS 1.0.0 AWS Web Architecture"
}

# retrieve a single control within a benchmark by name
data "crowdstrike_cloud_compliance_framework_controls" "by_name" {
  name      = "Ensure subnets for the Web tier are created"
  benchmark = "CIS 1.0.0 AWS Web Architecture"
}

# retrieve a single control within a benchmark by requirement
data "crowdstrike_cloud_compliance_framework_controls" "by_requirement" {
  requirement = "2.1"
  benchmark   = "CIS 1.0.0 AWS Web Architecture"
}

# query by FQL filter
data "crowdstrike_cloud_compliance_framework_controls" "fql" {
  fql = "compliance_control_name:'Ensure subnets for the Web tier are created'"
}
