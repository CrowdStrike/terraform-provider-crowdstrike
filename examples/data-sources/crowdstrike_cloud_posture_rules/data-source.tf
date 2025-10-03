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

# return a single rule within a cloud provider
data "crowdstrike_cloud_posture_rules" "specific" {
  cloud_provider = "AWS"
  rule_name      = "NLB/ALB configured publicly with TLS/SSL disabled"
}

# query by FQL filter
data "crowdstrike_cloud_posture_rules" "original" {
  fql = "rule_name:'NLB/ALB configured publicly with TLS/SSL disabled'"
}

# return all rules for a specific resource type within a benchmark
data "crowdstrike_cloud_posture_rules" "original" {
  resource_type = "AWS::ElasticLoadBalancingV2::*"
  benchmark     = "CIS 1.0.0 AWS Web Architecture"
}

# return all rules for a specific resource type within an entire framework
data "crowdstrike_cloud_posture_rules" "original" {
  resource_type = "AWS::ElasticLoadBalancingV2::*"
  framework     = "CIS"
}
