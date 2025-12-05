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


# Example 1: Fetch recent cloud risk findings
data "crowdstrike_cloud_risk_findings" "recent" {
  filter = "last_seen:>'2025-11-24T09:48:12.983Z'"
  sort   = "first_seen.desc"
}

output "total_recent_risks" {
  value = length(data.crowdstrike_cloud_risk_findings.recent.risks)
}

# Example 2: Fetch high severity privileged identity risk findings
data "crowdstrike_cloud_risk_findings" "privileged_identity" {
  filter = "rule_name:*'High privileged identity '+severity:'Medium'"
}

output "privileged_identity_risks_by_rule" {
  value = {
    for risk in data.crowdstrike_cloud_risk_findings.privileged_identity.risks :
    risk.rule_name => risk.asset_gcrn...
  }
}

# Example 3: Get high severity open risk findings
data "crowdstrike_cloud_risk_findings" "high_severity_open" {
  filter = "status:'Open'+severity:'High'"
}

locals {
  risks_by_severity = {
    for risk in data.crowdstrike_cloud_risk_findings.high_severity_open.risks :
    risk.severity => risk...
  }
}

output "risk_counts_by_severity" {
  value = {
    for severity, risks in local.risks_by_severity :
    severity => length(risks)
  }
}
