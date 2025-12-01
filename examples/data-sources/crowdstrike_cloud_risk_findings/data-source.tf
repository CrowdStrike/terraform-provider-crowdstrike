# Example 1: Fetch all open high severity risks
# This automatically paginates through all pages
data "crowdstrike_cloud_risk_findings" "high_severity" {
  filter = "last_seen:>'2025-11-24T09:48:12.983Z'"
  sort   = "first_seen.desc"
}

output "total_high_severity_risks" {
  value = length(data.crowdstrike_cloud_risk_findings.high_severity.risks)
}

# Example 2: Fetch all critical risks for a specific account
data "crowdstrike_cloud_risk_findings" "account_critical" {
  filter = "rule_name:*'High privileged identity '+severity:'High'"
}

output "critical_risks_by_rule" {
  value = {
    for risk in data.crowdstrike_cloud_risk_findings.account_critical.risks :
    risk.rule_name => risk.asset_gcrn...
  }
}

# Example 3: Get all unresolved risks
data "crowdstrike_cloud_risk_findings" "unresolved" {
  filter = "status:'Open'+severity:'High'"
}

locals {
  risks_by_severity = {
    for risk in data.crowdstrike_cloud_risk_findings.unresolved.risks :
    risk.severity => risk...
  }
}

output "risk_counts_by_severity" {
  value = {
    for severity, risks in local.risks_by_severity :
    severity => length(risks)
  }
}
