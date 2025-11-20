# Example 1: Fetch all open high severity risks
# This automatically paginates through all pages
data "crowdstrike_cloud_risks_all" "high_severity" {
  filter = "severity:'High'+status:'Open'"
  sort   = "first_seen|desc"
}

output "total_high_severity_risks" {
  value = length(data.crowdstrike_cloud_risks_all.high_severity.risks)
}

# Example 2: Fetch all critical risks for a specific account
data "crowdstrike_cloud_risks_all" "account_critical" {
  filter = "account_id:'123456789012'+severity:'Critical'"
}

output "critical_risks_by_rule" {
  value = {
    for risk in data.crowdstrike_cloud_risks_all.account_critical.risks :
    risk.rule_name => risk.severity...
  }
}

# Example 3: Get all unresolved risks
data "crowdstrike_cloud_risks_all" "unresolved" {
  filter = "status:'Open'+severity:'High'"
}

locals {
  risks_by_severity = {
    for risk in data.crowdstrike_cloud_risks_all.unresolved.risks :
    risk.severity => risk...
  }
}

output "risk_counts_by_severity" {
  value = {
    for severity, risks in local.risks_by_severity :
    severity => length(risks)
  }
}
