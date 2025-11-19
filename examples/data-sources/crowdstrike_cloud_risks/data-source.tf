# Query all high severity risks
data "crowdstrike_cloud_risks" "high_severity" {
  filter = "severity:'High'"
  sort   = "first_seen|desc"
  limit  = 1
}

# Query risks for a specific cloud provider
data "crowdstrike_cloud_risks" "aws_risks" {
  filter = "cloud_provider:'aws'+status:'Open'"
  sort   = "severity|desc"
}

# Query risks for a specific account
data "crowdstrike_cloud_risks" "account_risks" {
  filter = "account_id:'123456789012'"
  limit  = 1
}

# Query risks by rule name
data "crowdstrike_cloud_risks" "specific_rule" {
  filter = "rule_name:*'Identity*'"
  limit  = 1
}

# Output example
output "high_severity_risks" {
  value = data.crowdstrike_cloud_risks.high_severity.risks
}

output "risk_count" {
  value = length(data.crowdstrike_cloud_risks.high_severity.risks)
}
