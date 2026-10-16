# Resolve the group in the tenant configured by the provider.
data "crowdstrike_ioa_rule_group" "linux_monitoring" {
  name     = "Linux Monitoring Rules"
  platform = "Linux"
}

# Use the resolved ID in a prevention policy's ioa_rule_groups attribute.
output "linux_monitoring_group_id" {
  value = data.crowdstrike_ioa_rule_group.linux_monitoring.id
}

# Alternatively, look up a group by its ID.
data "crowdstrike_ioa_rule_group" "by_id" {
  id = "1234567890abcdef1234567890abcdef"
}
