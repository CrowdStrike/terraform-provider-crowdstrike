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

# Get all available content category versions
data "crowdstrike_content_category_versions" "available" {}

# Display the available versions as outputs
output "sensor_operations_versions" {
  description = "Available versions for Sensor Operations content category"
  value       = data.crowdstrike_content_category_versions.available.sensor_operations
}

output "system_critical_versions" {
  description = "Available versions for System Critical content category"
  value       = data.crowdstrike_content_category_versions.available.system_critical
}

output "vulnerability_management_versions" {
  description = "Available versions for Vulnerability Management content category"
  value       = data.crowdstrike_content_category_versions.available.vulnerability_management
}

output "rapid_response_versions" {
  description = "Available versions for Rapid Response content category"
  value       = data.crowdstrike_content_category_versions.available.rapid_response
}
