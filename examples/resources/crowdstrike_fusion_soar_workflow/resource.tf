terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# The definition uses the YAML format the Falcon console exports. To manage an
# existing workflow, export it from the console and load the exported file.
resource "crowdstrike_fusion_soar_workflow" "from_file" {
  enabled    = true
  definition = file("${path.module}/workflow.yaml")
}

# The definition can also be written inline.
resource "crowdstrike_fusion_soar_workflow" "inline" {
  enabled = true

  definition = <<-EOT
    name: tf-example-inline-workflow
    description: Pauses for one minute when run on demand.
    trigger:
      next:
        - Sleep
      name: On demand
      type: On demand
    actions:
      Sleep:
        id: 4f1af1ae4c13dc1e3bcd725f8dc0f63b
        properties:
          sleep_time: 1m
        version_constraint: ~1
  EOT
}

output "fusion_soar_workflow_from_file" {
  value = crowdstrike_fusion_soar_workflow.from_file
}

output "fusion_soar_workflow_inline" {
  value = crowdstrike_fusion_soar_workflow.inline
}
