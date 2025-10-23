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


resource "crowdstrike_cloud_compliance_custom_framework" "example" {
  name        = "example-framework"
  description = "An example framework created with Terraform"
  sections = {
    "Section 1" = {
      description = "This is the first section"
      controls = {
        "Control 1" = {
          description = "This is the first control"
          rules       = ["id1", "id2", "id3"]
        }
        "Control 1b" = {
          description = "This is another control in section 1"
          rules       = ["id4", "id5"]
        }
      }
    }
    "Section 2" = {
      description = "This is the second section"
      controls = {
        "Control 2" = {
          description = "This is the second control"
          rules       = []
        }
      }
    }
  }
}

output "cloud_compliance_custom_framework" {
  value = crowdstrike_cloud_compliance_custom_framework.example
}
