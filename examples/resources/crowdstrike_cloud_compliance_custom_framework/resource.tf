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
    "section-1" = { // immutable unique key
      name = "Section 1"
      controls = {
        "control-1a" = { // immutable unique key
          name        = "Control 1a"
          description = "This is the first control"
          rules       = ["id1", "id2", "id3"]
        }
        "control-1b" = {
          name        = "Control 1b"
          description = "This is another control in section 1"
          rules       = ["id4", "id5"]
        }
      }
    }
    "section-2" = {
      name = "Section 2"
      controls = {
        "control-2" = {
          name        = "Control 2"
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
