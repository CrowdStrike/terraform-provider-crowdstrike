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

resource "crowdstrike_cloud_google_workspace_registration" "example" {
  registration_id = "my-google-cloud-registration-id"
  customer_id     = "C01abc2de"
  organization_id = "123456789012"
}

output "google_workspace_registration" {
  value = crowdstrike_cloud_google_workspace_registration.example
}
