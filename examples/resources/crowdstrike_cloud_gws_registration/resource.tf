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

# Add the Google Workspace to the Google Cloud registration in the Falcon console first.
resource "crowdstrike_cloud_gws_registration" "example" {
  gcp_registration_id = "my-google-cloud-registration-id"
}

output "gws_registration" {
  value = crowdstrike_cloud_gws_registration.example
}
