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

resource "crowdstrike_cloud_gws_registration" "workspace" {
  gcp_registration_id = "my-google-cloud-registration-id"
}

# The four values are the outputs of the Google Workspace Terraform module.
resource "crowdstrike_cloud_gws_registration_settings" "example" {
  gcp_registration_id = crowdstrike_cloud_gws_registration.workspace.gcp_registration_id
  registration_id     = crowdstrike_cloud_gws_registration.workspace.id
  sa_email            = "csgws-1a2b3c4d5e6@my-wif-project-id.iam.gserviceaccount.com"
  sa_unique_id        = "123456789012345678901"
  wif_principal       = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/my-pool/subject/my-subject/my-google-workspace-registration-id"
  project_number      = "123456789012"
}
