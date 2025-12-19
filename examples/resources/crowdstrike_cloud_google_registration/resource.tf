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


resource "crowdstrike_cloud_google_registration" "example_project" {
  name               = "my-google-cloud-project-registrationchange"
  projects           = ["my-google-cloud-project-id", "project-two"]
  infra_project      = "my-infra-project-id2"
  wif_project        = "my-wif-project-id2"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"

  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration" "example_advanced" {
  name               = "my-advanced-google-cloud-registration"
  projects           = ["project-1", "project-2", "project-3"]
  infra_project      = "my-infra-project"
  wif_project        = "my-wif-project"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"


  excluded_project_patterns = [
    "sys-test-.*",
    "sys-.*-sandbox$"
  ]


  resource_name_prefix = "crowdstrike"
  resource_name_suffix = "prod"

  labels = {
    environment = "production"
    managed_by  = "terraform"
    team        = "security"
  }

  tags = {
    compliance = "required"
    owner      = "security-team"
  }


  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration" "example_folder" {
  name               = "my-folder-registration"
  folders            = ["123456789012"]
  infra_project      = "my-infra-project"
  wif_project        = "my-wif-project"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"

  excluded_project_patterns = ["sys-.*-dev$"]
}

resource "crowdstrike_cloud_google_registration" "example_organization" {
  name               = "my-org-registration"
  organization       = "987654321098"
  infra_project      = "my-infra-project"
  wif_project        = "my-wif-project"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"

  excluded_project_patterns = [
    "sys-.*-dev$",
    "sys-.*-test$"
  ]
}

output "example_registration" {
  value = {
    id              = crowdstrike_cloud_google_registration.example_project.id
    status          = crowdstrike_cloud_google_registration.example_project.status
    wif_pool_id     = crowdstrike_cloud_google_registration.example_project.wif_pool_id
    wif_provider_id = crowdstrike_cloud_google_registration.example_project.wif_provider_id
  }
}
