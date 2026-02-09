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
  name               = "my-advanced-google-cloud-registration"
  projects           = ["project-1", "project-2", "project-3"]
  infra_project      = "my-infra-project"
  wif_project        = "my-wif-project"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"


  excluded_project_patterns = [
    "test-*",
    "*-sandbox"
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

  excluded_project_patterns = ["*-dev"]
}

resource "crowdstrike_cloud_google_registration" "example_organization" {
  name               = "my-org-registration"
  organization       = "987654321098"
  infra_project      = "my-infra-project"
  wif_project        = "my-wif-project"
  wif_project_number = "123456789012"
  deployment_method  = "terraform-native"

  excluded_project_patterns = [
    "*-dev",
    "*-test"
  ]
}

resource "crowdstrike_cloud_google_registration" "example_infrastructure_manager" {
  name                          = "my-infrastructure-manager-registration"
  projects                      = ["my-project-1", "my-project-2"]
  infra_project                 = "my-infra-project"
  wif_project                   = "my-wif-project"
  wif_project_number            = "123456789012"
  deployment_method             = "infrastructure-manager"
  infrastructure_manager_region = "us-central1"

  realtime_visibility = {
    enabled = true
  }
}
