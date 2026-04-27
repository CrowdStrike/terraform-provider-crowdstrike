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

# Docker Hub registry
resource "crowdstrike_container_registry" "dockerhub" {
  url                = "https://registry-1.docker.io/"
  type               = "dockerhub"
  user_defined_alias = "My Docker Hub"
  url_uniqueness_key = "my-dockerhub-account"

  credential = {
    username = "myusername"
    password = "<your-dockerhub-token>"
  }
}

# AWS ECR registry
resource "crowdstrike_container_registry" "ecr" {
  url                = "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"
  type               = "ecr"
  user_defined_alias = "Production ECR"

  credential = {
    aws_iam_role    = "arn:aws:iam::123456789012:role/FalconContainerRole"
    aws_external_id = "<your-external-id>"
  }
}

# Azure ACR registry (password authentication)
resource "crowdstrike_container_registry" "acr_password" {
  url                = "https://myregistry.azurecr.io/"
  type               = "acr"
  user_defined_alias = "Production ACR"

  credential = {
    username = "<your-service-principal-name>"
    password = "<your-acr-password>"
  }
}

# Google Artifact Registry
resource "crowdstrike_container_registry" "gar" {
  url                = "https://us-docker.pkg.dev/"
  type               = "gar"
  user_defined_alias = "US Artifact Registry"
  url_uniqueness_key = "us-artifacts"

  credential = {
    project_id = "my-gcp-project"
    scope_name = "us-docker.pkg.dev/my-gcp-project"

    service_account_json = {
      type           = "service_account"
      private_key_id = "<your-key-id>"
      private_key    = "<your-private-key>"
      client_email   = "falcon-scanner@my-gcp-project.iam.gserviceaccount.com"
      client_id      = "<your-client-id>"
      project_id     = "my-gcp-project"
    }
  }
}
