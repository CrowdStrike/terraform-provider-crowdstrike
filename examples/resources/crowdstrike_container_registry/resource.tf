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

resource "crowdstrike_container_registry" "docker" {
  type                = "docker"
  url                 = "docker.example.com"
  user_defined_alias  = "Private Docker Registry"
  credential_username = "myuser"
  credential_password = "mypassword"
}

resource "crowdstrike_container_registry" "ecr" {
  type            = "ecr"
  url             = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
  aws_iam_role    = "arn:aws:iam::123456789012:role/CrowdStrikeECRRole"
  aws_external_id = "your-external-id"
}

output "docker_registry" {
  value = crowdstrike_container_registry.docker
}

output "ecr_registry" {
  value = crowdstrike_container_registry.ecr
}
