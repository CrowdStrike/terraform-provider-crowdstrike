# Docker Hub registry
resource "crowdstrike_falcon_container_image" "dockerhub" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"

  user_defined_alias = "My Docker Hub"
  url_uniqueness_key = "my-dockerhub-account"

  credential {
    details {
      username = "myusername"
      password = var.dockerhub_token
    }
  }
}

# AWS ECR registry
resource "crowdstrike_falcon_container_image" "ecr" {
  url  = "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"
  type = "ecr"

  user_defined_alias = "Production ECR"

  credential {
    details {
      aws_iam_role    = "arn:aws:iam::123456789012:role/FalconContainerRole"
      aws_external_id = var.falcon_external_id
    }
  }
}

# Azure ACR with certificate authentication
resource "crowdstrike_falcon_container_image" "acr" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"

  user_defined_alias = "Production ACR"

  credential {
    details {
      cert      = base64encode(file("service-principal.pem"))
      auth_type = "cert"
      tenant_id = "00000000-0000-0000-0000-000000000000"
      client    = "11111111-1111-1111-1111-111111111111"
    }
  }
}

# Google Artifact Registry
resource "crowdstrike_falcon_container_image" "gar" {
  url  = "https://us-docker.pkg.dev/"
  type = "gar"

  user_defined_alias = "US Artifact Registry"
  url_uniqueness_key = "us-artifacts"

  credential {
    details {
      project_id = "my-gcp-project"
      scope_name = "us-docker.pkg.dev/my-gcp-project"

      service_account_json {
        type           = "service_account"
        private_key_id = var.gcp_key_id
        private_key    = var.gcp_private_key
        client_email   = "falcon-scanner@my-gcp-project.iam.gserviceaccount.com"
        client_id      = var.gcp_client_id
        project_id     = "my-gcp-project"
      }
    }
  }
}
