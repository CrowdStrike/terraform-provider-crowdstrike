# Docker Hub registry
# url_uniqueness_key is required when multiple accounts share the same registry URL.
# user_defined_alias is optional. Once set, it can be updated but not cleared via Terraform.
resource "crowdstrike_falcon_container_image" "dockerhub" {
  url  = "https://registry-1.docker.io/"
  type = "dockerhub"

  user_defined_alias = "My Docker Hub"
  url_uniqueness_key = "my-dockerhub-account"

  credential = {
    username = "myusername"
    password = var.dockerhub_token
  }
}

# AWS ECR registry
resource "crowdstrike_falcon_container_image" "ecr" {
  url  = "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"
  type = "ecr"

  user_defined_alias = "Production ECR"

  credential = {
    aws_iam_role    = "arn:aws:iam::123456789012:role/FalconContainerRole"
    aws_external_id = var.falcon_external_id
  }
}

# AWS GovCloud ECR registry using commercial connection
resource "crowdstrike_falcon_container_image" "ecr_gov" {
  url  = "https://123456789012.dkr.ecr.us-gov-east-1.amazonaws.com"
  type = "ecr"

  user_defined_alias = "GovCloud ECR"

  credential = {
    aws_iam_role                        = "arn:aws-us-gov:iam::123456789012:role/FalconContainerRole"
    aws_external_id                     = var.falcon_external_id
    aws_gov_using_commercial_connection = true
  }
}

# Azure ACR with certificate authentication
resource "crowdstrike_falcon_container_image" "acr_cert" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"

  user_defined_alias = "Production ACR (cert)"

  credential = {
    cert      = base64encode(file("service-principal.pem"))
    auth_type = "cert"
    tenant_id = "00000000-0000-0000-0000-000000000000"
    client    = "11111111-1111-1111-1111-111111111111"
  }
}

# Azure ACR with username/password authentication
resource "crowdstrike_falcon_container_image" "acr_password" {
  url  = "https://myregistry.azurecr.io/"
  type = "acr"

  user_defined_alias = "Production ACR (password)"
  url_uniqueness_key = "acr-password-account"

  credential = {
    username = "myusername"
    password = var.acr_password
  }
}

# Google Artifact Registry
resource "crowdstrike_falcon_container_image" "gar" {
  url  = "https://us-docker.pkg.dev/"
  type = "gar"

  user_defined_alias = "US Artifact Registry"
  url_uniqueness_key = "us-artifacts"

  credential = {
    project_id = "my-gcp-project"
    scope_name = "us-docker.pkg.dev/my-gcp-project"

    service_account_json = {
      type           = "service_account"
      private_key_id = var.gcp_key_id
      private_key    = var.gcp_private_key
      client_email   = "falcon-scanner@my-gcp-project.iam.gserviceaccount.com"
      client_id      = var.gcp_client_id
      project_id     = "my-gcp-project"
    }
  }
}

# Google Container Registry
resource "crowdstrike_falcon_container_image" "gcr" {
  url  = "https://gcr.io/"
  type = "gcr"

  user_defined_alias = "GCR Production"
  url_uniqueness_key = "gcr-production"

  credential = {
    project_id = "my-gcp-project"

    service_account_json = {
      type           = "service_account"
      private_key_id = var.gcp_key_id
      private_key    = var.gcp_private_key
      client_email   = "falcon-scanner@my-gcp-project.iam.gserviceaccount.com"
      client_id      = var.gcp_client_id
      project_id     = "my-gcp-project"
    }
  }
}

# GitHub Container Registry
resource "crowdstrike_falcon_container_image" "github" {
  url  = "https://ghcr.io/"
  type = "github"

  user_defined_alias = "GitHub Container Registry"
  url_uniqueness_key = "my-github-org"

  credential = {
    username        = "myusername"
    password        = var.github_pat
    domain_url      = "https://github.com"
    credential_type = "PAT"
  }
}

# GitLab Container Registry
resource "crowdstrike_falcon_container_image" "gitlab" {
  url  = "https://registry.gitlab.com/"
  type = "gitlab"

  user_defined_alias = "GitLab Registry"
  url_uniqueness_key = "my-gitlab-group"

  credential = {
    username        = "myusername"
    password        = var.gitlab_pat
    domain_url      = "https://gitlab.com"
    credential_type = "PAT"
  }
}

# Oracle Container Registry
resource "crowdstrike_falcon_container_image" "oracle" {
  url  = "https://iad.ocir.io/"
  type = "oracle"

  user_defined_alias = "Oracle Registry"

  credential = {
    username   = "mytenancy/myusername"
    password   = var.oracle_auth_token
    scope_name = "iad.ocir.io/mytenancy"
    compartment_ids = [
      "ocid1.compartment.oc1..aaaaaaaa1111111111111111111111111111111111111111111111111111",
    ]
  }
}

# Generic Docker registry (self-hosted)
# Also applies to: artifactory, harbor, icr, mirantis, nexus, openshift, quay.io
resource "crowdstrike_falcon_container_image" "docker" {
  url  = "https://registry.example.com/"
  type = "docker"

  user_defined_alias = "Internal Registry"

  credential = {
    username = "myusername"
    password = var.registry_password
  }
}
