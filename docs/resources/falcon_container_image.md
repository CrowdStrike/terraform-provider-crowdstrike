---
page_title: "crowdstrike_falcon_container_image Resource - crowdstrike"
subcategory: "Falcon Container Image"
description: |-
  Manages container registry connections in CrowdStrike Falcon Container Security. This resource allows you to connect container registries for image scanning and vulnerability assessment.
  API Scopes
  The following API scopes are required:
  Falcon Container Image | Read & Write
---

# crowdstrike_falcon_container_image (Resource)

Manages container registry connections in CrowdStrike Falcon Container Security. This resource allows you to connect container registries for image scanning and vulnerability assessment.

## API Scopes

The following API scopes are required:

- Falcon Container Image | Read & Write


## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `credential` (Attributes) The credentials for accessing the registry. (see [below for nested schema](#nestedatt--credential))
- `type` (String) The type of container registry. Must be one of: `acr`, `artifactory`, `docker`, `dockerhub`, `ecr`, `gar`, `gcr`, `github`, `gitlab`, `harbor`, `icr`, `mirantis`, `nexus`, `openshift`, `oracle`, `quay.io`.
- `url` (String) The URL of the container registry. Must match the format expected by the registry type.

### Optional

- `url_uniqueness_key` (String) A unique key for registries where multiple accounts can use the same URL (e.g., Docker Hub, Google registries).
- `user_defined_alias` (String) A user-defined friendly name for the registry. When omitted, Terraform retains the value returned by the API. Once set, this value can be updated but not cleared via Terraform due to API limitations.

### Read-Only

- `created_at` (String) Timestamp when the registry was created.
- `id` (String) The UUID of the registry entity.
- `last_refreshed_at` (String) Timestamp when the registry was last refreshed.
- `next_refresh_at` (String) Timestamp when the registry will be refreshed next.
- `refresh_interval` (Number) The refresh interval in seconds.
- `state` (String) The current state of the registry entity.
- `state_changed_at` (String) Timestamp when the state last changed.
- `updated_at` (String) Timestamp when the registry was last updated.
- `url_uniqueness_alias` (String) System-generated URL uniqueness alias.

<a id="nestedatt--credential"></a>
### Nested Schema for `credential`

Optional:

- `auth_type` (String) Authentication type. Required for: `acr` (certificate auth). Valid value: `cert`.
- `aws_external_id` (String) AWS external ID. Required for: `ecr`.
- `aws_gov_using_commercial_connection` (Boolean) Whether AWS GovCloud uses commercial connection. Optional for: `ecr`.
- `aws_iam_role` (String) AWS IAM role ARN. Required for: `ecr`.
- `cert` (String, Sensitive) Azure service principal certificate as base64-encoded PEM. Required for: `acr` (certificate auth).
- `client` (String) Azure client ID. Required for: `acr` (certificate auth).
- `compartment_ids` (Set of String) Oracle compartment IDs. Required for: `oracle`.
- `credential_type` (String) Type of credential. Required for: `github`, `gitlab`. Valid value: `PAT`.
- `domain_url` (String) Domain URL for API access. Required for: `github`, `gitlab`.
- `password` (String, Sensitive) Password, API key, or access token. Required for: `dockerhub`, `docker`, `github`, `gitlab`, `icr`, `artifactory`, `acr` (password auth), `mirantis`, `oracle`, `openshift`, `quay.io`, `nexus`, `harbor`.
- `project_id` (String) GCP project ID. Required for: `gar`, `gcr`.
- `scope_name` (String) Scope name. Required for: `gar`, `oracle`.
- `service_account_json` (Attributes) GCP service account JSON. Required for: `gar`, `gcr`. (see [below for nested schema](#nestedatt--credential--service_account_json))
- `tenant_id` (String) Azure tenant ID. Required for: `acr` (certificate auth).
- `username` (String) Username for authentication. Required for: `dockerhub`, `docker`, `github`, `gitlab`, `icr`, `artifactory`, `acr` (password auth), `mirantis`, `oracle`, `openshift`, `quay.io`, `nexus`, `harbor`.

Read-Only:

- `credential_created_at` (String) Timestamp when the credential was created.
- `credential_expired` (Boolean) Whether the credential has expired.
- `credential_expired_at` (String) Timestamp when the credential expired.
- `credential_id` (String) The ID of the credential.
- `credential_updated_at` (String) Timestamp when the credential was last updated.

<a id="nestedatt--credential--service_account_json"></a>
### Nested Schema for `credential.service_account_json`

Required:

- `client_email` (String) Client email.
- `client_id` (String) Client ID.
- `private_key` (String, Sensitive) Private key.
- `private_key_id` (String) Private key ID.
- `project_id` (String) Project ID.
- `type` (String) Service account type. Typically `service_account`.

## Import

Import is supported using the following syntax:

```shell
#!/bin/bash

# Import a Falcon Container Image registry using its UUID.
terraform import crowdstrike_falcon_container_image.example <registry_uuid>

# Example:
# terraform import crowdstrike_falcon_container_image.example a1b2c3d4-e5f6-7890-abcd-ef1234567890

# NOTE: The API does not return credential values, so all credential fields
# (username, password, aws_iam_role, cert, service_account_json, etc.) will be
# null in state after import. You must add them to your configuration and run
# `terraform apply` to restore them.
```
