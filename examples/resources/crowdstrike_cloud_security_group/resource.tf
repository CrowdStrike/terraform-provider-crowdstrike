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

# Basic cloud security group with business context
resource "crowdstrike_cloud_security_group" "basic" {
  name            = "production-web-services"
  business_impact = "high"
  business_unit   = "Engineering"
  environment     = "prod"
  owners          = ["team-lead@company.com", "security@company.com"]
}

# Cloud security group with AWS cloud resources
resource "crowdstrike_cloud_security_group" "aws_resources" {
  name            = "aws-production-resources"
  description     = "AWS production resources across multiple accounts"
  business_impact = "high"
  business_unit   = "Platform"
  environment     = "prod"
  owners          = ["cloud-team@company.com"]

  aws = {
    account_ids = ["123456789012", "123456789013"]
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["Environment=Production", "Team=WebServices"]
    }
  }
}

# Cloud security group with Azure cloud resources
resource "crowdstrike_cloud_security_group" "azure_resources" {
  name        = "azure-staging-resources"
  description = "Azure staging environment resources"
  environment = "stage"

  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus", "westus2"]
      tags   = ["Team=Platform", "Environment=Staging"]
    }
  }
}

# Cloud security group with GCP cloud resources
resource "crowdstrike_cloud_security_group" "gcp_resources" {
  name        = "gcp-dev-resources"
  description = "GCP development resources"
  environment = "dev"

  gcp = {
    account_ids = ["my-gcp-project-123"]
    filters = {
      region = ["us-central1", "us-east1"]
      # Note: GCP does not support tag filtering
    }
  }
}

# Cloud security group with container images
resource "crowdstrike_cloud_security_group" "container_images" {
  name            = "production-containers"
  description     = "Production container images"
  business_impact = "high"
  environment     = "prod"
  owners          = ["devops@company.com"]

  images = [
    {
      registry   = "docker.io"
      repository = "mycompany/webapp"
      tag        = "latest"
    },
    {
      registry   = "gcr.io"
      repository = "myproject/api"
      tag        = "v2.1.0"
    },
    {
      registry   = "quay.io"
      repository = "prometheus/prometheus"
      # tag is optional - matches all tags if not specified
    }
  ]
}

# Complete cloud security group with multiple cloud providers and images
resource "crowdstrike_cloud_security_group" "complete" {
  name            = "complete-security-group"
  description     = "Complete example with multiple cloud providers and container images"
  business_impact = "moderate"
  business_unit   = "DevOps"
  environment     = "prod"
  owners          = ["devops@company.com", "security@company.com"]

  # AWS production resources
  aws = {
    account_ids = ["123456789012"]
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["Environment=Production", "ManagedBy=Terraform"]
    }
  }

  # Azure production resources
  azure = {
    account_ids = ["12345678-1234-1234-1234-123456789012"]
    filters = {
      region = ["eastus"]
      tags   = ["Environment=Production"]
    }
  }

  # GCP production resources
  gcp = {
    account_ids = ["my-gcp-project-456"]
    filters = {
      region = ["us-central1"]
    }
  }

  # Production container images
  images = [
    {
      registry   = "docker.io"
      repository = "mycompany/backend"
      tag        = "stable"
    },
    {
      registry   = "gcr.io"
      repository = "myproject/frontend"
      tag        = "v1.5.0"
    }
  ]
}

# Minimal cloud security group with only required fields
resource "crowdstrike_cloud_security_group" "minimal" {
  name = "minimal-security-group"
}

output "basic_security_group" {
  value = crowdstrike_cloud_security_group.basic
}

output "complete_security_group" {
  value = crowdstrike_cloud_security_group.complete
}

output "aws_security_group_id" {
  value = crowdstrike_cloud_security_group.aws_resources.id
}
