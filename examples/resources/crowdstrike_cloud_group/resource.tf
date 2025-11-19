terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-1"
}

# AWS cloud group with filters
resource "crowdstrike_cloud_group" "aws_production" {
  name            = "Production AWS Resources"
  description     = "Production AWS accounts in us-east-1 and us-west-2"
  business_impact = "high"
  business_unit   = "Engineering"
  environment     = "prod"
  owners          = ["security@example.com", "devops@example.com"]

  aws = {
    account_ids = ["123456789012", "234567890123"]
    filters = {
      region = ["us-east-1", "us-west-2"]
      tags   = ["Environment=Production", "Team=Platform"]
    }
  }
}

# Multi-cloud group
resource "crowdstrike_cloud_group" "multi_cloud_dev" {
  name            = "Development Multi-Cloud"
  description     = "Development resources across AWS, Azure, and GCP"
  business_impact = "moderate"
  environment     = "dev"

  aws = {
    account_ids = ["987654321098"]
    filters = {
      region = ["us-east-1"]
    }
  }

  azure = {
    account_ids = ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
    filters = {
      region = ["eastus"]
      tags   = ["Environment=Dev"]
    }
  }

  gcp = {
    account_ids = ["my-gcp-project-id"]
    filters = {
      region = ["us-central1"]
    }
  }
}

# Container image group
resource "crowdstrike_cloud_group" "container_images" {
  name        = "Production Container Images"
  description = "Production container images from various registries"
  environment = "prod"

  images = [
    {
      registry   = "docker.io"
      repository = "myorg/backend-api"
      tag        = "v1.2.3"
    },
    {
      registry   = "ghcr.io"
      repository = "myorg/frontend"
      tag        = "latest"
    },
    {
      registry   = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
      repository = "internal/worker"
    }
  ]
}

# Azure-only group with minimal configuration
resource "crowdstrike_cloud_group" "azure_simple" {
  name = "Azure Subscriptions"

  azure = {
    account_ids = [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    ]
  }
}

# GCP group (note: GCP does not support tag filtering)
resource "crowdstrike_cloud_group" "gcp_projects" {
  name            = "GCP Projects"
  description     = "All GCP projects for data analytics"
  business_unit   = "Data Analytics"
  business_impact = "moderate"

  gcp = {
    account_ids = ["analytics-project-prod", "analytics-project-staging"]
    filters = {
      region = ["us-central1", "us-east1", "global", "us"]
    }
  }
}

# Multi-cloud group managing all accounts with selective filters
resource "crowdstrike_cloud_group" "all_clouds_filtered" {
  name            = "All Cloud Accounts - Production Only"
  description     = "Access to all accounts across clouds, filtered by production tags"
  business_impact = "high"
  environment     = "prod"

  aws = {
    filters = {
      region = ["us-east-1", "us-west-2", "eu-west-1"]
      tags   = ["Environment=Production", "ManagedBy=Terraform"]
    }
  }

  azure = {
    filters = {
      region = ["eastus", "westus", "westeurope"]
      tags   = ["Environment=Production"]
    }
  }

  gcp = {
    filters = {
      region = ["us-central1", "us-east1", "europe-west1"]
    }
  }
}
