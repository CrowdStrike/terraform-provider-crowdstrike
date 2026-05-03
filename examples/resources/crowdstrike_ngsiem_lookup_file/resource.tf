terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

variable "assume_unchanged" {
  description = "Skip downloading the file during state refresh. When true, Terraform will not detect out-of-band changes made to the file on the server."
  type        = bool
  default     = false
}

# Read a local CSV file and upload it as a lookup
data "local_file" "network_hosts" {
  filename = "${path.module}/data/network_hosts.csv"
}

resource "crowdstrike_ngsiem_lookup_file" "csv_example" {
  filename         = "network_hosts.csv"
  repository       = "all"
  content          = data.local_file.network_hosts.content
  content_sha256   = data.local_file.network_hosts.content_sha256
  assume_unchanged = var.assume_unchanged
}

# Upload a JSON lookup file using the file() function
resource "crowdstrike_ngsiem_lookup_file" "json_example" {
  filename         = "user_enrichment.json"
  repository       = "investigate_view"
  content          = file("${path.module}/data/user_enrichment.json")
  content_sha256   = filesha256("${path.module}/data/user_enrichment.json")
  assume_unchanged = var.assume_unchanged
}
