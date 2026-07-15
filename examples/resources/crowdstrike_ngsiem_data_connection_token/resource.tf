terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# PUSH connection (HEC / HTTP Event Connector): no config, exposes an ingest URL.
resource "crowdstrike_ngsiem_data_connection" "hec" {
  name         = "app-hec-ingest"
  connector_id = "a1bfd0c4380f436790cb41afc2b95f38"
  parser       = "aws-elb" # required: supply a valid parser name from the catalog

  enable_host_enrichment = false
  enable_user_enrichment = false
}

# Generate the HEC ingest token for the push connection. The token is returned
# only at generation time and stored in state as sensitive; it cannot be read
# back from the API. Change triggers to regenerate (and invalidate the
# previous token).
resource "crowdstrike_ngsiem_data_connection_token" "hec" {
  connection_id = crowdstrike_ngsiem_data_connection.hec.id

  triggers = {
    rotated_on = "2026-01-01"
  }
}

# The ingest URL is not sensitive and can be output.
output "hec_ingest_url" {
  value = crowdstrike_ngsiem_data_connection_token.hec.ingest_url
}

# The token is sensitive: consume it via a write-only sink (e.g. a secrets
# manager), do not output it in plaintext.
