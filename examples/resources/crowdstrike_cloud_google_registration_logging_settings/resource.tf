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

resource "crowdstrike_cloud_google_registration" "registration" {
  name          = "my-google-cloud-project-registration"
  projects      = ["my-google-cloud-project-id"]
  infra_project = "my-infra-project-id"
  wif_project   = "my-wif-project-id"

  realtime_visibility = {
    enabled = true
  }
}

resource "crowdstrike_cloud_google_registration_logging_settings" "example" {
  registration_id                 = crowdstrike_cloud_google_registration.registration.id
  log_ingestion_sink_name         = "crowdstrike-log-sink"
  log_ingestion_topic_id          = "crowdstrike-log-topic"
  log_ingestion_subscription_name = "crowdstrike-log-subscription"

  depends_on = [crowdstrike_cloud_google_registration.registration]
}

output "log_ingestion_settings" {
  value = crowdstrike_cloud_google_registration_logging_settings.example
}
