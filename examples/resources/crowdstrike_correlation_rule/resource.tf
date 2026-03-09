# Manage NGSIEM Correlation Rules using the CrowdStrike provider.
terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Basic correlation rule
resource "crowdstrike_correlation_rule" "basic_rule" {
  name        = "tf-example-basic-rule"
  customer_id = "your-customer-id" # The CID of the environment (tenant ID)
  severity    = 50                 # Medium
  status      = "inactive"         # All examples are set to "inactive" to ensure that accidental deployments don't cause issues.

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }
}

# Correlation rule with description and MITRE ATT&CK mappings
resource "crowdstrike_correlation_rule" "advanced_rule" {
  name        = "tf-example-advanced-rule"
  customer_id = "your-customer-id" # The CID of the environment (tenant ID)
  description = "Detects AWS IAM policy attachments"
  severity    = 70 # High
  status      = "inactive"

  search {
    filter          = "#Vendor=\"aws\" #event.module=\"cloudtrail\" event.provider=\"iam.amazonaws.com\" event.action=\"AttachUserPolicy\""
    lookback        = "1h15m"
    outcome         = "detection"
    trigger_mode    = "summary"
    use_ingest_time = true
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }

  mitre_attack {
    tactic_id    = "TA0004"
    technique_id = "T1098.003"
  }
}

# Correlation rule with notifications
resource "crowdstrike_correlation_rule" "rule_with_notification" {
  name        = "tf-example-rule-with-notification"
  customer_id = "your-customer-id" # The CID of the environment (tenant ID)
  description = "Rule with email notification"
  severity    = 70 # High
  status      = "inactive"

  search {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    outcome      = "detection"
    trigger_mode = "verbose"
  }

  operation {
    schedule {
      definition = "@every 1h0m"
    }
  }

  notification {
    type = "email"
    config {
      cid        = "your-customer-id"
      config_id  = "your-config-id"
      plugin_id  = "your-plugin-id"
      recipients = ["security-team@example.com"]
      severity   = "high"
    }
  }
}

