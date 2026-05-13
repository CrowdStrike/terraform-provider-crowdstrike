terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {}

# Resolve the Customer ID (CID) for the tenant authenticated by the provider.
data "crowdstrike_cid" "this" {}

resource "crowdstrike_correlation_rule" "basic_rule" {
  name     = "tf-example-basic-rule"
  cid      = data.crowdstrike_cid.this.cid
  severity = "medium"
  status   = "inactive"

  search = {
    filter       = "#repo=\"base_sensor\" #event_simpleName=ProcessRollup2"
    lookback     = "1h0m"
    trigger_mode = "verbose"
  }

  schedule = {
    interval = "1h0m"
    start_on = "2030-01-01T00:00:00Z"
  }

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["oncall@example.com"]
    },
  ]
}

resource "crowdstrike_correlation_rule" "advanced_rule" {
  name        = "tf-example-advanced-rule"
  cid         = data.crowdstrike_cid.this.cid
  description = "Detects AWS IAM policy attachments"
  severity    = "high"
  status      = "inactive"

  search = {
    filter          = "#Vendor=\"aws\" #event.module=\"cloudtrail\" event.provider=\"iam.amazonaws.com\" event.action=\"AttachUserPolicy\""
    lookback        = "1h15m"
    create_case     = true
    trigger_mode    = "summary"
    use_ingest_time = true
  }

  schedule = {
    interval = "1h0m"
    start_on = "2030-01-01T00:00:00Z"
  }

  mitre_attack = [
    {
      tactic_id    = "TA0004"
      technique_id = "T1098.003"
    },
  ]

  notifications = [
    {
      type         = "email"
      is_guardrail = true
      recipients   = ["oncall@example.com"]
    },
  ]
}
