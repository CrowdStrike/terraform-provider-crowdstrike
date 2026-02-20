resource "crowdstrike_ioa_rule_group" "linux_monitoring" {
  name        = "Linux Security Monitoring"
  platform    = "Linux"
  description = "Custom IOA rules for monitoring suspicious Linux activity"
  comment     = "Managed by Security Operations team"
  enabled     = true

  rules = [
    {
      name             = "Suspicious Network Connection"
      description      = "Monitors for suspicious outbound network connections"
      comment          = "Alert on connections to known malicious IPs"
      pattern_severity = "critical"
      type             = "Network Connection"
      action           = "Monitor"
      enabled          = true

      image_filename = {
        include = ".*suspicious.*"
        exclude = ".*legitimate.*"
      }

      command_line = {
        include = ".*malicious.*"
        exclude = ".*safe.*"
      }

      remote_ip_address = {
        include = ".*"
      }

      connection_type = ["TCP", "UDP"]
    },
    {
      name             = "Unauthorized Process Creation"
      description      = "Detects unauthorized process creation"
      comment          = "Kill unauthorized processes immediately"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Kill Process"
      enabled          = true

      parent_image_filename = {
        include = ".*/bin/bash"
      }

      image_filename = {
        include = ".*/tmp/.*"
      }

      command_line = {
        include = ".*"
      }
    }
  ]
}
