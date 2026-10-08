variable "rule_group_name" {
  type = string
}

# Keys of the rules to configure on crowdstrike_ioa_rule_group.imported, in
# order. Each key is also the rule's ID in local.rules.
variable "imported_rules" {
  type = list(string)
}

# The same rules a, b, and c as in ../rule_group.
locals {
  rules = {
    a = {
      name             = "rule-a"
      description      = "rule-a description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*rule-a.*" }
      command_line     = { include = ".*" }
    }
    b = {
      name             = "rule-b"
      description      = "rule-b description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*rule-b.*" }
      command_line     = { include = ".*" }
    }
    c = {
      name             = "rule-c"
      description      = "rule-c description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*rule-c.*" }
      command_line     = { include = ".*" }
    }
  }
}

resource "crowdstrike_ioa_rule_group" "test" {
  name     = var.rule_group_name
  platform = "Mac"
  enabled  = true

  rules = [local.rules.a, local.rules.b, local.rules.c]
}

import {
  to = crowdstrike_ioa_rule_group.imported
  id = crowdstrike_ioa_rule_group.test.id
}

resource "crowdstrike_ioa_rule_group" "imported" {
  name     = var.rule_group_name
  platform = "Mac"
  enabled  = true

  rules = [for key in var.imported_rules : merge(local.rules[key], { local_key = key })]
}
