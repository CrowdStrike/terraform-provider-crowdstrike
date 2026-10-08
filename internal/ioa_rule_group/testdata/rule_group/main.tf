variable "rule_group_name" {
  type = string
}

# IDs of the rules in local.rules to configure, in order. When empty, the rule
# group has no rules attribute.
variable "rules" {
  type    = list(string)
  default = []
}

# Key of each configured rule, by rule ID. A rule without an entry has no key.
variable "keys" {
  type    = map(string)
  default = {}
}

# IDs of the configured rules whose key is unknown at plan time. Each key
# resolves to the rule's entry in keys, or to null when it has none.
variable "unknown_keys" {
  type    = list(string)
  default = []
}

# Changing unknown replaces terraform_data.unknown, so its output, and every
# rule value taken from it, is unknown at plan time and resolves during apply.
# Changing its input, such as the keys resolved for unknown_keys, has the same
# effect.
variable "unknown" {
  type    = bool
  default = false
}

# Makes the whole rules list unknown at plan time. Set together with unknown.
variable "unknown_rules" {
  type    = bool
  default = false
}

resource "terraform_data" "unknown" {
  triggers_replace = var.unknown

  input = {
    b_name = local.base_rules.b.name
    b_type = local.base_rules.b.type
    keys   = { for id in var.unknown_keys : id => lookup(var.keys, id, null) }
  }
}

locals {
  base_rules = {
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
    n = {
      name             = "rule-n"
      description      = "rule-n description"
      pattern_severity = "high"
      type             = "Process Creation"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*rule-n.*" }
      command_line     = { include = ".*" }
    }
    d = {
      name             = "rule-d"
      description      = "rule-d description"
      pattern_severity = "high"
      type             = "Domain Name"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*" }
      domain_name      = { include = ".*rule-d\\.example\\.com.*" }
    }
  }

  rules = merge(local.base_rules, {
    # Edits of the rules above.
    a_renamed = merge(local.base_rules.a, { name = "rule-a-renamed" })
    b_edited  = merge(local.base_rules.b, { description = "rule-b edited" })
    b_domain = {
      name             = "rule-b"
      description      = "rule-b description"
      pattern_severity = "high"
      type             = "Domain Name"
      action           = "Detect"
      enabled          = true
      image_filename   = { include = ".*" }
      domain_name      = { include = ".*rule-b\\.example\\.com.*" }
    }

    # Rules with a value from terraform_data.unknown, which resolves to the
    # value shown in its input.
    b_unknown_name = merge(local.base_rules.b, { name = terraform_data.unknown.output.b_name })
    b_unknown_type = merge(local.base_rules.b, { type = terraform_data.unknown.output.b_type })
  })

  configured_rules = [
    for id in var.rules : merge(local.rules[id], {
      local_key = contains(var.unknown_keys, id) ? terraform_data.unknown.output.keys[id] : lookup(var.keys, id, null)
    })
  ]
}

resource "crowdstrike_ioa_rule_group" "test" {
  name     = var.rule_group_name
  platform = "Mac"
  enabled  = true

  rules = (
    length(var.rules) == 0 ? null :
    var.unknown_rules ? [for rule in local.configured_rules : rule if terraform_data.unknown.output != null] :
    local.configured_rules
  )
}
