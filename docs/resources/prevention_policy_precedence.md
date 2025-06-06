---
page_title: "crowdstrike_prevention_policy_precedence Resource - crowdstrike"
subcategory: "Prevention Policy"
description: |-
  This resource allows you set the precedence of Prevention Policies based on the order of IDs.
  API Scopes
  The following API scopes are required:
  Prevention policies | Read & Write
---

# crowdstrike_prevention_policy_precedence (Resource)

This resource allows you set the precedence of Prevention Policies based on the order of IDs.

## API Scopes

The following API scopes are required:

- Prevention policies | Read & Write


## Example Usage

```terraform
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


resource "crowdstrike_prevention_policy_precedence" "example" {
  ids = [
    "a1j09y3yq0wnrpb5o6jlij9e4f40k6lq",
    "2asia54xti93bg0jbr5hfpqqbhxbyeoa",
    "xuzq8hs1uyc2s7zdar3fli0shiyl22vc",
  ]
  platform_name = "linux"
  enforcement   = "dynamic"
}

output "prevention_policy_precedence" {
  value = crowdstrike_prevention_policy_precedence.example
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `enforcement` (String) The enforcement type for this resource. `strict` requires all non-default prevention policy ids for platform to be provided. `dynamic` will ensure the provided policies have precedence over others. When using dynamic, policy ids not included in `ids` will retain their current ordering after the managed ids.
- `ids` (List of String) The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.
- `platform_name` (String) That platform of the prevention policies. (Windows, Mac, Linux)

### Read-Only

- `last_updated` (String) Timestamp of the last Terraform update of the resource.
