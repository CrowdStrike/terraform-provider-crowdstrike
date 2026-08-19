---
page_title: "crowdstrike_cloud_compliance_framework Data Source - crowdstrike"
subcategory: "Falcon Cloud Security"
description: |-
  This data source provides information about a single compliance framework, built-in or custom, in the CrowdStrike Falcon Platform. Look the framework up by ID, or with an FQL filter that matches exactly one framework, and reference its attributes in other resources.
  API Scopes
  The following API scopes are required:
  Cloud Security Policies | Read
---

# crowdstrike_cloud_compliance_framework (Data Source)

This data source provides information about a single compliance framework, built-in or custom, in the CrowdStrike Falcon Platform. Look the framework up by ID, or with an FQL filter that matches exactly one framework, and reference its attributes in other resources.

## API Scopes

The following API scopes are required:

- Cloud Security Policies | Read


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

# Look up a compliance framework by ID, built-in or custom
data "crowdstrike_cloud_compliance_framework" "by_id" {
  id = "3d67d331d69742f2a3e1e5db2e5f5f0f"
}

# Look up a compliance framework with an FQL filter. The filter must match
# exactly one framework, otherwise the lookup fails.
#
# Only compliance_framework_name, compliance_framework_version, and
# compliance_framework_authority are filterable. The framework ID is not
# filterable at all, so use the id argument above to look a framework up by ID.
#
# The default FQL operator is "equal to", which compares the whole name and is
# case sensitive. Framework names are unique, so name equality is the reliable
# way to resolve a single framework.
data "crowdstrike_cloud_compliance_framework" "by_name" {
  filter = "compliance_framework_name:'PCI DSS Internal'"
}

# Equality does no partial matching, so reach for an operator when you only know
# part of the name. Wildcards need both the operator asterisk after the colon and
# a wildcard asterisk in the value, and they ignore case. Partial matches happily
# cover several frameworks, and matching more than one is an error, so keep the
# pattern narrow.
data "crowdstrike_cloud_compliance_framework" "by_name_prefix" {
  filter = "compliance_framework_name:*'pci dss internal*'"
}

# Reference the data source's attributes elsewhere
output "framework_sections" {
  value = data.crowdstrike_cloud_compliance_framework.by_name.sections
}

output "framework_control_ids" {
  value = flatten([
    for section in values(data.crowdstrike_cloud_compliance_framework.by_name.sections) : [
      for control in values(section.controls) : control.id
    ]
  ])
}
```

## Filtering

Provide either `id` to look a framework up directly, or `filter` to find it with a
[Falcon Query Language (FQL)](https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql)
expression. A filter must resolve to exactly one framework: the data source fails
if it matches none, and fails if it matches more than one. Both forms of lookup
work for built-in frameworks, such as CIS, as well as custom ones.

### Filterable properties

The compliance frameworks query accepts three properties:
`compliance_framework_name`, `compliance_framework_version`, and
`compliance_framework_authority`. Any other property is rejected with a 400 that
lists the three supported ones, so the framework identifier cannot be filtered on
at all. Use the `id` argument to look a framework up by identifier.

`compliance_framework_version` is of little use for a custom framework: every one
is created with version `1.0`, so the property cannot tell two of them apart. It
is useful for distinguishing built-in framework versions, such as different CIS
benchmark releases.

### Matching a framework by name

The default FQL operator is "equal to", and on this property it compares the
whole name and is case sensitive. Framework names are unique, so name equality
resolves to a single framework:

```terraform
filter = "compliance_framework_name:'PCI DSS Internal'"
```

Equality does no partial matching of any kind. Against a framework named
`PCI DSS Internal`, both `compliance_framework_name:'Internal'` and
`compliance_framework_name:'pci dss internal'` match nothing.

For partial matches, use one of these instead:

- Wildcards, which need both an operator asterisk after the colon and at least
  one wildcard asterisk in the value. Wildcard matching ignores case, so
  `compliance_framework_name:*'*pci*'` matches `PCI DSS Internal`.
- `~`, a text match that tokenizes the value and ignores case and punctuation, so
  `compliance_framework_name:~'internal'` matches `PCI DSS Internal`.

```terraform
filter = "compliance_framework_name:*'PCI DSS Internal*'"
```

Both operators can match several frameworks, which is an error for this data
source. Narrow the expression, or look the framework up by `id`. Avoid the
combined `~*` operator: the endpoint answers it with a 500.

Expressions combine with `+` (AND) and `,` (OR), and `!` negates one. A name
containing a single quote has to escape it with a backslash, for example
`compliance_framework_name:'Acme\'s Baseline'`.

### Restricting a filter to custom or built-in frameworks

Add `compliance_framework_authority` to the filter to restrict a lookup to one
kind of framework, for example `compliance_framework_authority:'Custom'` for
custom frameworks only, or `compliance_framework_authority:'CIS'` for the CIS
benchmark. Combine it with the name filter using `+`:

```terraform
filter = "compliance_framework_name:'CIS Amazon Web Services Foundations Benchmark'+compliance_framework_authority:'CIS'"
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `filter` (String) FQL filter used to find the compliance framework. The filter must resolve to exactly one framework: the lookup fails if it matches none or more than one. Exactly one of `id` or `filter` must be provided. The only filterable properties are `compliance_framework_name`, `compliance_framework_version`, and `compliance_framework_authority`. The framework identifier is not a filterable property, so use `id` to look a framework up by identifier. Framework names are unique, so a name equality filter is the reliable way to resolve one framework, for example `compliance_framework_name:'PCI DSS Internal'`; equality matches the whole name and is case sensitive. See the Filtering section above for the operators and the full set of caveats.
- `id` (String) Identifier for the compliance framework. Exactly one of `id` or `filter` must be provided.

### Read-Only

- `description` (String) A description of the compliance framework.
- `name` (String) The name of the compliance framework.
- `sections` (Attributes Map) Map of sections within the framework. Key is an immutable unique string. (see [below for nested schema](#nestedatt--sections))

<a id="nestedatt--sections"></a>
### Nested Schema for `sections`

Read-Only:

- `controls` (Attributes Map) Map of controls within the section. Key is an immutable unique string. (see [below for nested schema](#nestedatt--sections--controls))
- `name` (String) Display name of the compliance framework section.

<a id="nestedatt--sections--controls"></a>
### Nested Schema for `sections.controls`

Read-Only:

- `description` (String) Description of the control.
- `id` (String) Identifier for the compliance framework control.
- `name` (String) Display name of the compliance framework control.
- `rules` (Set of String) Set of rule IDs assigned to this control.
