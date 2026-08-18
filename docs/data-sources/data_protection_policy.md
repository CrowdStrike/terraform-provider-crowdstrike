---
page_title: "crowdstrike_data_protection_policy Data Source - crowdstrike"
subcategory: "Data Protection"
description: |-
  This data source provides information about a single Falcon Data Protection policy.
  API Scopes
  The following API scopes are required:
  Data Protection | Read & Write
---

# crowdstrike_data_protection_policy (Data Source)

This data source provides information about a single Falcon Data Protection policy.

## API Scopes

The following API scopes are required:

- Data Protection | Read & Write


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

# Look up a policy by its identifier. platform_name is not used here.
data "crowdstrike_data_protection_policy" "by_id" {
  id = "00112233445566778899aabbccddeeff"
}

# Look up a policy with an FQL filter. platform_name scopes the search, and the
# text match operator matches the whole policy name.
data "crowdstrike_data_protection_policy" "by_name" {
  filter        = "name:~'Payroll Data Policy'"
  platform_name = "Windows"
}

# Filters are not limited to name.
data "crowdstrike_data_protection_policy" "default_windows" {
  filter        = "is_default:true"
  platform_name = "Windows"
}

output "payroll_policy_classifications" {
  value = data.crowdstrike_data_protection_policy.by_name.classifications
}
```

## Filtering

Provide `id` to look a policy up by its identifier, or `filter` to find it with a
Falcon Query Language (FQL) expression. A filter must resolve to exactly one
policy: the data source fails if it matches none, and fails if it matches more
than one.

`platform_name` is required alongside `filter`, because the search API searches a
single platform at a time. It must not be set alongside `id`, which the API
resolves without a platform.

For the FQL syntax itself, the operators, and how to escape a value in a Terraform
string, see the
[Filtering with Falcon Query Language](https://registry.terraform.io/providers/crowdstrike/crowdstrike/latest/docs/guides/falcon-query-language)
guide. This page covers what is specific to data protection policies.

### Filterable properties

| Property | Matches |
| --- | --- |
| `name` | The policy name. See [Matching a policy name](#matching-a-policy-name). |
| `description` | The policy description. |
| `is_enabled` | Whether the policy is enabled. |
| `is_default` | Whether the policy is the platform's default policy. |
| `precedence` | The policy's position in the precedence order. |
| `created_at` | When the policy was created. |
| `created_by` | Who created the policy. |
| `modified_at` | When the policy was last modified. |
| `modified_by` | Who last modified the policy. |

Individual policy settings are filterable under `properties.`. These use the
field names of the underlying API rather than this data source's attribute names,
so `max_file_size` is filtered as `properties.max_file_size_to_inspect`:

- **Inspection**: `properties.enable_context_inspection`,
  `properties.enable_content_inspection`,
  `properties.enable_clipboard_inspection`, `properties.inspection_depth`,
  `properties.min_confidence_level`, `properties.similarity_detection`,
  `properties.similarity_threshold`, `properties.max_file_size_to_inspect`,
  `properties.max_file_size_to_inspect_unit`, `properties.classifications`
- **Browser extension**: `properties.be_exclude_domains`,
  `properties.besplash_enabled`, `properties.besplash_custom_message`,
  `properties.besplash_message_source`,
  `properties.be_upload_timeout_duration_seconds`,
  `properties.be_upload_timeout_response`,
  `properties.be_paste_timeout_duration_milliseconds`,
  `properties.be_paste_timeout_response`,
  `properties.be_paste_clipboard_min_size`,
  `properties.be_paste_clipboard_min_size_unit`,
  `properties.be_paste_clipboard_max_size`,
  `properties.be_paste_clipboard_max_size_unit`,
  `properties.be_paste_clipboard_over_size_behaviour_block`
- **Unsupported browsers**: `properties.browsers_without_active_extension`,
  `properties.block_all_data_access`,
  `properties.enable_end_user_notifications_unsupported_browser`
- **Notifications and justification**: `properties.allow_notifications`,
  `properties.block_notifications`, `properties.custom_allow_notification`,
  `properties.custom_block_notification`, `properties.euj_dialog_timeout`
- **Screen capture and evidence**: `properties.enable_screen_capture`,
  `properties.screen_capture_duration_pre_event`,
  `properties.screen_capture_duration_post_event`,
  `properties.evidence_storage_max_size`,
  `properties.evidence_storage_free_disk_perc`,
  `properties.evidence_encrypted_enabled`,
  `properties.evidence_download_enabled`,
  `properties.evidence_duplication_enabled_default`
- **Network**: `properties.enable_network_inspection`,
  `properties.network_inspection_files_exceeding_size_limit`

### Matching a policy name

This endpoint matches `name` as a set of whole words rather than as one string.
Use the text match operator `~` with the full name, which ignores case,
punctuation, and word order:

```terraform
filter = "name:~'Payroll Data Policy'"
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `filter` (String) An FQL filter that resolves to exactly one data protection policy: the lookup fails if it matches none or more than one. Requires `platform_name`. Exactly one of `id` or `filter` must be provided. See the [Filtering with Falcon Query Language](https://registry.terraform.io/providers/crowdstrike/crowdstrike/latest/docs/guides/falcon-query-language) guide for the syntax, and the Filtering section of this page for the properties data protection policies can be filtered on and the caveats that apply to them.
- `id` (String) Unique identifier of the policy. Set this to look the policy up directly by identifier, which does not require `platform_name`. Exactly one of `id` or `filter` must be provided.
- `platform_name` (String) Platform the policy applies to. Accepts `Windows` or `Mac`. Required when using `filter`, because the search API only searches one platform at a time. Must not be set when using `id`, which the API resolves without a platform.

### Read-Only

- `be_custom_splash_message` (String) Custom text for the browser extension splash dialog.
- `be_exclude_domains` (Set of String) Domain patterns excluded from visibility and enforcement by the Falcon browser extension.
- `be_paste_clipboard_block_over_max_size` (Boolean) When `true`, pastes exceeding `be_paste_clipboard_max_size` are blocked regardless of content.
- `be_paste_clipboard_max_size` (Number) Maximum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_max_size_unit`.
- `be_paste_clipboard_max_size_unit` (String) Unit for `be_paste_clipboard_max_size`.
- `be_paste_clipboard_min_size` (Number) Minimum clipboard payload size evaluated on paste, expressed in `be_paste_clipboard_min_size_unit`.
- `be_paste_clipboard_min_size_unit` (String) Unit for `be_paste_clipboard_min_size`.
- `be_paste_timeout_milliseconds` (Number) How long the browser extension waits for a response when pasting data before timing out, in milliseconds.
- `be_paste_timeout_response` (String) Extension behavior when a paste evaluation times out.
- `be_splash_screen` (Boolean) Whether the browser extension shows a splash screen while a file is being evaluated.
- `be_upload_timeout_response` (String) Extension behavior when an upload evaluation times out.
- `be_upload_timeout_seconds` (Number) How long the browser extension waits for a response when uploading data before timing out, in seconds.
- `block_all_data_access` (Boolean) **Windows only.** Blocks all data access via Firefox and Internet Explorer.
- `browsers_without_active_extension` (String) **Windows only.** How browsers without an active Falcon extension handle data uploads.
- `cid` (String) Customer ID that owns the policy.
- `classifications` (Set of String) Classification IDs assigned to this policy.
- `clipboard_inspection` (Boolean) Detects egress when classified data is pasted from the clipboard in supported browsers.
- `clipboard_web_origin` (Boolean) Tracks and attributes web sources for clipboard content copied from web applications.
- `content_inspection` (Boolean) Inspects egressing data against the content patterns used by this policy's classifications.
- `context_inspection` (Boolean) Gives insight into data sources, assigned sensitivity labels, and file types, for data in motion and at rest.
- `created_at` (String) Timestamp when the policy was created.
- `created_by` (String) Identity that created the policy.
- `custom_allowed_action_notification` (String) Custom text shown to end users when a rule allows an action.
- `custom_blocked_action_notification` (String) Custom text shown to end users when a rule blocks an action.
- `description` (String) Description of the policy.
- `enable_ocr` (Boolean) **Mac only.** Extracts and classifies sensitive text from image files such as screenshots and photos during data egress.
- `enabled` (Boolean) Whether the policy is enabled.
- `end_user_encryption_activity` (Boolean) **Windows only.** When data encryption occurs, stores a copy of the original data in a protected folder on the host.
- `euj_business_purposes_enabled` (Boolean) Whether the built-in `Business purposes` option is offered in the end user justification dialog.
- `euj_company_logo` (String) Company logo shown in the end user justification dialog, as a base64 PNG data URI.
- `euj_custom_dropdown_options` (List of String) Custom justification options offered in the end user justification dialog.
- `euj_custom_header_text` (String) Custom header text for the end user justification dialog.
- `euj_dialog_timeout` (Number) Timeout for the end user justification dialog, in seconds.
- `euj_personal_use_enabled` (Boolean) Whether the built-in `Personal use` option is offered in the end user justification dialog.
- `euj_require_additional_details` (Boolean) When `true`, the end user must fill in the additional details box to proceed with a justification.
- `evidence_storage` (Boolean) **Windows only.** Allows users with the Data Protection Forensics Manager role to request and download files for egress events.
- `evidence_storage_max_free_space_percent` (Number) **Windows only.** Maximum percentage of free disk space evidence storage may consume.
- `evidence_storage_max_size_gib` (Number) **Windows only.** Maximum disk space in GiB that evidence storage may use on a host.
- `host_groups` (Set of String) Host group IDs assigned to this policy.
- `inspection_confidence` (String) Minimum confidence level for reporting content matches.
- `inspection_depth` (String) Inspection depth for data in motion.
- `is_default` (Boolean) Whether this is the platform's default policy.
- `max_file_size` (Number) Largest file the sensor inspects for classified content, expressed in `max_file_size_unit`.
- `max_file_size_unit` (String) Unit for `max_file_size`.
- `minimum_similarity_threshold` (String) Minimum percentage of similar content required for an egress event to be monitored.
- `name` (String) Name of the policy.
- `network_inspection` (Boolean) **Windows only.** Detects egress of classified data via network traffic.
- `network_inspection_files_exceeding_size_limit` (String) **Windows only.** How network inspection handles file uploads larger than its 1 MiB ceiling.
- `precedence` (Number) Position of the policy in its platform's precedence order.
- `screen_capture` (Boolean) **Windows only.** Captures the screen before and after an egress event.
- `screen_capture_post_event_seconds` (String) **Windows only.** Seconds of screen recording retained after a trigger event.
- `screen_capture_pre_event_seconds` (String) **Windows only.** Seconds of screen recording retained before a trigger event.
- `similarity_detection` (Boolean) Detects egress of files containing content copied from other classified files on the same endpoint.
