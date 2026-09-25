# Fusion SOAR workflow API: findings for a `crowdstrike_fusion_workflow` resource

Tracks GitHub issue #324. Everything below was verified by calling the live API (us-2 dev tenant, default `FALCON_CLIENT_ID`) on 2026-09-25 unless marked "docs only". Sample payloads live next to this file in `samples/`.

Sources:
- Live API probes (curl). The helper used is `samples/fapi.sh`; it keeps the OAuth token in a shell variable and never writes it to disk.
- CrowdStrike docs page "Fusion SOAR Workflow APIs" (falcon-docs MCP document id `z028de1a`, sections "Export and import a workflow definition", "Update a workflow definition", endpoint reference, "Workflow definition FQL filters").
- gofalcon `falcon/client/workflows` and `falcon/models`.

## Endpoint summary

All endpoints require scope `Workflow: Write` (write) or `Workflow: Read` (read). The resource declares `Workflow` Read & Write.

| Purpose | Call | gofalcon method | Works via gofalcon as generated? |
|---|---|---|---|
| Create | `POST /workflows/entities/definitions/v1` (flat YAML or JSON, undocumented) | none | No method; needs a custom ClientOperation |
| Create (documented) | `POST /workflows/entities/definitions/import/v1` (multipart `data_file`, YAML) | `WorkflowDefinitionsImport` | Yes |
| Read (JSON) | `GET /workflows/combined/definitions/v1?filter=id:'<id>'` | `WorkflowDefinitionsCombined` | **No** for real workflows. The generated model types `trigger.parameters` as a string, but the API returns an object, so decoding fails with `cannot unmarshal object into ... trigger.parameters of type string`. The provider uses a Reader override that decodes only `id`, `name`, `enabled` and `has_validation_errors` |
| Read (YAML) | `GET /workflows/entities/definitions/export/v1?id=<id>&sanitize=false` | `WorkflowDefinitionsExport` | Only with a `ProducesMediaTypes` override; the default Accept header gets a 406. The 299 status is modeled (`WorkflowDefinitionsExportStatus299`) |
| Update | `PUT /workflows/entities/definitions/v1` | `WorkflowDefinitionsUpdate` | **No.** See "Update" |
| Enable / disable | `POST /workflows/entities/definition-actions/v1?action_name=enable\|disable`, body `{"ids":[...]}` | `WorkflowDefinitionsAction` | Yes |
| Delete | `DELETE /workflows/entities/definitions/v1?ids=<id>` (repeatable `ids`) | `WorkflowDefinitionsDelete` | Yes |

## Create (undocumented POST, not used)

The resource doesn't use this endpoint, because CONTRIBUTING.md forbids undocumented endpoints. It's recorded here for reference. It was found by sending a POST to the path that already serves PUT and DELETE. It appears in none of these:
- the docs pages "Fusion SOAR Workflow APIs" (`z028de1a`) and Fusion SOAR "Reference" (`vc76f3e9`)
- gofalcon's `specs/swagger.json`, `swagger.previous.json` or `swagger-patched.json`, which list only `PUT` (`WorkflowDefinitionsUpdate`) and `DELETE` (`WorkflowDefinitionsDelete`) for this path

`POST /workflows/entities/definitions/v1` isn't in the docs or in gofalcon, but it works. It takes the same flat body that PUT accepts, with no `id`: either YAML (`Content-Type: application/yaml`) or flat JSON. Using it would need a custom ClientOperation in `internal/clientoverrides`.

- On success it returns 200 with `resources: ["<id>"]`, a list of strings. Import's response uses objects instead.
- **Unlike import, POST honors `enabled`.** A valid flat JSON body with `enabled: true` created the workflow already enabled, at version 1 with `has_validation_errors: false`.
- **Validation is loose when the workflow isn't enabled.** Two bodies whose action was missing `version_constraint` were saved anyway, with `has_validation_errors: true`, and the response was 200 with nothing in `errors`. An invalid body *with* `enabled: true` returned 200 with `errors: [{"code": 2018, "message": "Action was not found, please select a new action.", "id": "<action key>"}]` and created nothing. So the provider must check `errors` even on a 200, and should check `has_validation_errors` after Create.
- A duplicate name returns 409 `"A workflow by this name already exists. Try a new name."`, and the error entry includes the `id` of the existing workflow.
- If `version_constraint` is omitted, it defaults to `~0`. That matters: PUT rejected a body without it with 404 `activity not found ... constraint "~0"`. Configs should always set `version_constraint`.

## Create (import)

- The body is `multipart/form-data` with the YAML in a `data_file` field. Query parameters: `name` (overrides the YAML name), `validate_only` and `include_activity_metadata`.
- On success it returns 200 with `resources[0].id`, a 32-hex definition ID.
- **Every imported workflow starts `enabled: false` at `version: 1`.** To enable it, Create has to call the `enable` action afterwards.
- `validate_only=true` returns 200 with `resources: [{"parameters": null}]` and saves nothing. This could back a plan-time `ValidateConfig` check, but it needs an API call.
- Names must be unique per CID. A duplicate returns **409** `"A workflow by this name already exists. Try a new name."`
- Malformed YAML returns 400 `"import file must be a valid YAML file"`.
- **Import accepts semantically invalid definitions.** A definition with a nonexistent activity ID imported with 200 and was stored with `has_validation_errors: true`. `validate_only=true` also returned 200 for it. So after an import, Create must check `has_validation_errors` in the combined response. To get the actual error message, send a `validate_only=true` PUT with the same definition plus the new `id`; it returns 404 `activity not found for id: "<id>" constraint "~1"`.
- Enabling a workflow that has validation errors fails with the same 404 `activity not found ...` message.
- Import restrictions (docs only): no third-party plugin or Falcon Foundry actions; no CID-specific event queries from another CID; required subscriptions and Store plugins must exist in the target CID.

## Update (PUT)

This is where the docs and gofalcon both mislead.

| Body sent | Result |
|---|---|
| Flat YAML, `Content-Type: application/yaml`, top-level `id:` plus the definition keys (the docs' example) | **200.** Updated in place, same ID, version +1 |
| Flat YAML, `Content-Type: application/x-yaml` | **415 Unsupported Media Type.** This matters because `application/x-yaml` is the only YAML producer registered in the go-openapi runtime (`runtime.YAMLMime`), so gofalcon can't send a YAML body |
| Flat JSON, `Content-Type: application/json`, same shape as the YAML (`{"id": ..., "name": ..., "trigger": ..., "actions": ...}`) | **200.** Updated in place |
| JSON wrapper `{"id", "enabled", "change_log", "Definition": {...}}` (the docs' parameter table and gofalcon's `ModelsDefinitionUpdateRequestV2`) | **500 Internal Server Error**, even with `nodeRegistry`, `uniqNodeSeen` and `parent` filled in as `{}` |

Consequences:
- `WorkflowDefinitionsUpdate` cannot be used as generated. The provider overrides `Params` so the body is the user's YAML converted to a flat JSON object with the top-level `id` injected, sent as `application/json`.
- **PUT replaces the definition; it doesn't merge.** A PUT without `description` removed the description.
- **PUT always validates strictly**, whether or not the workflow is enabled. An invalid activity ID returned 404 `activity not found ...` from both `validate_only=true` and a real PUT, and the stored workflow was left unchanged.
- `id` is required in the body. Omitting it returns 400 `"invalid ID"`.
- A PUT on a nonexistent ID returns 404 `"definition not found for id: <id>"`.
- **The server ignores `enabled` in the PUT body.** I sent `enabled: false` in a flat JSON body to an enabled workflow; it stayed enabled. Only the action endpoint changes the enabled state.
- **A PUT keeps the current enabled state.** A PUT to an enabled workflow left it enabled.
- **Changing `name` through PUT renames in place.** Same ID, no replacement needed.
- **Every PUT bumps `version`, even when nothing changed.** Re-PUTting the exported YAML took the version from 6 to 7. Update should only PUT when the definition actually differs, and a plan shouldn't show a diff when nothing semantic changed.
- Malformed YAML on PUT returns 400 with the parser error, for example `"yaml: line 1: did not find expected ',' or ']'"`.

## Read

Two options.

**Combined (JSON).** `GET /workflows/combined/definitions/v1?filter=id:'<id>'`. Each resource has the definition keys (`name`, `description`, `trigger`, `actions`, ...) inline, plus the metadata `id`, `enabled`, `has_validation_errors`, `last_modified_timestamp` and `version`. If the workflow is gone, it returns 200 with `total: 0`, and **not** a 404. Treat an empty result as not-found.

**Export (YAML).** `GET .../export/v1?id=<id>&sanitize=false`:
- **The Accept header must be exactly `application/yaml`.** gofalcon's generated operation sends both `application/json` and `application/yaml` as separate Accept values, and the server answers **406 Not Acceptable**. Override `ProducesMediaTypes` to `["application/yaml"]`. gofalcon's download-aware consumer then streams the raw YAML into the `io.Writer` passed to `WorkflowDefinitionsExport`.
- Exports of workflows with custom trigger or action configuration (for example Inline.Python) return **HTTP 299** with header `X-Api-Warning: exported workflow contains custom trigger or action config`. Other exports, such as a workflow that only uses the built-in Sleep action, return 200. Treat both as success.
- A missing ID returns 404 `"definition with id <id> not found"`.
- **`sanitize` defaults to true and strips PII.** It turned `to: [placeholder@crowdstrike.com]` into `to: []` (compare `samples/export_b_raw.yaml` and `samples/export_b_sanitized.yaml`). The provider must always send `sanitize=false`.
- The export has **no top-level `id`**, so it can't be PUT back until `id` is added. With `id` added, re-PUTting an export succeeds.
- `version=<n>` exports a historical version. Old versions are retained; I exported version 1 after several updates. `version=0` (the draft) returned 404 for an API-created workflow.
- Exports aren't available for workflows created from Falcon Foundry templates (docs only).

### Normalization the server applies (drift risk)

Comparing `samples/a.yaml` (what I imported) with `samples/export_a.yaml`, and `samples/b.yaml` with `samples/export_b_raw.yaml`:
- It adds the header comment `# This is an exported workflow. Editing this file is not recommended.`
- It re-indents to 4 spaces.
- It uses a fixed top-level key order (`name`, `description`, `trigger`, `actions`, ...) and **sorts keys alphabetically inside nested maps** (`properties`, `parameters`).
- **It adds keys the user didn't write.** Every action gets `default_name`, and actions without a `name` get `name` (the activity's display name, for example `Send email`).
- The combined JSON shows the same additions.

- **It silently drops keys it doesn't recognize**, at the top level (`bogus_top_level`) and inside actions (`bogus_action_key`). The import still returns 200.

So a raw string compare of config against export always shows a diff. The resource handles this with semantic equality in `internal/fusion_workflow/definition.go`: the API's copy counts as equal when it contains every configured value. Keys only the API sets are ignored, and a dropped or changed configured key is reported with its path. This is the same problem described in the `reference-opaque-json-terraform-contract` memory, solved with its "configured keys only" workaround.

## Documented import restrictions, tested against import, POST and PUT

The docs say import doesn't work for third-party plugin actions, Falcon Foundry actions, or CID-specific event queries from another CID. I tested whether the undocumented POST or PUT handles those cases better. Only the us-2 default credentials have the Workflow scope; `_PARENT`, `_CHILD1`, `_US_1`, `_TALON1`, `_EU_1`, `_DODO_RED` and `_DODO_BLACK` all return 403 "scope not permitted". So the cross-CID cases were simulated with activity IDs that don't exist in this CID.

In the table, "saved" means the call returned 200 with a new ID, but the stored workflow has `has_validation_errors: true` and can't be enabled.

| Case | Import | Undocumented POST | PUT |
|---|---|---|---|
| Foundry app action, app installed (`601add...~29c85b...`, `plugin.custom_integration`, copied from the tenant's "estoner GTI" workflow) | 200, **valid**, enable succeeded | not tested | 200, valid |
| Foundry app action, app not installed (fake app ID `fff...~29c85b...`) | Saved | Saved | **404** `activity not found ...` |
| Store plugin, installed but not configured (Send Slack message `1afdf9...`, placeholder `config_id`) | Saved; enable returned 200 with errors 2035 and 2016 | Saved | 200, saved with validation errors |
| CID-specific event query from another CID (the `<cid>_<id>_<id>` ID format with a different CID prefix) | Saved; enable returned 404 `activity not found` | Saved | **404** `activity not found ...` |
| CID-specific event query from this CID (`e82676...`, `logscale.search_result`) | Saved; its only error was 2016 for a property I omitted (`execution_id`) | Saved | 200 |

Conclusions:
- No endpoint makes a restricted case work. Import and POST behave identically: they save a workflow that can't be enabled. PUT is stricter and rejects missing activities outright.
- The undocumented POST has no advantage over import here, so the resource uses import.
- A workflow that uses a Foundry app action exports fine (still 299). The docs' "exports are not available" note applies to workflows created *from* Foundry workflow templates, which I didn't test.
- The restrictions are really "the referenced activity or plugin configuration must exist in the target CID." Within one CID, Foundry and plugin actions work once they're installed and configured.

## Enable / disable

- **The enable action can return HTTP 200 with errors in the payload.** Enabling a workflow that uses an unconfigured Slack plugin returned 200 with `errors: [{"code": 2035, "message": "missing required plugin configuration for 'Send Slack message'"}, {"code": 2016, "message": "A value is required for the property \"_fields\""}]`, and the workflow stayed disabled. An unknown activity returns a 404 instead. The provider must check payload errors on this call.
- Call `POST /workflows/entities/definition-actions/v1?action_name=enable` with body `{"ids":["<id>"]}`. It returns 200 with empty `errors` and `resources`. After enabling, the version went from 2 to 3, so the action also bumps the version.
- `action_name=cancel` cancels in-flight executions (docs only). It isn't relevant to the resource.
- Because import always creates the workflow disabled and PUT ignores `enabled`, an `enabled` attribute has to be applied through this endpoint on both Create and Update.

## Delete

- Call `DELETE ?ids=<id>` (repeat `ids` to delete several). It returns 200 with `resources: [<ids>]`.
- An enabled workflow deletes fine without being disabled first.
- Deleting an ID that's already gone returns 404 `"definition with id <id> not found"`. Treat that as success.

## Listing and lookups

- **FQL name matching:** `filter=name:'exact name'` returned `total: 0` even for a name that exists; `filter=name:~'partial'` works. The docs' own example uses `~`. An import-by-name or data source would need `~` and then an exact match on the client side.
- Other filters that work: `id:'<id>'` and `enabled:true`. The docs also list `trigger.type`, `activity_id`, `version` and more.
- **Activity lookup:** `GET /workflows/combined/activities/v1?filter=name:~'send email'`. There are 6,284 activities in the tenant, so always filter. An action's `id` in the YAML is the activity ID (for example `Send email` is `07413ef9ba7c47bf5a242799f59902cc`, and Create Python script / `Inline.Python` is `7fb9eb10b23943efaf1e6082b0ac0338`).

## Minimal working definition

`samples/a.yaml` is the smallest definition that imported cleanly: an on-demand trigger with one inline Python action. The acceptance tests use the built-in Sleep action (`4f1af1ae4c13dc1e3bcd725f8dc0f63b`) instead, with `properties: {sleep_time: 1m}` and `version_constraint: ~1`, because it needs no subscription or plugin. Without `sleep_time`, enable fails with 2016 `A value is required for the property "sleep_time"`. A trigger with no actions is saved but invalid: enable fails with 2019 `At least one action or valid loop should be defined after the trigger` and 2017 `Workflow/Loop cannot end with a trigger`. You don't need `nodeRegistry`, `uniqNodeSeen` or `parent`, even though gofalcon's `V2Definition` marks them required. `samples/b.yaml` adds trigger input `parameters` and a Send email action.

## Implementation (`internal/fusion_workflow`)

The resource `crowdstrike_fusion_workflow` has three attributes:
- `definition` (required YAML string, custom type `definitionType`)
- `enabled` (optional, computed, defaults to `false`)
- `id` (computed)

**Files:**
- `fusion_workflow_resource.go`: CRUD, plus the read, update and enable helpers.
- `definition.go`: the custom type, YAML parsing, validation, the subset comparison (`definitionDiff`), exact comparison (`definitionsEqual`), and the JSON update body.
- `overrides.go`: the three gofalcon overrides (update body, export Accept header, combined reader).
- `sweep.go`: the sweeper.

**CRUD:**
- **Create:** import the YAML, then set `id` in state immediately. If `enabled` is set, call the `enable` action. Then read back.
- **Read:** combined for `enabled`, then export (`sanitize=false`) for `definition`. An empty combined result or a 404 on export removes the resource from state.
- **Update:**
  - The PUT is skipped when the configured and stored definitions are structurally identical, meaning only formatting differs. Every PUT creates a new version.
  - After a successful PUT, `definition` is written to state before the enabled state is changed. If the enable or disable call then fails, the new definition is still recorded.
- **Delete:** a 404 counts as success.

**After every write** (the shared `refresh` helper):
- The export is compared with the configuration. A configured key the API dropped fails the apply, naming the key's path.
- A workflow saved with validation errors produces a warning. The detail comes from a `validate_only` PUT when the API returns one.

**Gotchas found while implementing:**
- **Semantic equality direction.** The framework calls `StringSemanticEquals` on the *new* value (the API's copy), with the *prior* value (plan or state) as the argument (`internal/fwschemadata/value_semantic_equality_string.go:37` in terraform-plugin-framework v1.17.0). The framework docs' RFC 3339 example reads as if it were the other way round. A subset comparison written the wrong way round fails every create with "Provider produced inconsistent result after apply".
- **Update response state.** The framework pre-populates `resp.State` in Update with the **prior** state (`fwserver/server_updateresource.go:105`), not the plan as the `UpdateResponse` doc comment says. On an early error return, anything already applied must be written to state explicitly.
- **Update 404s.** A PUT that references an unknown activity returns a typed 404 (`WorkflowDefinitionsUpdateNotFound`). `tferrors.NewDiagnosticFromAPIError` turns that into "Resource Not Found", so the update helper reports the payload errors instead.
- **Import plan.** Import fills `definition` from the export, and plan-time diffs don't use semantic equality. So the first plan after import is an in-place update of `definition`. The import test uses `ImportBlockWithID` with `ExpectNonEmptyPlan` and a plan check asserting that the imported definition contains every configured value.
- **yaml.v3 mapping keys.** yaml.v3 decodes a mapping with any non-string key as `map[any]any`. `parseDefinition` converts every mapping to string keys, matching `encoding/json` output.

## Not yet verified

- How Flight Control `flight_control` targeting behaves on PUT for parent and child CIDs.
- Scheduled triggers and Signal (event) triggers. Only On demand was tested here; an existing Signal workflow in the tenant exports fine.
- Whether `include_activity_metadata` on import changes what gets stored.
- A true cross-CID import. No second tenant with the Workflow scope was available, so it was simulated; see "Documented import restrictions".
- Workflows created from Falcon Foundry workflow templates.
