# testgen

`testgen` generates acceptance tests from resource schemas. It reads each registered resource's schema at runtime, applies one rule per test type, and writes the test file and its Terraform config. Authors supply attribute values only when the generator cannot derive them.

For day-to-day usage, see "Generated Acceptance Tests" in CONTRIBUTING.md. This file covers design decisions, current status, and remaining work.

## Goal

AI-written tests kept missing cases or adding things they should not. Rules written into skills were not followed reliably. The generator enforces those rules mechanically, so nobody (human or AI) writes test configs by hand.

Generated tests assert the schema's desired-state contract. If a generated test fails because the API behaves differently from what the schema promises, the test found a bug. The generator has no knobs for API quirks.

## How it works

```
internal/<pkg>/
├── testgen.go                         # opt-in and values (//go:build testgen), hand-written
├── <resource>_resource_test.go        # hand-written tests, optional
├── <resource>_resource_gen_test.go    # generated, DO NOT EDIT
└── testdata/<resource>/main.tf        # generated, DO NOT EDIT

internal/testgen/   # library imported by testgen.go files: Register, Resource, Attribute
tools/testgen/      # the generator program
```

`make gen` runs it through `//go:generate go run -tags testgen ./tools/testgen` in `main.go`. CI's existing `make gen` plus `git diff` check catches stale output.

### Pipeline

1. **Load.** Call `provider.New("test")().Resources()`, then `Metadata` and `Schema` on each. Keep only resources registered through `testgen.Register`. Reading schemas at runtime keeps validators and plan modifiers, which `terraform providers schema -json` drops.
2. **Model** (`model.go`). Convert each attribute to its type, Required/Optional/Computed flags, Default, facts parsed from validators (OneOf values, size and length bounds, NoneOf exclusions), RequiresReplace, and whether the resource supports import.
3. **Values** (`values.go`). Use the spec's pool if one exists. Otherwise use heuristics: the sweeper attribute (`SweepAttribute`, default `name`) gets the random prefixed test name and an `-updated` variant; OneOf gets the listed values; other strings get stable placeholders (`testgen <path> 1`, `2`, and `3` for collections); bool gets true/false; numbers get range bounds that skip excluded values. If no heuristic applies, generation fails and names the attribute and the `testgen.go` file to edit. Placeholders are not checked against validators the generator does not parse; provider validation of every generated step rejects them, and the error points at `testgen.go`. Placeholders the API rejects fail the acceptance test, and the fix is the same: supply `Values`.
4. **Rules** (`rules.go`). Turn the model into test cases: a name, steps with config variables, state checks, and plan checks.
5. **Validate** (`validate.go`). Run every generated step config through the provider's own `ValidateResourceConfig` RPC. That applies attribute validators, `ConfigValidators`, and imperative `ValidateConfig`, exactly like `terraform validate`, with no API call and no configured provider.
6. **Overrides** (`resources.go`). Parse the package's hand-written `_test.go` files with `go/parser` and drop generated cases whose function name already exists (case-insensitive).
7. **Render** (`render.go`). Write `main.tf` with `hclwrite` and the Go file with `go/format`.
8. **Cleanup.** Delete files carrying the generator's header that this run did not produce. Files without the header are never touched.

## Decisions

| Topic                          | Decision                                                                                                                                               | Why                                                                                                                                                                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Opt-in                         | A resource opts in by calling `testgen.Register` in `internal/<pkg>/testgen.go`. One file per package; it can register several resources.              | Gradual adoption, one resource per PR. The same file holds values, so there is no second list to keep in sync.                                                                                                                                                 |
| Spec file location             | A regular `.go` file behind `//go:build testgen`, not `_test.go`.                                                                                      | Go cannot import `_test.go` files from another package. The build tag keeps specs out of the provider binary. The generator imports `internal/provider`, which already imports every resource package, so each `init()` registers itself with no extra wiring. |
| What authors supply            | Values only. No hand-written HCL or templates.                                                                                                         | Templates (the AWS approach) let AI make the same mistakes again, and a template per test type gets out of hand. A value written once feeds every test type.                                                                                                   |
| Generation vs. runtime builder | Code generation.                                                                                                                                       | Readable tests and reviewable diffs; failures point into the test, not a helper.                                                                                                                                                                               |
| Generated Go                   | One `<resource>_resource_gen_test.go` per resource with header `// Code generated by testgen. DO NOT EDIT.`                                            | Standard Go header; golangci-lint skips it; `.gitattributes` marks it `linguist-generated`.                                                                                                                                                                    |
| Generated HCL                  | One `testdata/<resource>/main.tf` per resource. Every settable attribute is a variable defaulting to `null`; each step only changes `ConfigVariables`. | A `null` variable is the same as omitting the attribute, so one file covers every test and every step (DP policy went from 50 `.tf` files to 1 with identical results).                                                                                        |
| Overrides                      | A hand-written test with the same function name wins.                                                                                                  | No config to keep in sync. Existing hand-written tests shadow generated ones until deleted. A missed match fails to compile as a duplicate function.                                                                                                           |
| Known generator gaps           | `Skip: {"<suffix>": "reason"}` emits a test that calls `t.Skip(reason)`.                                                                               | The gap stays visible in test output and greppable. Never use Skip to hide a resource bug.                                                                                                                                                                     |
| Import verify                  | `ImportIgnore` spec field.                                                                                                                             | `last_updated` is only set in Create and Update, so import cannot match it.                                                                                                                                                                                    |
| Singletons                     | `Serial: true` uses `resource.Test` instead of `resource.ParallelTest`.                                                                                | Default policies are one shared remote object.                                                                                                                                                                                                                 |
| Disappears                     | `_disappears` passes Delete every top-level primitive attribute from state, converted to its schema type. `NoDisappears: true` opts out.               | AWS copies only root strings, which leaves bools null: a policy Delete that disables first when `enabled` is true would skip the disable and fail. Few resources, such as default policies, have a Delete that leaves the remote object.                       |
| Generator bugs                 | Unit tests with golden files in `tools/testgen/testdata/golden`, run by `make test`.                                                                   | Catches rule regressions in seconds, without credentials.                                                                                                                                                                                                      |

### Test contract

- **Omit means removed.** Terraform manages the resource end to end.
- **List reorder** is an update, and state must match the new order.
- **Set reorder** must produce an empty plan.
- **`[]` is valid** only if there is no `SizeAtLeast(1)` validator.

| Attribute                       | Omit step expects                                       |
| ------------------------------- | ------------------------------------------------------- |
| Optional                        | `null`                                                  |
| Optional + Default              | the default value                                       |
| Optional + Computed, no Default | no omit step; the schema allows keeping the prior value |
| Required                        | no omit step                                            |

If the provider's own validation rejects an omit step, the step is dropped and a comment on the generated test explains why.

## Test types

- **`_basic`.** Required attributes only (plus `Base`). Asserts `knownvalue.NotNull()` on every Computed-only attribute. Adds an import step if the resource implements `ResourceWithImportState`. Does not assert Required values, since Terraform already fails with "inconsistent result after apply" and import verify catches a Read that does not populate them. No update or replace steps.
- **`_disappears`.** Applies the `_basic` config, then the `acctest.ResourceDisappears` state check deletes the resource outside Terraform, and the refreshed plan must be a create. The generated test passes the resource's constructor, such as `hostgroups.NewHostGroupResource`. The helper (`internal/acctest/disappears.go`) builds the resource, configures it with the shared provider data from `acctest.PreCheck`, and calls its `Delete` with the resource's full state decoded from Terraform's JSON state against the resource schema. Generated for every resource unless `NoDisappears` is set.
- **Per attribute (`_<camelName>`).** The `_basic` config plus one attribute (and its `Requires` and `Set`).
  - Primitives: set value 1, update to value 2 (plan expects `DestroyBeforeCreate` if RequiresReplace, otherwise `Update`), omit per the table above, then import. Enums step through every OneOf value.
  - Lists and sets: create `[a, b]`, add `[a, b, c]`, reorder, remove a middle element, `[]` when allowed, then omit. Size validators cap and shape the steps.
  - Nested objects: pools of objects built from the nested schema. Optional children of single nested objects get their own tests (for example `_rapidResponseDelayHours`).

## Spec fields

Defined in `internal/testgen/testgen.go`.

- `SweepAttribute`: the string attribute sweepers match on, set to the random prefixed test name. Defaults to `name`.
- `Attributes[name].Values`: pool of values when the generated ones are not valid (for example a regex, or a URL glob the API checks). Collections need at least two values; three enable every lifecycle step. Nested paths use dots.
- `Attributes[name].Requires`: other attributes that must be present in this attribute's test. Each keeps its `Base` value, or takes its first value from its `Values` or the generated values.
- `Attributes[name].Set`: specific values for other attributes in this attribute's test, for example `minimum_similarity_threshold` sets `similarity_detection = true`. `nil` unsets a `Base` attribute.
- `Base`: attributes set in every config, for resources where no Required-only config validates (host group's `type` makes a different attribute required).
- `NoDisappears`: leaves out `_disappears` for resources whose Delete does not remove the remote object, such as default policies.
- `Skip`, `ImportIgnore`, `Serial`: see Decisions.

## Status

Phases 0 through 3, 5, and 6 are implemented. Phase 4 (references) is deferred.

| Phase | Scope                                                                                                  | State                                                                                     |
| ----- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| 0     | Spikes: ConfigDirectory with provider factories, build tags in tooling, test naming, validator parsing | Done                                                                                      |
| 1     | `_basic`                                                                                               | Done                                                                                      |
| 2     | Per-attribute primitives, enums, RequiresReplace                                                       | Done                                                                                      |
| 3     | Lists and sets of literal values                                                                       | Done                                                                                      |
| 4     | References to other resources (`_hostGroups`)                                                          | Deferred                                                                                  |
| 5     | Nested attributes                                                                                      | Done for single nested children; whole elements only for list/set nested                  |
| 6     | Singletons (`Serial`)                                                                                  | Done for default policies; precedence, attachment, and settings resources wait on Phase 4 |

Registered resources: `cid_group`, `response_policy`, `data_protection_content_pattern`, `data_protection_policy`, `host_group`, `content_update_policy`, `default_content_update_policy`.

### Acceptance results

| Resources                                                          | Pass | Skip | Fail |
| ------------------------------------------------------------------ | ---- | ---- | ---- |
| cid_group, response_policy, content_pattern, host_group, DP policy | 71   | 6    | 4    |
| content_update_policy and default (serial)                         | 0    | 9    | 21   |

Every failure is a provider bug the tests found. None are fixed or hidden behind Skip:

1. **Content update policies (all 21).** Every apply, update, and omit step passes, but import returns `delay_hours = 0` where Create left it `null`.
2. **DP policy on Mac.** Apply fails with "inconsistent result" because the API returns `evidence_storage` and related fields that were not configured.
3. **DP policy `be_paste_clipboard_max_size`.** The schema allows up to 65536, but the API applies that limit in bytes after unit conversion and rejects 67108864.
4. **DP policy unit change.** Switching `be_paste_clipboard_max_size_unit` to `Bytes` sends `0.06` to the API.
5. **DP policy `max_file_size_unit = "MB"`.** It can never pass validation: the minimum of 512 MB exceeds the 500 MiB cap. MB is left out of that test's values.
6. **Content pattern `_disappears`.** The API soft-deletes: after DELETE, GET still returns the pattern with `deleted: true` and a name ending in `(deleted on <timestamp>)`. Read ignores `deleted`, so the refresh plans an update instead of a create, and the post-test destroy gets a 500.

## Known limitations

- **Plan modifier and validator detection** reads unexported struct fields by reflection, and tells `RequiresReplace` from `RequiresReplaceIf` by the symbol name of its closure. A library upgrade that renames a field returns an error; one that renames the closure is caught by the unit tests. `RequiresReplaceIf` logic is not evaluated, so plan actions on those attributes are not asserted.
- **Environment-dependent values** (`cid_group.cids`, pinned content versions) are Skip entries. There is no way yet to source values from environment variables.
- **Linked values** (such as `custom_ioc` where `value` depends on `type`) have no spec support yet.
- **Map attributes** are skipped with a reason.
- **List/set lifecycle steps** are fixed index patterns sized for pools of 2 or 3 elements (`lifecycle` in `rules.go`). A `minSize` above 1 drops steps instead of producing a sequence that respects the bounds.
- **List/set nested objects** are tested as whole elements; their children do not get their own tests.
- **Editors.** gopls needs `-tags=testgen` in `buildFlags` to analyze `testgen.go` files. golangci-lint has the tag configured in `.golangci.yml`.

## Next

1. Decide whether to fix the six provider bugs above on this branch.
2. Phase 4, references: create dependency resources (for example host groups) alongside the resource under test and compare IDs with `statecheck.CompareValuePairs`. First spike whether indexed addresses like `crowdstrike_host_group.dep[2]` work in state checks.
3. Precedence, attachment, and settings resources, which need Phase 4.
4. Environment-sourced values, linked value sets, map attributes, and per-child tests for list/set nested objects.
5. Move imperative `ValidateConfig` rules to declarative validators (`ExactlyOneOf`, `AtLeastOneOf`) where possible, so the model can read them instead of relying only on the validation RPC.
6. Opt in more resources and delete the hand-written tests the generated ones replace.
7. Render the Go test file with `text/template` and `golang.org/x/tools/imports` instead of string building and hand-tracked imports, and build `main.tf` with the `hclwrite` builder API instead of `Fprintf`.
8. Update the `terraform-provider-testing` skill (it lives in a plugin, not this repo) so AI edits `testgen.go` instead of writing tests.
