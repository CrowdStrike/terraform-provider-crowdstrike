# Reference Example: Ideal GitHub Issue Format

This is issue #263 - a well-crafted planning issue that shows the right level of detail.

**What makes this good:**
- Clear HCL examples with multiple realistic scenarios
- Complete schema definition (this IS implementation code - it's the exception)
- High-level checklist with specific notes embedded
- API quirks documented in Notes section (character limits, groups field behavior, detection_json handling)
- No .Wrap() code, no helper functions, no prescriptive implementation details

---

# Add ioa_exclusion resource

Manages IOA (Indicator of Attack) exclusions in CrowdStrike Falcon. IOA exclusions allow you to prevent specific detection patterns from triggering alerts based on command line and image filename regex patterns.

## Example

```hcl
resource "crowdstrike_ioa_exclusion" "example" {
  name        = "Exclude legitimate admin tool"
  description = "Exclude detections for our custom admin tool"
  pattern_id  = "12345"
  pattern_name = "Suspicious PowerShell Activity"

  ifn_regex = "C:\\\\AdminTools\\\\.*\\.exe"
  cl_regex  = ".*-ExecutionPolicy Bypass.*"

  groups = ["a1b2c3d4e5f6"]

  comment = "This tool is used by IT operations and is safe"
}

# Apply exclusion globally to all hosts
resource "crowdstrike_ioa_exclusion" "global_example" {
  name        = "Global exclusion for approved software"
  description = "Exclude detections for company-approved software"
  pattern_id  = "67890"

  ifn_regex = "C:\\\\Program Files\\\\ApprovedApp\\\\.*"
  cl_regex  = ".*"

  groups = ["all"]
}
```

## API Details

**gofalcon package**: `github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions`

**Available operations**:
- `CreateIOAExclusionsV1` - Create IOA exclusion
- `UpdateIOAExclusionsV1` - Update IOA exclusion
- `GetIOAExclusionsV1` - Get IOA exclusions by IDs
- `QueryIOAExclusionsV1` - Query/list IOA exclusion IDs
- `DeleteIOAExclusionsV1` - Delete IOA exclusion

**Models**:
- Request: `models.IoaExclusionsIoaExclusionCreateReqV1` / `models.IoaExclusionsIoaExclusionUpdateReqV1`
- Response: `models.IoaExclusionsIoaExclusionRespV1`

## Resource Schema

**Required attributes**:
- `name` (string) - The name of the IOA exclusion.
- `description` (string) - The description of the IOA exclusion.
- `pattern_id` (string) - The ID of the IOA pattern to exclude.
- `cl_regex` (string) - Command line regex pattern for exclusion matching. Limited to 256 characters.
- `ifn_regex` (string) - Image filename regex pattern for exclusion matching. Limited to 256 characters.
- `groups` (set of strings) - Set of host group IDs to apply this exclusion to. Use `["all"]` to apply globally.

**Optional attributes**:
- `pattern_name` (string) - The name of the IOA pattern. If omitted, appears empty in the Falcon console.
- `comment` (string) - Additional information about the exclusion, such as the reason for creating it.

**Computed attributes** (read-only):
- `id` (string) - The ID of the IOA exclusion.
- `applied_globally` (bool) - Whether the exclusion is applied globally.
- `last_updated` (string) - The timestamp when the exclusion was last updated.

## Schema Implementation

```go
func (r *ioaExclusionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        MarkdownDescription: utils.MarkdownDescription(
            "IOA Exclusions",
            "Manages IOA (Indicator of Attack) exclusions in CrowdStrike Falcon. IOA exclusions allow you to prevent specific detection patterns from triggering alerts based on command line and image filename regex patterns.",
            apiScopesReadWrite,
        ),
        Attributes: map[string]schema.Attribute{
            "id": schema.StringAttribute{
                Computed:    true,
                Description: "The ID of the IOA exclusion.",
                PlanModifiers: []planmodifier.String{
                    stringplanmodifier.UseStateForUnknown(),
                },
            },
            "name": schema.StringAttribute{
                Required:    true,
                Description: "The name of the IOA exclusion.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                },
            },
            "description": schema.StringAttribute{
                Required:    true,
                Description: "The description of the IOA exclusion.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                },
            },
            "pattern_id": schema.StringAttribute{
                Required:    true,
                Description: "The ID of the IOA pattern to exclude.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                },
            },
            "pattern_name": schema.StringAttribute{
                Optional:    true,
                Description: "The name of the IOA pattern. If omitted, appears empty in the Falcon console.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                },
            },
            "cl_regex": schema.StringAttribute{
                Required:    true,
                Description: "Command line regex pattern for exclusion matching. Limited to 256 characters. If longer, it will be truncated and appended with .* by the API.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                    stringvalidator.LengthAtMost(256),
                    // TODO: Implement custom regex validation
                    // validators.ValidRegexPattern(),
                },
            },
            "ifn_regex": schema.StringAttribute{
                Required:    true,
                Description: "Image filename regex pattern for exclusion matching. Limited to 256 characters. If longer, it will be truncated and appended with .* by the API.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                    stringvalidator.LengthAtMost(256),
                    // TODO: Implement custom regex validation
                    // validators.ValidRegexPattern(),
                },
            },
            "groups": schema.SetAttribute{
                ElementType: types.StringType,
                Required:    true,
                Description: "Set of host group IDs to apply this exclusion to. Use `[\"all\"]` to apply globally to all hosts.",
                Validators: []validator.Set{
                    setvalidator.ValueStringsAre(validators.StringNotWhitespace()),
                },
            },
            "comment": schema.StringAttribute{
                Optional:    true,
                Description: "Additional information about the exclusion, such as the reason for creating it.",
                Validators: []validator.String{
                    validators.StringNotWhitespace(),
                },
            },
            "applied_globally": schema.BoolAttribute{
                Computed:    true,
                Description: "Whether the exclusion is applied globally to all hosts.",
                PlanModifiers: []planmodifier.Bool{
                    boolplanmodifier.UseStateForUnknown(),
                },
            },
            "last_updated": schema.StringAttribute{
                Computed:    true,
                Description: "The timestamp when the exclusion was last updated.",
            },
        },
    }
}
```

## Implementation Checklist

**Resource implementation**:
- [ ] Create package directory `internal/ioa_exclusion/`
- [ ] Implement `Schema()` method
- [ ] Implement `Create()` method (pass `nil` for `detection_json` field in API request)
- [ ] Implement `Read()` method
- [ ] Implement `Update()` method (pass `nil` for `detection_json` field in API request)
- [ ] Implement `Delete()` method
- [ ] Implement `ImportState()` method
- [ ] Add `ValidateConfig()` method to validate that if `groups` contains `"all"`, it must be the only element
- [ ] Add `.Wrap()` method to convert API response to Terraform model (handle `groups` field - API returns complex objects but we only store IDs)
- [ ] Register resource in `internal/provider/provider.go`

**Testing and documentation**:
- [ ] Create acceptance tests in `internal/ioa_exclusion/ioa_exclusion_test.go`
- [ ] Create example in `examples/resources/crowdstrike_ioa_exclusion/resource.tf`
- [ ] Create import script in `examples/resources/crowdstrike_ioa_exclusion/import.sh`
- [ ] Run `make gen` to generate documentation

## Required API Scopes

- IOA Exclusions | Read & Write

## Testing Notes

- Use `resource.ParallelTest()` for concurrent execution
- Test full lifecycle: create, read, update, import, destroy
- Test both specific group IDs and `["all"]` for global application
- Test validation logic in `ValidateConfig()` to ensure `"all"` cannot be combined with other group IDs

## Notes

**Character Limit Handling**: The `cl_regex` and `ifn_regex` fields are limited to 256 characters. If a longer value is provided, the API automatically truncates it and appends `.*` to ensure pattern matching works.

**Groups Field**: In API responses, the `groups` field contains complex `HostGroupsHostGroupV1` objects with full details. However, in the Terraform state, we only store the group IDs (strings) for simplicity. The `.Wrap()` method should extract just the IDs from the response objects.

**Detection JSON**: The `detection_json` field in the gofalcon model is marked as required, but the API documentation says it's optional. Pass `nil` for this field in both create and update requests.
