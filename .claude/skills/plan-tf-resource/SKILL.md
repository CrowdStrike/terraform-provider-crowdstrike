---
name: plan-tf-resource
description: Plan and create a GitHub issue for a new Terraform resource or data source in the CrowdStrike provider
disable-model-invocation: true
allowed-tools: Bash, Read, AskUserQuestion
---

# Plan Terraform Resource/Data Source

Plan and create a GitHub issue for a new Terraform resource or data source in the CrowdStrike provider.

## Process Overview

1. Initial questions → API discovery → Schema design → Issue generation → User review → Create issue

## Phase 1: Initial Questions

### Step 1: Feature Description
Ask the user (text prompt, not AskUserQuestion):
**"What CrowdStrike feature or capability do you want to add to the provider?"**

Wait for the user to provide either:
- An example name (e.g., "response_policy" or "real_time_response_policy")
- A brief description (e.g., "manages real-time response policies that control endpoint response capabilities")

### Step 2: Infer or Ask Resource Type
Based on the user's description:
- If it's clear this is a **resource** (manages/creates/updates something) or **data source** (reads existing data), proceed with that understanding
- If unclear, ask using AskUserQuestion:
  - Is this a **resource** or **data source**?
  - Options: "Resource" or "Data Source"

### Step 3: Package Discovery
Ask the user using AskUserQuestion:
- Do you know the gofalcon package name?

## Phase 2: API Discovery

Use the following commands to learn more about the api:

```bash
# Find relevant packages
go list github.com/crowdstrike/gofalcon/... | grep <keyword>

# Explore package operations
go doc <package>

# View client methods
go doc <package>.Client

# View API models
go doc github.com/crowdstrike/gofalcon/falcon/models.<Model>
```

Document:
- **gofalcon package**: Full package path
- **Available operations**: List CRUD methods with brief descriptions
  - Example: `EntitiesContentPatternCreate` - Create content pattern
- **Models**: Main request/response model names

## Phase 3: Intelligent Schema Design

Use pattern-based heuristics to automatically design the complete schema, then present it to the user for feedback.

### Step 1: Examine API Model Fields

Use `go doc` to view the API model structure and field documentation:

```bash
go doc github.com/crowdstrike/gofalcon/falcon/models.<ModelName>
```

Extract:
- Field names and types
- Field descriptions from gofalcon documentation (if available)
- Any enum values or constraints mentioned

### Step 2: Apply Automatic Field Classification

For each field in the API model, apply these pattern-matching rules:

#### By Field Name Patterns:
- `id` → Computed string with `UseStateForUnknown()` plan modifier
- `last_updated` → Computed string (timestamp)
- `enabled` → Optional bool with `booldefault.StaticBool(false)` default
- `description` → Optional string with `StringNotWhitespace()` validator
- `name` → Required string with `StringNotWhitespace()` validator

#### By Field Type from API:
- Boolean fields → Usually Optional with `booldefault.StaticBool(false)` default
- String ID fields → Usually Optional unless they're discriminators
- Arrays in API → Optional Set or List type in Terraform
- Objects in API → Optional nested Object type in Terraform
- Enums → Add `OneOf()` validator with valid values

#### Automatic Validator Assignment:
- Optional strings → `stringvalidator.NotEmptyOrWhitespace()` or `validators.StringNotWhitespace()`
- Enum fields → `stringvalidator.OneOf(...values from API docs...)`
- Email fields → `validators.StringIsEmailAddress()`
- Collections → `setvalidator.ValueStringsAre(validators.StringNotWhitespace())` for string elements
- Numeric ranges → `int64validator.Between(min, max)` if constraints mentioned in docs

#### Automatic Description Generation:
1. **Primary source**: Use field description from gofalcon `go doc` output if available as a starting point. Reword to be a good description.
2. **Fallback patterns** if gofalcon docs don't provide description:
   - Simple fields: `"The <field_name> of the <resource>."`
   - Enum fields: `"The <field_name> of the <resource>. Valid values: <values>."`
3. Always use MarkdownDescription format with backticks for code values and enums

### Step 3: Present Complete Schema Design

After applying pattern matching to all fields, present the complete schema design:

**Pattern-Based Schema Design:**

I've analyzed the API model and designed the following schema using common patterns:

**Assumptions made:**
- [List key assumptions, e.g., "`enabled` defaults to false", "`name` is required with non-empty validator"]
- [Note any fields where pattern confidence is low]

**Required attributes:**
- `field_name` (type) - Description [Pattern: reason]
- ...

**Optional attributes:**
- `field_name` (type) - Description [Pattern: reason]
- [List default values where applicable]
- ...

**Hardcoded values** (not exposed to users):
- `field_name` = "value" (set internally) [Pattern: reason]
- ...

**Computed attributes** (read-only):
- `field_name` (type) - Description [Pattern: reason]
- ...

**Fields needing verification:**
- `field_name` - [Explain why this field is ambiguous or needs confirmation]
- ...

**Validation requirements** (if applicable):
- Document any feature prerequisites (e.g., "Feature X must be enabled for Feature Y to work")
- Include these dependencies in:
  - Attribute descriptions (e.g., "Required for all X commands")
  - ValidateConfig requirements in the issue
- Use proper display names in validation requirements

Ask: **"I've designed the schema based on common patterns. Does this look correct? What would you like to change?"**

Wait for user feedback. They can:
- Approve the schema as-is
- Request changes to specific fields
- Ask questions about the patterns used

Iterate on feedback until the schema is finalized.

## Phase 4: Additional Information

Ask the user:

1. **"What are the required API scopes?"**
   - Example: "Data Protection | Read & Write"
   - Format: `<Scope Name> | Read & Write` or `<Scope Name> | Read` etc.

2. **"Are there any questions to investigate during implementation?"** (Only if there are genuinely ambiguous scenarios)
   - Only for things that cannot be known until API testing
   - Example: "Platform support - UI shows Windows/Mac but API doesn't accept platform"
   - NOT for schema design decisions already made
   - Skip this question if there are no unknowns

## Phase 5: Issue Generation

Generate a complete GitHub issue with the following structure:

### Title Format
- Resources: `Add <resource_name> resource`
- Data Sources: `Add <data_source_name> data source`

### Body Structure

```markdown
<Brief description of what this resource/data source manages>

## Example

```hcl
<Generate realistic Terraform HCL based on the schema>
```

## API Details

**gofalcon package**: `github.com/crowdstrike/gofalcon/falcon/client/<package>`

**Available operations**:
- Operation1 - Description
- Operation2 - Description
- ...

**Model**: `models.<ModelName>`

## Resource Schema

**Required attributes**:
- `field_name` (type) - Description
- ...

**Optional attributes**:
- `field_name` (type) - Description
- ...

**Hardcoded values** (not exposed to users):
- `field_name` = "value" (set internally)
- ...

**Computed attributes** (read-only):
- `field_name` (type) - Description
- ...

## Schema Implementation


```go
resp.Schema = schema.Schema{
    MarkdownDescription: utils.MarkdownDescription(
        "<Category>",
        "<Description>",
        apiScopesReadWrite,  // Reference the scope variable defined in the package
    ),
    Attributes: map[string]schema.Attribute{
        "id": schema.StringAttribute{
            Computed:    true,
            Description: "The ID of the <resource>.",
            PlanModifiers: []planmodifier.String{
                stringplanmodifier.UseStateForUnknown(),
            },
        },
        <Generate all other attributes with full validators and plan modifiers>
    },
}
```

## Implementation Checklist

**Resource implementation**:
- [ ] Create package directory `internal/<package>/`
- [ ] Implement `Schema()` method
- [ ] Implement `Create()` method
- [ ] Implement `Read()` method
- [ ] Implement `Update()` method
- [ ] Implement `Delete()` method
- [ ] Implement `ImportState()` method
- [ ] Add `ValidateConfig()` method (if validation needed)
- [ ] Add `.Wrap()` method to convert API response to Terraform model
- [ ] Register resource in `internal/provider/provider.go`

**Testing and documentation**:
- [ ] Create acceptance tests in `internal/<package>/<file>_test.go`
- [ ] Create example in `examples/resources/<resource_name>/resource.tf`
- [ ] Create import script in `examples/resources/<resource_name>/import.sh`
- [ ] Run `make gen` to generate documentation

## Required API Scopes

- <Scope Name> | Read & Write

## Testing Notes

- Use `resource.ParallelTest()` for concurrent execution
- Test full lifecycle: create, read, update, import, destroy

## Questions to Resolve During Implementation

<Only include this section if there are actual unknowable questions>

1. Question here

## Notes

<Any API quirks or special handling notes>

Note: <Special handling description if applicable>
```

## Phase 6: User Review and Creation

**CRITICAL**: Show the complete issue title and body to the user.

Say: **"Here's the GitHub issue I've prepared. Please review and let me know if you'd like any changes before I create it."**

Wait for user feedback. They can:
- **Approve**: Proceed to create the issue
- **Request changes**: Update the issue and show again
- **Provide specific edits**: Apply changes and show updated version

After user approval, create the issue using proper heredoc syntax to avoid escaped backticks:

```bash
gh issue create --label "enhancement" --title "title here" --body "$(cat <<'EOF'
body here
EOF
)"
```

Return the issue URL to the user.

## Reference

### Common Validators
- `int64validator.AtLeast(N)` - Minimum value constraint
- `stringvalidator.NotEmptyOrWhitespace()` - No empty/whitespace strings
- `stringvalidator.OneOf("val1", "val2")` - Enum value validation
- Custom validators - Use pseudo-code with TODO comments

### Common Plan Modifiers
- `stringplanmodifier.UseStateForUnknown()` - For computed ID fields
- `stringplanmodifier.RequiresReplace()` - Force resource recreation on change

### Example Custom Validator Pseudo-code
```go
Validators: []validator.String{
    // TODO: Implement custom regex compilation validator
    validators.ValidRegexPattern(),
},
```

## Important Notes

### General Guidelines
- **Never** reference existing resources as implementation examples unless asked
- **Always** explain the assumptions made when presenting the schema design
- **Always** show issue content before creating
- Questions to Resolve section is only for things unknowable until API testing
- All optional strings automatically get `NotEmptyOrWhitespace()` validator
- Use gofalcon documentation as the primary source for field descriptions

### Issue Structure Guidelines
- **Avoid file structure details**: Don't specify specific `.go` file names (schema.go, api.go, errors.go) - let implementer decide file organization
- **Focus on WHAT, not HOW**: Document requirements and what needs to happen, not specific method names or implementation details
- **No prescriptive sections**: Don't include sections like "API Helper Functions" or reference specific method names
- Guide the implementation approach without being overly prescriptive about code organization
