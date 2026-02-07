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

### Step 1: Initial Information Gathering
Present this question as text output (do not use AskUserQuestion tool):

**"What CrowdStrike feature or capability do you want to add to the provider? If you know the gofalcon package name, please include it."**

Wait for the user to provide:
- Feature name or description (e.g., "response_policy" or "manages real-time response policies")
- Optionally: gofalcon package name (e.g., "response_policies")

### Step 2: Infer or Ask Resource Type
Based on the user's description:
- If it's clear this is a **resource** (manages/creates/updates something) or **data source** (reads existing data), proceed with that understanding
- If unclear, ask using AskUserQuestion:
  - Is this a **resource** or **data source**?
  - Options: "Resource" or "Data Source"

## Phase 1.5: Package Validation/Discovery

**Always perform package validation or discovery**, regardless of whether the user provided a package name.

### Scenario A: User Provided Package Name

If the user provided a gofalcon package name in Phase 1, validate it:

1. **Verify package exists**:
```bash
go doc github.com/crowdstrike/gofalcon/falcon/client/<package>
```

2. **Check for required CRUD operations**:
Look for methods matching these patterns (at least Create and Get should exist):
- Create operations: `*Create*`, `*Post*`
- Read operations: `*Get*`, `*Query*`
- Update operations: `*Update*`, `*Patch*`
- Delete operations: `*Delete*`

3. **If validation fails** (package doesn't exist or lacks critical operations):
- Inform the user: "The package `<package>` doesn't exist or lacks required CRUD operations."
- Proceed to Scenario B (discovery)

4. **If validation passes**:
- Proceed to Phase 2 (API Discovery)

### Scenario B: User Did NOT Provide Package Name OR Validation Failed

Help discover the correct package:

1. **Search for relevant packages** using keywords from the feature description:
```bash
go list github.com/crowdstrike/gofalcon/... | grep <keyword>
```

2. **Show results** to the user with brief package descriptions (if available)

3. **Ask user to choose** the correct package or provide additional search terms

4. **Once package is identified**, validate it using Scenario A steps

5. **After successful validation**, proceed to Phase 2 (API Discovery)

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

**Note**: In this phase, present the schema design and questions as regular text output and wait for user responses. Do not use the AskUserQuestion tool.

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
   - Enum fields: `"The <field_name> of the <resource>. One of: <values>."`
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

Present the schema and say:

**"I've designed the schema based on common patterns. Does this look correct? What would you like to change?"**

**STOP and wait for user response.**

### Iteration Process:

1. **User provides feedback** - They can:
   - Approve the schema as-is (e.g., "looks good", "proceed", "that's correct") → Proceed to Phase 4
   - Request changes to specific fields → Continue to step 2
   - Ask questions about the patterns used → Clarify and continue to step 2

2. **Apply requested changes** to the schema

3. **Present the updated schema** (showing what changed)

4. **Ask again**: **"Does this look correct now? Any other changes?"**

5. **Repeat steps 1-4** until the user explicitly approves the schema

6. **Only after user approval**, proceed to Phase 4 (Additional Information)

## Phase 4: Additional Information

Ask the user:

1. **"What are the required API scopes?"** (ONLY if not already established during API discovery)
   - If API scopes were already identified, skip this question
   - Example: "Data Protection | Read & Write"
   - Format: `<Scope Name> | Read & Write` or `<Scope Name> | Read` etc.

2. **"Are there any questions to investigate during implementation?"** (Only if there are genuinely ambiguous scenarios)
   - Only for things that cannot be known until API testing
   - Example: "Platform support - UI shows Windows/Mac but API doesn't accept platform"
   - NOT for schema design decisions already made
   - Skip this question if there are no unknowns

## Phase 5: Issue Generation

## CRITICAL: What NOT to Include in GitHub Issues

GitHub issues are planning documents, NOT implementation guides. DO NOT include:

- ❌ Code for `.Wrap()` method - No conversion logic
- ❌ Code for CRUD methods (`.Create()`, `.Read()`, `.Update()`, `.Delete()`)
- ❌ References to other resources as implementation examples
- ❌ Helper function code or patterns
- ❌ API client call examples or error handling code
- ❌ Sections like "API Helper Functions" or "Error Handling Implementation"

DO include:

- ✅ Complete schema definition (with validators and plan modifiers) - This is critical
- ✅ Realistic HCL examples showing how users will use the resource
- ✅ WHAT needs to be done (checklist of tasks)
- ✅ API caveats discovered during planning (character limits, field transformations, special behaviors)
- ✅ High-level notes about special handling requirements

**The schema definition IS implementation code and should be complete. Everything else should be guidance, not code.**

### Reference Format

Before generating the issue, review `examples/ioa-exclusion-issue.md` to understand the expected format and level of detail.

**Key characteristics:**
- Realistic HCL example (single scenario preferred, multiple only if fundamentally different usage patterns)
- Complete schema Go code (validators, plan modifiers) without imports or package declaration
- High-level checklist (what to do, not how)
- Notes section for API quirks and discoveries
- NO .Wrap() code, NO helper functions, NO method implementations

### Issue Structure

Generate a complete GitHub issue with the following structure:

### Title Format
- Resources: `Add <resource_name> resource`
- Data Sources: `Add <data_source_name> data source`

### Body Structure

```markdown
<Brief description (1-2 sentences) of what this resource/data source manages>

## Example

```hcl
<Generate a realistic, complete Terraform HCL example showing how users will use this resource>
<Include inline comments only where they add clarity about non-obvious usage>
<Only include multiple scenarios if there are fundamentally different ways to use the resource (e.g., specific vs global configurations)>
```

## API Details

**gofalcon package**: `github.com/crowdstrike/gofalcon/falcon/client/<package>`

**Available operations**:
- OperationName - Brief description
- OperationName - Brief description
- ...

**Models**:
- Request: `models.<RequestModel>`
- Response: `models.<ResponseModel>`

## Resource Schema

**Required attributes**:
- `field_name` (type) - Description
- ...

**Optional attributes**:
- `field_name` (type) - Description
- ...

**Computed attributes** (read-only):
- `field_name` (type) - Description
- ...

## Schema Implementation

```go
func (r *<resource>Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        MarkdownDescription: utils.MarkdownDescription(
            "<Category>",
            "<Description>",
            apiScopesReadWrite,
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
}
```

## Implementation Checklist

Note: Checklist items and sub-bullets are high-level by default. Add indented sub-bullets under ANY item to document special handling requirements discovered during planning (e.g., "Pass `nil` for field X", "Validate Y cannot be combined with Z"). Do NOT include implementation code.

**Resource implementation**:
- [ ] Create package directory `internal/<package>/`
- [ ] Implement `Schema()` method
- [ ] Implement `Create()` method
- [ ] Implement `Read()` method
- [ ] Implement `Update()` method
- [ ] Implement `Delete()` method
- [ ] Implement `ImportState()` method
- [ ] Add `ValidateConfig()` method
- [ ] Add `.Wrap()` method to convert API response to Terraform model
- [ ] Register resource in `internal/provider/provider.go`

**Testing and documentation**:
- [ ] Create acceptance tests in `internal/<package>/<file>_test.go`
- [ ] Create example in `examples/resources/<resource_name>/resource.tf`
- [ ] Create import script in `examples/resources/<resource_name>/import.sh`
- [ ] Run `make gen` to generate documentation

## Required API Scopes

- <Scope Name> | <Permissions>

## Testing Notes

- Use `resource.ParallelTest()` for concurrent execution
- Test full lifecycle: create, read, update, import, destroy
<Add specific test scenarios if applicable>

## Notes

<Only include this section if there are API quirks, caveats, or special cases discovered during planning>

**<Quirk Category>**: <Description of the quirk and how it should be handled>

<Add additional notes as needed>
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

### Issue Philosophy
- Issues define WHAT needs to be built, not HOW to build it 
- The implementer already knows provider patterns - don't tell them how to code
- Focus on the unique aspects of THIS resource (schema, API quirks, special cases)
- The schema is the contract - make it complete and correct

### What Makes a Good Issue
- **Schema first**: The schema definition is the most important part - it sets up everything
- **Document discoveries**: Note any API quirks found during planning (limits, transformations, unexpected behaviors)
- **High-level checklist**: List what needs to be done, let implementer decide how
- **No code examples**: Except the schema - everything else is prescriptive

### Common Mistakes to Avoid
- Showing how to implement `.Wrap()` - implementer knows this pattern
- Referencing other resources - don't create dependencies on understanding other code
- Including helper function pseudo-code - not needed in planning document
- Being too specific about file organization - let implementer structure the package

### General Guidelines
- **Never** reference existing resources as implementation examples
- **Always** explain the assumptions made when presenting the schema design
- **Always** show issue content before creating
- Use gofalcon documentation as the primary source for field descriptions
