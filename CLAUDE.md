This is a Terraform provider for managing CrowdStrike Falcon resources, built with the Terraform Plugin Framework and the `gofalcon` library. See CONTRIBUTING.md for architecture, code patterns, and development workflows.

---

## Quick Reference

```bash
make build                  # Build and install provider
make acctest                # Run all acceptance tests
PKG=host_groups make acctest  # Test a specific package
TESTARGS="-run TestAccHostGroupResource" PKG=host_groups make acctest
make test                   # Unit tests only (no TF_ACC)
make fmt                    # Fix formatting and linting
make gen                    # Regenerate docs (never edit docs/ manually)
make lint                   # Run golangci-lint
make fmt-check              # Check formatting without changing files
make sweep                  # Clean up test resources (dev accounts only)
make apply <resource>       # Apply example (e.g., make apply crowdstrike_host_group)
make destroy <resource>     # Destroy example
```

## Environment Variables

Acceptance tests require CrowdStrike API credentials:

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_CLOUD="us-1"  # or us-2, eu-1, us-gov-1
```

## Directory Structure

```
internal/
├── provider/          # Provider registration (add new resources here)
├── framework/         # Shared framework utilities
│   ├── flex/          # Type conversion helpers (API ↔ Terraform)
│   ├── types/         # Custom Terraform types
│   └── validators/    # Custom schema validators
├── tferrors/          # Centralized error handling
├── scopes/            # API scope definitions
├── utils/             # Shared utilities (MarkdownDescription, etc.)
├── <package>/         # Resource packages (may group related resources)
├── sweep/             # Test sweeper definitions
└── testconfig/        # Shared test configuration helpers
```

## Key Rules

- All API calls go through the `gofalcon` library. Never use direct HTTP calls.
- Model structs MUST contain only Terraform types (`types.String`, `types.Bool`, etc.), never Go native types.
- Docs in `/docs` are generated with `make gen`. MUST not manually modify files in `/docs`.

## CONTRIBUTING.md Reference

You MUST read the relevant section(s) of CONTRIBUTING.md before doing the corresponding work.

| When you are...                        | Read CONTRIBUTING.md §                                  |
|----------------------------------------|---------------------------------------------------------|
| Creating a new resource or data source | "Creating a New Resource"                               |
| Writing or modifying CRUD methods      | "Error Handling"                                        |
| Designing a resource schema            | "Resource Schema Patterns", "Validation"                |
| Writing a `.wrap()` method             | "Model Wrapping with .wrap Method"                      |
| Handling optional fields / state drift | "State Consistency with flex and Validators"            |
| Adding schema descriptions             | "Schema Description Formatting"                         |
| Adding logging                         | "Logging with tflog"                                    |
| Writing diagnostics                    | "Single-line Diagnostics with Ellipsis"                 |
| Setting state in Create                | "Early State Updates"                                   |
| Writing or modifying tests             | "Testing"                                               |
| Deciding where to put new files        | "File Structure"                                        |

## Scaffolding New Resources and Data Sources

```bash
go run ./tools/generate resource <name>
go run ./tools/generate resource -d cloud_security kac_policy
go run ./tools/generate datasource <name>
go run ./tools/generate datasource -d cloud_security rules
```
