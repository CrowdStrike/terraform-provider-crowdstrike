# Test Sweepers

This document describes the test sweeper infrastructure for cleaning up leaked test resources.

## Overview

Sweepers clean up resources that were created during acceptance tests but failed to be destroyed. This can happen when:

- Tests fail before cleanup
- API errors prevent deletion
- Developer interrupts tests
- Partial test runs leave resources behind

## Running Sweepers

### Clean up all test resources

```bash
make sweep
```

### Allow failures and continue

```bash
make sweeper
```

### Run specific sweeper

```bash
TF_ACC=1 go test ./internal/sweep -v -sweep=default -sweep-run=crowdstrike_host_group
```

### Control Log Verbosity

Sweepers use structured logging with configurable log levels. Set the `SWEEP_LOG_LEVEL` environment variable to control output verbosity:

```bash
# Show only warnings and errors (default: INFO)
SWEEP_LOG_LEVEL=WARN make sweep

# Show all logs including trace messages (useful for debugging)
SWEEP_LOG_LEVEL=TRACE make sweep

# Available levels: TRACE, DEBUG, INFO, WARN, ERROR
```

Log levels:
- **TRACE** - Detailed debug information including all skipped resources
- **DEBUG** - Debug information
- **INFO** - General operational information (default)
- **WARN** - Warning messages for non-critical issues
- **ERROR** - Error messages

Example with trace logging:
```bash
SWEEP_LOG_LEVEL=TRACE make sweep
# Output includes: [TRACE] Skipping Prevention Policy production-policy (not a test resource)
```

## Prerequisites

Sweepers require the same environment variables as acceptance tests:

- `FALCON_CLIENT_ID` - CrowdStrike API client ID
- `FALCON_CLIENT_SECRET` - CrowdStrike API client secret
- `FALCON_CLOUD` - (optional) Cloud region

**WARNING:** Sweepers will delete infrastructure. Only run in development/test accounts.

## Test Resource Naming

All test resources MUST use the `sweep.ResourcePrefix` constant (defined as `"tf-acc-test-"` in [internal/sweep/sweep.go](../internal/sweep/sweep.go)) to be identified by sweepers.

Example:
```go
name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix) // "tf-acc-test-abc123"
```

## Registered Sweepers

The following sweepers are currently registered:

- `crowdstrike_host_group` - Host groups
- `crowdstrike_prevention_policy` - Prevention policies (Windows, Linux, Mac)
- `crowdstrike_sensor_update_policy` - Sensor update policies
- `crowdstrike_content_update_policy` - Content update policies (RT Response)
- `crowdstrike_cloud_aws_account` - AWS cloud account registrations
- `crowdstrike_cloud_gcp_account` - GCP cloud account registrations
- `crowdstrike_ioa_rule_group` - Custom IOA rule groups
- `crowdstrike_firewall_rule_group` - Firewall rule groups
- `crowdstrike_sensor_visibility_exclusion` - Sensor visibility exclusions
- `crowdstrike_ml_exclusion` - Machine learning exclusions
- `crowdstrike_data_protection_content_pattern` - Data protection content patterns
- `crowdstrike_cloud_compliance_custom_framework` - Cloud compliance custom frameworks
- `crowdstrike_cloud_group` - Cloud groups
- `crowdstrike_cloud_security_custom_rule` - Cloud security custom rules
- `crowdstrike_cloud_security_kac_policy` - Cloud security KAC policies
- `crowdstrike_it_automation_task` - IT automation tasks
- `crowdstrike_it_automation_task_group` - IT automation task groups
- `crowdstrike_it_automation_policy` - IT automation policies

## Adding New Sweepers

1. Create `sweep.go` in the service package (e.g., `internal/host_groups/sweep.go`)
2. Implement `RegisterSweepers()` function
3. Add sweeper registration to `internal/sweep/sweep_test.go`

Example:

```go
package myservice

import (
    "github.com/hashicorp/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
    sweep.Register("crowdstrike_my_resource", sweepMyResources,
        "crowdstrike_dependency",  // Optional dependencies
    )
}

func sweepMyResources(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
    // Implementation
}
```

## Sweeper Dependencies

Sweepers can declare dependencies to ensure cleanup order:

```go
sweep.Register("crowdstrike_policy_attachment", sweepAttachments)
sweep.Register("crowdstrike_policy", sweepPolicies,
    "crowdstrike_policy_attachment",  // Delete attachments first
)
```

## Architecture

### Core Components

- **`internal/sweep/sweep.go`** - Core interfaces (`Sweepable`), shared client, and orchestration
- **`internal/sweep/register.go`** - Registration helper that wraps sweepers with error handling
- **`internal/sweep/resource.go`** - Resource wrapper for creating sweepable resources
- **`internal/sweep/skip.go`** - Error handling logic for skipping transient failures
- **`internal/sweep/sweep_test.go`** - TestMain entry point and sweeper registration

### Service Sweepers

Each service package can implement a `sweep.go` file that:
1. Defines a `RegisterSweepers()` function
2. Implements sweep functions that list and filter test resources
3. Returns a list of `Sweepable` resources to delete

### Parallel Deletion

The `SweepOrchestrator` uses `hashicorp/go-multierror` to delete resources in parallel while collecting errors. All resources within a sweeper are deleted concurrently unless errors occur.

### Error Handling

Sweepers skip transient errors that shouldn't fail the entire sweep:
- Rate limiting (429)
- Service unavailable (503)
- Timeouts
- Network errors
- Resource not found (404)

## Implementation Details

### Resource Identification

Test resources are identified by the `sweep.ResourcePrefix` constant in their name field:

```go
if !strings.HasPrefix(name, sweep.ResourcePrefix) {
    log.Printf("[INFO] Skipping resource %s (not a test resource)", name)
    continue
}
```

### Delete Function Pattern

Each service implements a delete function:

```go
func deleteResource(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
    params := service.NewDeleteResourceParams()
    params.WithContext(ctx)
    params.Ids = []string{id}

    _, err := client.Service.DeleteResource(params)
    if err != nil {
        if sweep.ShouldIgnoreError(err) {
            sweep.Debug("Ignoring error for resource %s: %s", id, err)
            return nil
        }
        return err
    }

    return nil
}
```

## Troubleshooting

### Sweeper Fails with Rate Limit Error

Rate limit errors are automatically skipped. If you see consistent rate limiting, you can:
- Wait and re-run the sweeper
- Run sweepers for specific resources instead of all at once

### Resources Not Being Swept

Verify that:
1. Resources use the `sweep.ResourcePrefix` constant (accessed via `acctest.ResourcePrefix` in tests)
2. The sweeper is registered in `internal/sweep/sweep_test.go`
3. The list API call is returning the resources

### Sweeper Times Out

Increase the timeout:
```bash
make sweep SWEEP_TIMEOUT=120m
```

## Development

### Running Tests

The sweep infrastructure can be tested by:

1. Creating test resources manually
2. Running the sweeper
3. Verifying resources are deleted

Example:
```bash
# Create a test host group via Terraform
cd examples/resources/crowdstrike_host_group
terraform apply

# Run the sweeper
make sweep

# Verify the resource was deleted
terraform plan  # Should show resource needs to be created
```

### Adding Dependencies

When adding a new sweeper, consider if other resources must be deleted first:
- Attachments before policies
- Policies before the resources they protect
- Child resources before parent resources

Declare dependencies in the `Register()` call:
```go
sweep.Register("crowdstrike_child", sweepChildren)
sweep.Register("crowdstrike_parent", sweepParents,
    "crowdstrike_child",  // Delete children first
)
```
