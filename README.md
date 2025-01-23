# Terraform CrowdStrike Provider

The CrowdStrike provider enables terraform to manage CrowdStrike resources.
 
- [docs](./docs/) - Documentation for each resource.
- [examples](./examples/) - Examples of each resource.
- [issues](https://github.com/crowdstrike/terraform-provider-crowdstrike/issues) - Report issues or request the next set of resources.

### Support

Refer to our support documentation [here](./SUPPORT.md).

### CrowdStrike API Access
The provider uses the CrowdStrike Falcon API to manage resources. In order to use the provider, you must have a CrowdStrike API client ID and client secret.

The following scopes are required to create and manage all the resources the provider currently supports:

> [!NOTE]
> See a resource's documentation for the specific scopes required for that resource.

| Scope                   | Permission      |
|-------------------------|-----------------|
| Device Control Policies | *READ*, *WRITE* |
| Prevention Policies     | *READ*, *WRITE* |
| Response Policies       | *READ*, *WRITE* |
| Firewall Management     | *READ*, *WRITE* |
| Host Groups             | *READ*, *WRITE* |
| Sensor Update Policies  | *READ*, *WRITE* |
| Falcon FileVantage      | *READ*, *WRITE* |

### Importing Existing CrowdStrike resources

The CrowdStrike provider supports importing existing resources into terraform state. This is useful for managing resources that were created outside of terraform. Refer to the [importing guide](./docs/importing.md) for an example of using the `import` block and the `terraform import` command.
