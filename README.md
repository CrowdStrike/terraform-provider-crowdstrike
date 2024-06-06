# Terraform CrowdStrike Provider

The CrowdStrike provider enables terraform to manage CrowdStrike resources.
 
- [docs](./docs/) - Documentation for each resource.
- [examples](./examples/) - Examples of each resource.
- [issues](https://github.com/crowdstrike/terraform-provider-crowdstrike/issues) - Report issues or request the next set of resources.

The CrowdStrike terraform provider is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

### CrowdStrike API Access
The provider uses the CrowdStrike Falcon API to manage resources. In order to use the provider, you must have a CrowdStrike API client ID and client secret.

The following scopes are required to create and manage all the resources the provider currently supports:
| Scope                   | Permission      |
|-------------------------|-----------------|
| Device Control Policies | *READ*, *WRITE* |
| Prevention Policies     | *READ*, *WRITE* |
| Response Policies       | *READ*, *WRITE* |
| Firewall Management     | *READ*, *WRITE* |
| Host Groups             | *READ*, *WRITE* |
| Sensor Update Policies  | *READ*, *WRITE* |
| Falcon FileVantage      | *READ*, *WRITE* |


