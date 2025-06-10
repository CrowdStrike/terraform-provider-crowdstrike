# Terraform CrowdStrike Provider

The CrowdStrike provider enables terraform to manage CrowdStrike resources.
 
- [docs](./docs/) - Documentation for each resource.
- [examples](./examples/) - Examples of each resource.
- [issues](https://github.com/crowdstrike/terraform-provider-crowdstrike/issues) - Report issues or request the next set of resources.

### Support

Terraform CrowdStrike Provider is a community-driven, open source project designed to streamline deploying and managing resources in the CrowdStrike console. While not a formal CrowdStrike product, Terraform CrowdStrike Provider is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional information, please refer to the [SUPPORT.md](./SUPPORT.md) file.

### CrowdStrike API Access
The provider uses the CrowdStrike Falcon API to manage resources. In order to use the provider, you must have a CrowdStrike API client ID and client secret.

> [!NOTE]
> See a resource's documentation for the specific scopes required for that resource.

### Importing Existing CrowdStrike resources

The CrowdStrike provider supports importing existing resources into terraform state. This is useful for managing resources that were created outside of terraform. Refer to the [importing guide](./docs/importing.md) for an example of using the `import` block and the `terraform import` command.

# Contributing
See the [contributing documentation](./CONTRIBUTING.md).
