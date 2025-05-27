# Prerequisites

- [Go 1.21+](https://go.dev/doc/install) installed and configured.
- [Terraform v1.8+](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) installed locally.

# Setting up the environment

Create a `.terraformrc` file in your home directory.

`touch ~/.terraformrc`

Then edit the `.terraformrc` file to look like this

```
provider_installation {
  dev_overrides {
      "registry.terraform.io/crowdstrike/crowdstrike" = "/path/to/go/bin"
  }

  direct {}
}
```

The value of `/path/to/go/bin` will be your `GOBIN` path. You can run `go env GOBIN` to find the path Go installs your binaries.

If `go env GOBIN` is not set then use the default path of `/Users/<Username>/go/bin`

Terraform will now use the locally built provider when you run terraform configurations that reference the CrowdStrike provider. Use the steps below in [Building the provider](#Building-the-provider) to learn how to create the local provider.

# Building the provider

Clone the repository

`git clone https://github.com/CrowdStrike/terraform-provider-crowdstrike.git`

Change into the cloned repository.

`cd terraform-provider-crowdstrike`

Build the terraform-provider-crowdstrike provider

`make build`

Run `make build` anytime new changes are added to the provider or you pull a new code from the repository to update your local install of the provider.
