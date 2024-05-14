# WORK IN PROGRESS

The CrowdStrike terraform provider is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

> [!CAUTION]
> This repository is a work in progress and should not be used.


## Requirements

### CrowdStrike API Access
| Scope                   | Permission      |
|-------------------------|-----------------|
| Device Control Policies | *READ*, *WRITE* |
| Prevention Policies     | *READ*, *WRITE* |
| Response Policies       | *READ*, *WRITE* |
| Firewall Management     | *READ*, *WRITE* |
| Host Groups             | *READ*, *WRITE* |
| Sensor Update Policies  | *READ*, *WRITE* |


- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0

## Testing locally

1. Install [Go >= 1.21](https://golang.org/doc/install)
1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:
    ```shell
    go install
    ```
1. Create a `.terraformrc` file in your home directory. 

    #### Mac/Linux
    `~/.terraformrc` is the path to the file.

    #### Windows

    `%APPDATA%\.terraform.rc` is the path to the file.

1. Find your `GOBIN` path. You can find this by running `go env GOBIN`. If nothing is returned you can run `go env GOPATH` and append `/bin` to the end of the path. Ex: `C:\Users\username\go\bin`

1. Add the following to your `.terraformrc` file replacing `GOBIN_PATH` with the path found in the previous step:
    ```shell
    provider_installation {

      dev_overrides {
          "registry.terraform.io/crowdstrike/crowdstrike" = "GOBIN_PATH"
      }

      direct {}
    }
    ```

    Example:
    ```shell
    provider_installation {

      dev_overrides {
          "registry.terraform.io/crowdstrike/crowdstrike" = "C:\Users\username\go\bin"
      }

      direct {}
    }
    ```
1. You are ready to use the terraform provider. The [docs](./docs/) folder has documentation for each resource. The [examples](./examples/) folder has examples of each resource.


## Example Usage
1. Export your CrowdStrike API credentials as environment variables. 
    ```shell
    export FALCON_CLIENT_ID="YOUR_CLIENT_ID"
    export FALCON_CLIENT_SECRET="YOUR_CLIENT_SECRET"
    ```

1. Create a `main.tf` file with the following content:
    ```hcl
    terraform {
      required_providers {
        crowdstrike = {
          source = "registry.terraform.io/crowdstrike/crowdstrike"
        }
      }
    }

    provider "crowdstrike" {
      cloud = "us-2"
    }


    resource "crowdstrike_host_group" "example" {
      name            = "example_host_group"
      description     = "made with terraform"
      type            = "dynamic"
      assignment_rule = "tags:'SensorGroupingTags/cloud-lab'+os_version:'Amazon Linux 2'"
    }

    output "host_group" {
      value = crowdstrike_host_group.example
    }
    ```
1. Run `terraform plan` to see the changes that will be made. (Since we are using a local provider, there is no reason to run `terraform init`)
1. Run `terraform apply` to apply the changes.
1. Run `terraform destroy` to remove the resources.
