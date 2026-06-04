---
page_title: "Get Started with the CrowdStrike Provider"
subcategory: "Guides"
description: |-
  A hands-on tutorial that walks you through installing Terraform, authenticating
  to the CrowdStrike Falcon API, and using the CrowdStrike provider to create,
  change, and destroy host groups.
---

# Get Started with the CrowdStrike Provider

Terraform lets you manage infrastructure as code: you write declarative
configuration files that describe the resources you want, and Terraform creates,
updates, and deletes them through a provider's API.

This tutorial walks you through the full Terraform workflow with the CrowdStrike
provider. By the end you will have installed Terraform, authenticated to the
CrowdStrike Falcon API, and used a single configuration to **create**, **change**,
and **destroy** Falcon host groups.

If you have used Terraform with another provider (such as AWS) the workflow here
is identical. Only the provider configuration and the resource itself are
specific to CrowdStrike.

## Prerequisites

To follow along you need:

- The [Terraform CLI](https://developer.hashicorp.com/terraform/install) (1.0 or
  later) installed locally. See [Install Terraform](#install-terraform) below.
- A CrowdStrike Falcon subscription.
- A CrowdStrike API client ID and client secret. See
  [Create an API client](#create-an-api-client) below.

You do not need to manage any sensors or hosts to complete this tutorial. A host
group is a lightweight, logical object in your Falcon tenant, which makes it a
safe resource to create and delete while you learn.

---

## Install Terraform

Install the Terraform CLI for your operating system by following HashiCorp's
official guide: [Install Terraform](https://developer.hashicorp.com/terraform/install).
It covers the package managers for macOS, Windows, and Linux as well as manual
installation.

Once installed, confirm Terraform is on your `PATH`:

```shell
terraform version
```

```
Terraform v1.9.0
on darwin_arm64
```

---

## Create an API client

The provider authenticates to the CrowdStrike Falcon API with an OAuth2 API
client. To create one:

1. In the Falcon console, go to **Support and resources > Resources and tools >
   API clients and keys**.
2. Select **Create API client**.
3. Give the client a name (for example, `terraform-tutorial`).
4. Grant the API scopes required for this tutorial. The `crowdstrike_host_group`
   resource requires the following scopes, each with **Read & Write**:
   - Host groups
   - Firewall management
   - Prevention policies
   - Response policies
   - Sensor update policies
5. Select **Create** and copy the **client ID** and **client secret**. The secret
   is shown only once.

Host groups need more than the "Host groups" scope because groups can be attached
to firewall, prevention, response, and sensor update policies. The provider needs
read and write access to those areas to manage those relationships.

~> **Note:** Each resource documents the API scopes it requires. When you start
managing other resources, check that resource's documentation page and add the
listed scopes to your API client.

### Provide your credentials

The provider reads credentials from environment variables, which keeps secrets
out of your configuration files. Export them in your shell:

```shell
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_CLOUD="us-2"
```

Set `FALCON_CLOUD` to the cloud your tenant runs in. Valid values are
`autodiscover`, `us-1`, `us-2`, `eu-1`, `us-gov-1`, and `us-gov-2`.

-> **Tip:** You can also set `client_id`, `client_secret`, and `cloud` directly
in the `provider` block, but environment variables are recommended so that
secrets are never written to disk or committed to version control. A value set in
the `provider` block takes precedence over the matching environment variable.

---

## Write configuration

Each Terraform configuration lives in its own working directory. Create one for
this tutorial and move into it:

```shell
mkdir learn-terraform-crowdstrike
cd learn-terraform-crowdstrike
```

Terraform configuration files are plain text files ending in `.tf`. When you run
the Terraform CLI, Terraform loads every configuration file in the current
working directory and automatically resolves dependencies between them, so you
can organize your configuration across multiple files in any order you choose.

Terraform configuration is organized into blocks that configure Terraform
itself, the providers it uses, and the resources that make up your
infrastructure.

### The `terraform` block

The `terraform` block configures Terraform itself, including which providers to
install and which version of Terraform to use. Using a consistent file structure
makes maintaining your projects easier, so we recommend configuring the
`terraform` block in a dedicated `terraform.tf` file.

Create a file named `terraform.tf` with the following configuration:

```terraform
terraform {
  required_providers {
    crowdstrike = {
      source  = "registry.terraform.io/crowdstrike/crowdstrike"
      version = "~> 0.0"
    }
  }

  required_version = ">= 1.0"
}
```

Terraform uses binary plugins called providers to manage resources by calling an
API. Providers are distributed and versioned separately from Terraform itself.
The `required_providers` block sets version constraints on the providers your
configuration uses.

The `source` argument specifies a hostname (optional), namespace, and provider
name. Here, `registry.terraform.io/crowdstrike/crowdstrike` is the address of the
provider in the [Terraform Registry](https://registry.terraform.io/providers/crowdstrike/crowdstrike).

The `version` argument sets a version constraint for the provider. If you omit
it, Terraform installs the most recent version. We recommend constraining the
version so Terraform does not install a version you have not tested with. The
string `~> 0.0` allows any `0.x` release.

The block also sets `required_version`, the version constraint for Terraform
itself. The string `>= 1.0` means your configuration supports any version of
Terraform greater than or equal to 1.0. You can check your version with
`terraform version`.

### Configuration blocks

Paste the following configuration into a new file named `main.tf`:

```terraform
provider "crowdstrike" {
  cloud = "us-2" # set to your tenant's cloud, or omit to use FALCON_CLOUD
}

resource "crowdstrike_host_group" "example" {
  name        = "Learn Terraform"
  description = "Managed by Terraform"
  type        = "static"
  hostnames   = ["host1", "host2"]
}
```

When you write a new Terraform configuration, we recommend defining your provider
blocks and primary infrastructure in `main.tf`. As your configuration grows, you
can organize related infrastructure into separate files.

#### The `provider` block

The `provider` block configures options that apply to all resources managed by
that provider. The label of the block (`crowdstrike`) corresponds to the name of
the provider in the `required_providers` list in your `terraform` block.

```terraform
provider "crowdstrike" {
  cloud = "us-2" # set to your tenant's cloud, or omit to use FALCON_CLOUD
}
```

This block only sets `cloud`, because the client ID and secret come from the
environment variables you exported earlier. If you set `FALCON_CLOUD`, you can
omit `cloud` here as well.

You can use multiple `provider` blocks to configure multiple providers, or
multiple instances of the same provider with different configurations.

#### The `resource` block

A `resource` block defines a component of your infrastructure. The first line
declares the resource type and the resource name.

```terraform
resource "crowdstrike_host_group" "example" {
  name        = "Learn Terraform"
  description = "Managed by Terraform"
  type        = "static"
  hostnames   = ["host1", "host2"]
}
```

The resource type is `crowdstrike_host_group`. The prefix of the resource type
corresponds to the name of the provider. Together, the resource type and name
form a unique resource address, `crowdstrike_host_group.example`, which you can
use to refer to this resource elsewhere in your configuration.

The arguments inside the block configure the host group:

- `name` and `description` are required for every host group.
- `type` is `static`, which means membership is defined by an explicit list of
  hostnames. The other valid types are `dynamic` (membership is defined by an
  assignment rule) and `staticByID` (membership is defined by a list of host
  IDs).
- `hostnames` is the list of hosts that belong to this static group.

### Format your configuration

We recommend using consistent formatting for readability. The `terraform fmt`
command automatically reformats the configuration files in the current directory
to the canonical style:

```shell
terraform fmt
```

Terraform prints the names of any files it changed. If your files already match
the canonical style, it prints nothing.

---

## Initialize the directory

Before you can apply a configuration, you must initialize the working directory
with `terraform init`. Initialization downloads and installs the providers
declared in your configuration.

```shell
terraform init
```

```
Initializing the backend...
Initializing provider plugins...
- Finding crowdstrike/crowdstrike versions matching "~> 0.0"...
- Installing crowdstrike/crowdstrike ...
- Installed crowdstrike/crowdstrike (signed by a HashiCorp partner)

Terraform has been successfully initialized!
```

Terraform downloads the CrowdStrike provider into a hidden `.terraform`
subdirectory and records the selected version in a `.terraform.lock.hcl` lock
file. Commit this lock file to version control so that everyone working on the
configuration uses the same provider version.

## Validate your configuration

Make sure your configuration is syntactically valid and internally consistent
with `terraform validate`:

```shell
terraform validate
```

```
Success! The configuration is valid.
```

The `validate` command helps you catch errors before you apply. For example, if
you mistype a resource name or reference an argument the resource does not
support, Terraform reports the error here.

---

## Create the host group

Terraform makes changes to your infrastructure in two steps:

1. Terraform creates an execution plan describing the changes it will make.
   You review this plan to confirm Terraform will make the changes you expect.
2. Once you approve the plan, Terraform applies those changes through the
   provider.

This workflow lets you detect and resolve unexpected problems before Terraform
changes anything.

Plan and apply your configuration with `terraform apply`. Terraform prints the
execution plan and asks you to confirm before it applies. Your configuration
includes a single resource, `crowdstrike_host_group.example`, so the plan
indicates that Terraform will create one host group.

```shell
terraform apply
```

A `+` next to a resource means Terraform will create it. Attributes whose values
the API assigns are shown as `(known after apply)`.

```
Terraform will perform the following actions:

  # crowdstrike_host_group.example will be created
  + resource "crowdstrike_host_group" "example" {
      + description  = "Managed by Terraform"
      + hostnames    = [
          + "host1",
          + "host2",
        ]
      + id           = (known after apply)
      + last_updated = (known after apply)
      + name         = "Learn Terraform"
      + type         = "static"
    }

Plan: 1 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value:
```

The output format is similar to the diff format produced by tools such as Git.
Terraform has not created any infrastructure yet. If the plan showed unexpected
changes, you could cancel the operation here. In this case the plan is
acceptable, so type `yes` at the confirmation prompt to proceed.

```
crowdstrike_host_group.example: Creating...
crowdstrike_host_group.example: Creation complete after 1s [id=abc123...]

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.
```

You have created a host group in your Falcon tenant. You can confirm it exists in
the Falcon console under **Host setup and management > Host groups**.

-> **Tip:** Type `yes` at the prompt to approve. To skip the interactive
confirmation entirely, for example in scripts or CI, run
`terraform apply -auto-approve`. Use it with care, since it applies the plan
without giving you a chance to review it.

### Inspect state

When you applied your configuration, Terraform wrote data about your
infrastructure into a state file named `terraform.tfstate`. Terraform uses this
state to map your configuration to the real objects in your Falcon tenant and to
manage them over their lifecycle.

List the resources tracked in your workspace's state with `terraform state list`:

```shell
terraform state list
```

```
crowdstrike_host_group.example
```

Print your workspace's entire state with `terraform show`:

```shell
terraform show
```

When you plan and apply changes, Terraform compares the last known state, your
current configuration, and the data returned by the provider to build its
execution plan.

The state file is how Terraform knows which real objects it manages. It records
the mapping between each resource in your configuration and its identifier in
your Falcon tenant (for example, a host group's `id`). If you lose the state
file, Terraform no longer knows those resources exist: a later `terraform apply`
would plan to create brand new host groups instead of managing the ones you
already have, leaving you with duplicates it cannot reconcile. Protect your state
file accordingly, and as your usage grows, consider storing it remotely so it is
backed up and shared with your team.

~> **Note:** The state file can contain sensitive values. Never commit
`terraform.tfstate` to version control, and protect it the same way you protect
your credentials.

---

## Change your configuration

As your needs evolve, you can use Terraform to change the infrastructure it
manages. In this section you will add input variables and output values to make
your configuration more dynamic and flexible.

### Input variables

Input variables let you parametrize your configuration so you can change its
behavior without editing the configuration files each time. You can set their
values with environment variables, command line arguments, or files on disk.

Create a new file named `variables.tf`:

```terraform
variable "host_group_name" {
  description = "The display name for the host group."
  type        = string
  default     = "Learn Terraform"
}

variable "hostnames" {
  description = "The hosts that belong to the static host group."
  type        = list(string)
  default     = ["host1", "host2"]
}
```

Each variable sets a default value that Terraform uses if you do not provide one.
We recommend putting your variable and output definitions in their own files,
`variables.tf` and `outputs.tf`, to make your configuration easier to maintain.

Update the resource in `main.tf` to reference these variables instead of
hard-coding the values:

```terraform
resource "crowdstrike_host_group" "example" {
  name        = var.host_group_name
  description = "Managed by Terraform"
  type        = "static"
  hostnames   = var.hostnames
}
```

Run a plan without applying it to preview what would happen if you added a host
using a command line variable:

```shell
terraform plan -var 'hostnames=["host1","host2","host3"]'
```

```
crowdstrike_host_group.example: Refreshing state... [id=abc123...]

Terraform used the selected providers to generate the following execution plan.
Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # crowdstrike_host_group.example will be updated in-place
  ~ resource "crowdstrike_host_group" "example" {
      ~ hostnames    = [
          + "host3",
            # (2 unchanged elements hidden)
        ]
      ~ last_updated = "Thursday, 04-Jun-26 14:57:55 CDT" -> (known after apply)
        id           = "abc123..."
        name         = "Learn Terraform"
        # (2 unchanged attributes hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.

Note: You didn't use the -out option to save this plan, so Terraform can't
guarantee to take exactly these actions if you run "terraform apply" now.
```

The `~` symbol indicates Terraform would update the host group in place. Because
you did not apply this plan, Terraform made no changes.

### Output values

Output values expose data about your resources so you can consume it with other
automation tools or workflows.

Create a new file named `outputs.tf`:

```terraform
output "host_group_id" {
  description = "The unique identifier of the host group."
  value       = crowdstrike_host_group.example.id
}
```

Apply your configuration. Because the default values of your variables match the
values they replaced, Terraform detects that the only change is the new output
value. Respond to the confirmation prompt with `yes`.

```shell
terraform apply
```

```
crowdstrike_host_group.example: Refreshing state... [id=abc123...]

Changes to Outputs:
  + host_group_id = "abc123..."

You can apply this plan to save these new output values to the Terraform state,
without changing any real infrastructure.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes


Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

host_group_id = "abc123..."
```

Terraform prints your output values when you run a plan or apply, and stores them
in your state file. Review them at any time with `terraform output`:

```shell
terraform output
```

```
host_group_id = "abc123..."
```

### Plan and apply changes

Now apply a real change to your host group. Add a host to the `hostnames`
variable by editing its default in `variables.tf`:

```terraform
variable "hostnames" {
  description = "The hosts that belong to the static host group."
  type        = list(string)
  default     = ["host1", "host2", "host3"]
}
```

Apply the change:

```shell
terraform apply
```

The plan shows `~` next to the resource, which means Terraform will update it in
place rather than replacing it.

```
crowdstrike_host_group.example: Refreshing state... [id=abc123...]

Terraform will perform the following actions:

  # crowdstrike_host_group.example will be updated in-place
  ~ resource "crowdstrike_host_group" "example" {
      ~ hostnames    = [
          + "host3",
            # (2 unchanged elements hidden)
        ]
      ~ last_updated = "Thursday, 04-Jun-26 14:57:55 CDT" -> (known after apply)
        id           = "abc123..."
        name         = "Learn Terraform"
        # (2 unchanged attributes hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
```

Type `yes` to confirm. Terraform updates the existing host group in place; the
`id` does not change.

```
crowdstrike_host_group.example: Modifying... [id=abc123...]
crowdstrike_host_group.example: Modifications complete after 1s [id=abc123...]

Apply complete! Resources: 0 added, 1 changed, 0 destroyed.
```

-> **Tip:** Not every change can be made in place. Some arguments, such as a host
group's `type`, cannot be modified after creation. If you change one, the plan
shows `-/+` and Terraform replaces the resource: it destroys the existing host
group and creates a new one with a new `id`. When Terraform builds an execution
plan it determines the correct order of operations from resource dependencies,
and the plan always tells you exactly what will happen before you confirm.

### Add a second host group

A configuration can manage many resources. Add a second host group to `main.tf`
so your workspace manages two resources:

```terraform
resource "crowdstrike_host_group" "servers" {
  name        = "Learn Terraform Servers"
  description = "Managed by Terraform"
  type        = "static"
  hostnames   = ["server1", "server2"]
}
```

Apply the change to create the new host group. Your existing host group is
unchanged, so the plan adds one resource and changes nothing else.

```shell
terraform apply
```

```
crowdstrike_host_group.example: Refreshing state... [id=abc123...]

Terraform will perform the following actions:

  # crowdstrike_host_group.servers will be created
  + resource "crowdstrike_host_group" "servers" {
      + description  = "Managed by Terraform"
      + hostnames    = [
          + "server1",
          + "server2",
        ]
      + id           = (known after apply)
      + last_updated = (known after apply)
      + name         = "Learn Terraform Servers"
      + type         = "static"
    }

Plan: 1 to add, 0 to change, 0 to destroy.
```

Type `yes` to confirm. Both host groups are now managed by your configuration.
List them with `terraform state list`:

```shell
terraform state list
```

```
crowdstrike_host_group.example
crowdstrike_host_group.servers
```

---

## Destroy your infrastructure

You can remove resources individually as part of your normal workflow, or
destroy everything in a workspace when you no longer need it.

### Remove a resource

When you remove a resource from your configuration, Terraform plans to destroy it
on the next apply. "Removing it from your configuration" simply means the resource
block is no longer present: you can delete the lines outright, or comment them out
if you want to keep them handy. Either has the same effect.

In `main.tf`, remove the `crowdstrike_host_group.example` resource block, leaving
the `servers` host group in place. This example comments it out:

```terraform
/*
resource "crowdstrike_host_group" "example" {
  name        = var.host_group_name
  description = "Managed by Terraform"
  type        = "static"
  hostnames   = var.hostnames
}
*/
```

The `host_group_id` output in `outputs.tf` refers to the resource you just
removed, so you must remove it as well, or your configuration would be invalid:

```terraform
/*
output "host_group_id" {
  description = "The unique identifier of the host group."
  value       = crowdstrike_host_group.example.id
}
*/
```

Apply this change with `terraform apply`. Approve the plan to destroy the
`example` host group and remove the output value by responding `yes`. The
`servers` host group stays as it is.

```shell
terraform apply
```

```
crowdstrike_host_group.servers: Refreshing state... [id=def456...]
crowdstrike_host_group.example: Refreshing state... [id=abc123...]

Terraform will perform the following actions:

  # crowdstrike_host_group.example will be destroyed
  # (because crowdstrike_host_group.example is not in configuration)
  - resource "crowdstrike_host_group" "example" {
      - description  = "Managed by Terraform" -> null
      - hostnames    = [
          - "host1",
          - "host2",
          - "host3",
        ] -> null
      - id           = "abc123..." -> null
      - last_updated = "Thursday, 04-Jun-26 14:57:55 CDT" -> null
      - name         = "Learn Terraform" -> null
      - type         = "static" -> null
    }

Plan: 0 to add, 0 to change, 1 to destroy.

Changes to Outputs:
  - host_group_id = "abc123..." -> null

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

crowdstrike_host_group.example: Destroying... [id=abc123...]
crowdstrike_host_group.example: Destruction complete after 1s

Apply complete! Resources: 0 added, 0 changed, 1 destroyed.
```

Terraform destroyed only the `example` host group. The `servers` host group is
still managed by your configuration.

### Destroy the workspace

Removing resources one at a time is useful during normal development, but when
you are finished with everything in a workspace you can tear it all down at once
with `terraform destroy`. This is handy for short-lived environments such as
build or testing systems.

Run `terraform destroy`. Unlike `apply`, this command plans to remove every
resource in your configuration, in this case the remaining `servers` host group.
Approve the plan by responding `yes`.

```shell
terraform destroy
```

Terraform prints a plan with a `-` next to each resource it will destroy:

```
crowdstrike_host_group.servers: Refreshing state... [id=def456...]

Terraform will perform the following actions:

  # crowdstrike_host_group.servers will be destroyed
  - resource "crowdstrike_host_group" "servers" {
      - description  = "Managed by Terraform" -> null
      - hostnames    = [
          - "server1",
          - "server2",
        ] -> null
      - id           = "def456..." -> null
      - last_updated = "Thursday, 04-Jun-26 14:57:55 CDT" -> null
      - name         = "Learn Terraform Servers" -> null
      - type         = "static" -> null
    }

Plan: 0 to add, 0 to change, 1 to destroy.

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

crowdstrike_host_group.servers: Destroying... [id=def456...]
crowdstrike_host_group.servers: Destruction complete after 1s

Destroy complete! Resources: 1 destroyed.
```

Your host groups are gone from both your Terraform state and the Falcon console.
You can confirm they no longer appear under **Host setup and management > Host
groups**.

---

## Import an existing resource

If you already have host groups (or other resources) that were created outside of
Terraform, you can bring them under Terraform management with `terraform import`.

For a host group, the import ID is the host group's ID:

```shell
terraform import crowdstrike_host_group.example 7fb858a949034a0cbca175f660f1e769
```

After importing, run `terraform plan` and reconcile your configuration with the
imported resource until the plan reports no changes. See the
[importing guide](https://github.com/crowdstrike/terraform-provider-crowdstrike/blob/main/docs/importing.md)
for a complete walkthrough using `import` blocks.

---

## Next steps

You have completed the core Terraform workflow with the CrowdStrike provider:
install, write, init, apply (create), apply (change), and destroy.

From here you can:

- Browse the [provider documentation](https://registry.terraform.io/providers/crowdstrike/crowdstrike/latest/docs)
  to see every resource and data source the provider supports.
- Explore [examples](https://github.com/crowdstrike/terraform-provider-crowdstrike/tree/main/examples)
  for each resource.
- Learn the broader Terraform language and workflow in HashiCorp's
  [Terraform documentation](https://developer.hashicorp.com/terraform/docs).
- Report issues or request new resources on the
  [project issue tracker](https://github.com/crowdstrike/terraform-provider-crowdstrike/issues).
