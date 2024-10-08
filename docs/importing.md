# Importing CrowdStrike Resources

You can start managing existing CrowdStrike resources with terraform by importing resources into terraform state. This guide will go over two different methods of importing CrowdStrike resources into terraform. 

The examples below will show how to import a CrowdStrike Host Group resource, but the same process can be used for other CrowdStrike resources.

## Importing a Single Resource

This example will be importing a single CrowdStrike Host Group named `import_example`.

First create a terraform file that will contain the imported resource, or use an existing file. In the terraform file create a resource block for the resource you want to import. 
```terraform
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

resource "crowdstrike_host_group" "import_example" {}

```

Next, obtain the ID of the resource you want to import. You can obtain the ID by using the CrowdStrike API or, in the CrowdStrike console go to the host group you want to import and copy the ID from the URL.

For example, if the URL is `https://falcon.us-2.crowdstrike.com/hosts/groups-new/edit/7e053217c9cf449fbb503429a0501e87` then the ID is `7e053217c9cf449fbb503429a0501e87`.

At this point, you can import the resource into terraform state by running the following command:
```bash
terraform import crowdstrike_host_group.import_example 7e053217c9cf449fbb503429a0501e87
```

You should see an output similar to the following:

![import_command image](./images/import_command.png)

Now the resource is imported into terraform state, and you can manage it with terraform. However, you are not yet ready to run terraform. Running `terraform plan` at this stage will result in errors similiar to the ones shown below.

![plan_command image](./images/plan_command.png)

These errors occur because although the resource is imported into terraform state, the configration block remains empty in the terraform file.


```terraform
resource "crowdstrike_host_group" "import_example" {}
```

The next step is to fill in the resource block with the desired configuration. Luckily there is a command that will generate the configuration for you based on the state.

Running the following command will output what terraform thinks the resource should look like based on state.
```bash
terraform state show crowdstrike_host_group.import_example
```

You can copy the configuration and paste it into the resource block in the terraform file. 

```terraform
# crowdstrike_host_group.import_example:
resource "crowdstrike_host_group" "import_example" {
    assignment_rule = "tags:'SensorGroupingTags/molecule'+os_version:'RHEL 9.4'"
    description     = "example importing resources"
    id              = "7e053217c9cf449fbb503429a0501e87"
    name            = "import_example"
    type            = "dynamic"
}
```

Remove the `id` field from the configuration as it is not needed. 

Now run `terraform plan`

![plan_finished](./images/plan_finished.png)

If the output shows no changes, your configuration now matches the remote state. If you have errors or changes you can make the necessary modifications to the configuration and run `terraform plan` again until the output shows what you expect.   





