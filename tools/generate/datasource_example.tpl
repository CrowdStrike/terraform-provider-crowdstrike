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


data "crowdstrike_{{.SnakeCaseName}}" "example" {}

output "{{.SnakeCaseName}}" {
  value = data.crowdstrike_{{.SnakeCaseName}}.example
}
