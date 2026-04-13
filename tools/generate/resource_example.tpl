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


resource "crowdstrike_{{.SnakeCaseName}}" "example" {}

output "{{.SnakeCaseName}}" {
  value = crowdstrike_{{.SnakeCaseName}}.example
}
