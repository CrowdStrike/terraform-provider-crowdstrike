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


resource "crowdstrike_filevantage_policy_precedence" "windows" {
  ids = [
    "12345678901234567890123456789012",
    "abcdefabcdefabcdefabcdefabcdefab",
    "11111111222222223333333344444444",
  ]
  platform_name = "windows"
  enforcement   = "dynamic"
}

resource "crowdstrike_filevantage_policy_precedence" "linux" {
  ids = [
    "aaaabbbbccccddddeeeeffffaaaabbbb",
    "55555555666666667777777788888888",
  ]
  platform_name = "linux"
  enforcement   = "dynamic"
}

resource "crowdstrike_filevantage_policy_precedence" "mac" {
  ids = [
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabe",
  ]
  platform_name = "mac"
  enforcement   = "dynamic"
}
