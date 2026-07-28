terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

# Granting roles in a child CID requires parent CID credentials.
provider "crowdstrike" {
  cloud = "us-2"
}

variable "user_uuid" {
  description = "UUID of the existing Falcon user to assign roles to."
  type        = string
}

variable "child_cid" {
  description = "A child CID of the Falcon Flight Control (FCTL) parent tenant, in canonical form: 32 lowercase hex characters with no checksum suffix."
  type        = string
}

# The CID for the authenticating credentials, which is the parent CID for FCTL
# customers.
data "crowdstrike_cid" "current" {}

# Roles granted to the user in the CID making the request.
resource "crowdstrike_user_role_assignment" "parent" {
  user_uuid = var.user_uuid
  cid       = data.crowdstrike_cid.current.cid

  role_ids = [
    "falcon_console_guest",
    "image_viewer",
  ]
}

# Roles granted to the same user in a child CID. FCTL customers making requests
# from the parent CID can set cid to the ID of any of their child CIDs.
#
# role_ids is authoritative per CID, so the two assignments are independent:
# neither one revokes the roles the user holds in the other CID.
resource "crowdstrike_user_role_assignment" "child" {
  user_uuid = var.user_uuid
  cid       = var.child_cid

  role_ids = [
    "falcon_console_guest",
  ]
}

output "parent_cid_roles" {
  value = crowdstrike_user_role_assignment.parent
}

output "child_cid_roles" {
  value = crowdstrike_user_role_assignment.child
}
