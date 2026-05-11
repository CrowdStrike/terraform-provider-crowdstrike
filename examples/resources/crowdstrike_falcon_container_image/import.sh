#!/bin/bash

# Import a Falcon Container Image registry using its UUID.
terraform import crowdstrike_falcon_container_image.example <registry_uuid>

# Example:
# terraform import crowdstrike_falcon_container_image.example a1b2c3d4-e5f6-7890-abcd-ef1234567890

# NOTE: The API does not return credential values, so all credential fields
# (username, password, aws_iam_role, cert, service_account_json, etc.) will be
# null in state after import. You must add them to your configuration and run
# `terraform apply` to restore them.
