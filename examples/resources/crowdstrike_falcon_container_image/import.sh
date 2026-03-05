#!/bin/bash

# Import a Falcon Container Image registry using its UUID
terraform import crowdstrike_falcon_container_image.dockerhub <registry_uuid>

# Example:
# terraform import crowdstrike_falcon_container_image.dockerhub a1b2c3d4-e5f6-7890-abcd-ef1234567890
