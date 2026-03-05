data "crowdstrike_falcon_container_image" "example" {
  id = "12345678-1234-1234-1234-123456789012"
}

output "registry_url" {
  value = data.crowdstrike_falcon_container_image.example.url
}

output "credential_expired" {
  value = data.crowdstrike_falcon_container_image.example.credential_expired
}
