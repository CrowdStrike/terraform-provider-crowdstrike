resource "crowdstrike_response_policy" "example" {
  name          = "Production RTR Policy"
  description   = "Allows basic RTR commands for production hosts"
  platform_name = "Windows" # Valid values: "Windows", "Mac", "Linux"
  enabled       = true
  host_groups   = [crowdstrike_host_group.production.id]

  # Required for any RTR functionality (all platforms)
  real_time_response = true

  # Common RTR commands (all platforms)
  custom_scripts = true
  get_command    = true
  put_command    = true
  exec_command   = false

  # Windows-only settings
  falcon_scripts      = true # Requires custom_scripts
  memdump_command     = false
  xmemdump_command    = false
  put_and_run_command = false # Also available on Mac
}
