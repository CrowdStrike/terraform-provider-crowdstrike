resource "crowdstrike_host_group" "windows_build_hosts" {
  name            = "windows-build-hosts"
  description     = "Windows CI workers that run the signed build agent"
  type            = "dynamic"
  assignment_rule = "tags:'SensorGroupingTags/windows-build-hosts'"
}

resource "crowdstrike_self_service_ioa_exclusion" "example" {
  name        = "Windows build agent package restore"
  description = "Suppress a known false positive when the signed build agent restores packages during CI jobs."

  pattern_id            = "12345"
  ifn_regex             = ".*\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1\\.0\\\\powershell\\.exe"
  cl_regex              = ".*-File C:\\\\BuildAgent\\\\work\\\\_temp\\\\restore-packages\\.ps1.*"
  parent_ifn_regex      = ".*\\\\BuildAgent\\\\bin\\\\Agent\\.Worker\\.exe"
  parent_cl_regex       = ".*Agent\\.Worker\\.exe.*-jobId [A-Za-z0-9-]+.*"
  grandparent_ifn_regex = ".*\\\\BuildAgent\\\\bin\\\\Agent\\.Listener\\.exe"
  grandparent_cl_regex  = ".*Agent\\.Listener\\.exe.*"

  host_groups = [crowdstrike_host_group.windows_build_hosts.id]
  comment     = "Scoped to tagged Windows build hosts and the expected build-agent process tree."
}
