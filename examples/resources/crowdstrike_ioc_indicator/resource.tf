# Allow a specific SHA256 hash globally across all Mac hosts
resource "crowdstrike_ioc_indicator" "allow_by_hash" {
  type             = "sha256"
  value            = "73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac"
  action           = "allow"
  severity         = "informational"
  description      = "Allowlist for approved application - VENDSEC-10155"
  platforms        = ["mac"]
  applied_globally = true
  tags             = ["vendsec-approved"]
}

# Detect a domain, scoped to specific host groups
resource "crowdstrike_ioc_indicator" "detect_domain" {
  type        = "domain"
  value       = "malicious-example.com"
  action      = "detect"
  severity    = "high"
  description = "Known C2 domain"
  platforms   = ["windows", "mac", "linux"]
  host_groups = ["host-group-id-1", "host-group-id-2"]
  expiration  = "2026-12-31T23:59:59Z"
}

# Block an MD5 hash globally
resource "crowdstrike_ioc_indicator" "block_md5" {
  type             = "md5"
  value            = "d41d8cd98f00b204e9800998ecf8427e"
  action           = "prevent"
  severity         = "critical"
  description      = "Known malware hash"
  platforms        = ["windows"]
  applied_globally = true
}
