resource "crowdstrike_cloud_security_iac_custom_rule" "example" {
  name           = "Check SSH Access from Anywhere"
  description    = "Detects security groups that allow SSH access from any IP address"
  cloud_provider = "AWS"
  resource_type  = "EC2"
  severity       = "high"

  logic = <<-EOF
    package crowdstrike

    import rego.v1

    default result := "fail"

    # Only governs security groups; pass every other resource type through.
    result := "pass" if {
      not input.resource.aws_security_group
    }

    # Passes only when no ingress rule opens SSH (port 22) to 0.0.0.0/0.
    result := "pass" if {
      every _, sg in input.resource.aws_security_group {
        not allows_ssh_from_anywhere(sg)
      }
    }

    allows_ssh_from_anywhere(sg) if {
      some rule in sg.ingress
      rule.from_port == 22
      "0.0.0.0/0" in rule.cidr_blocks
    }
  EOF

  remediation_info = [
    "Review the security group configuration",
    "Restrict SSH access to specific IP ranges",
    "Consider using AWS Systems Manager Session Manager instead"
  ]

  alert_info = [
    "Check if the security group allows SSH from 0.0.0.0/0",
    "Verify the resource configuration meets security requirements"
  ]

  category = "Network Security"

  labels = ["aws", "network", "ssh", "critical"]
}

# Example using file() function to load logic from an external file
resource "crowdstrike_cloud_security_iac_custom_rule" "with_file" {
  name           = "Check S3 Bucket Public Access"
  description    = "Ensures S3 buckets have public access blocks enabled"
  cloud_provider = "AWS"
  resource_type  = "S3"
  severity       = "high"

  # Load Rego policy from external file
  logic = file("${path.module}/s3_public_access.rego")

  remediation_info = [
    "Enable block_public_acls on the S3 bucket",
    "Review S3 bucket public access settings"
  ]

  alert_info = [
    "S3 bucket is missing public access block configuration"
  ]

  category = "Data Security"

  labels = ["aws", "s3", "data-protection"]
}
