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

resource "crowdstrike_cloud_security_kac_custom_rule" "host_network_detection" {
  name        = "detect-host-network-usage"
  description = "Detects pods using host network namespace"
  severity    = "critical"
  logic       = <<EOF
package crowdstrike

default result := "pass"

result := "fail" if {
	input.spec.containers[_].securityContext.privileged == true
}

result := "fail" if {
	input.spec.initContainers[_].securityContext.privileged == true
}
EOF
  remediation_info = [
    "Review the pod specification",
    "Remove or set hostNetwork to false",
    "Use Kubernetes services for network connectivity instead"
  ]
  alert_info = [
    "Pod is configured to use the host network namespace",
    "This grants the pod access to the host's network interfaces"
  ]
  attack_types = [
    "Network Attack",
    "Lateral Movement"
  ]
}
