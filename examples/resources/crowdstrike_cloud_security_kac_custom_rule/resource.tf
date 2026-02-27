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

import rego.v1

result := message if {
	count(violations) > 0
	message = sprintf("container(s) running as privileged: %v", [violations])
}

#########################################################################################
# Rules for Pod
#########################################################################################

violations contains message if {
	some cntr in nput.request.object.spec.containers
	cntr.securityContext.privileged
	message = sprintf("container: %v", [cntr.name])
}

violations contains message if {
	some cntr in input.request.object.spec.initContainers
	cntr.securityContext.privileged
	message = sprintf("initContainer: %v", [cntr.name])
}

violations contains message if {
	some cntr in input.request.object.spec.ephemeralContainers
	cntr.securityContext.privileged
	message = sprintf("ephemeralContainer: %v", [cntr.name])
}

#########################################################################################
# Rules for Daemonset, Deployment, Job, ReplicaSet, ReplicationController, StatefulSet
#########################################################################################

violations contains message if {
	some cntr in input.request.object.spec.template.spec.containers
	cntr.securityContext.privileged
	message = sprintf("container: %v", [cntr.name])
}

violations contains message if {
	some cntr in input.request.object.spec.template.spec.initContainers
	cntr.securityContext.privileged
	message = sprintf("initContainer: %v", [cntr.name])
}

#########################################################################################
# Rules for CronJob
#########################################################################################

violations contains message if {
	some cntr in input.request.object.spec.jobTemplate.spec.template.spec.containers
	cntr.securityContext.privileged
	message = sprintf("container: %v", [cntr.name])
}

violations contains message if {
	some cntr in input.request.object.spec.jobTemplate.spec.template.spec.initContainers
	cntr.securityContext.privileged
	message = sprintf("initContainer: %v", [cntr.name])
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

resource "crowdstrike_cloud_security_kac_custom_rule" "host_network_detection_by_file" {
  name        = "detect-host-network-usage-by-file"
  description = "Detects pods using host network namespace"
  severity    = "critical"
  logic       = file("../rego/detect-host-network-usage.rego")
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
