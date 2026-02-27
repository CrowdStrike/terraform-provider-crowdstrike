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

resource "crowdstrike_cloud_security_kac_custom_rule" "privileged_container_detection" {
  name        = "detect-privileged-containers"
  description = "Detects containers configured to run in privileged mode"
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
	some cntr in input.request.object.spec.containers
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
    "Remove or set securityContext.privileged to false",
    "Run containers with minimum required privileges"
  ]
  alert_info = [
    "Container is configured to run in privileged mode",
    "This grants the container unrestricted access to host resources"
  ]
  attack_types = [
    "Privilege Escalation",
    "Container Escape"
  ]
}

resource "crowdstrike_cloud_security_kac_custom_rule" "privileged_container_detection_by_file" {
  name        = "detect-privileged-containers"
  description = "Detects containers configured to run in privileged mode"
  severity    = "critical"
  logic       = file("../rego/detect-privileged-container.rego")
  remediation_info = [
    "Review the pod specification",
    "Remove or set securityContext.privileged to false",
    "Run containers with minimum required privileges"
  ]
  alert_info = [
    "Container is configured to run in privileged mode",
    "This grants the container unrestricted access to host resources"
  ]
  attack_types = [
    "Privilege Escalation",
    "Container Escape"
  ]
}
