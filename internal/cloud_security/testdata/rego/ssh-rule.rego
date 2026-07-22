package crowdstrike

import rego.v1

# EC2 Security Group policy
cx_policy contains result if {
	some i, name
	resource := input.document[i].resource.aws_security_group[name]
	some rule in resource.ingress
	rule.from_port == 22
	"0.0.0.0/0" in rule.cidr_blocks

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": name,
		"searchKey": sprintf("aws_security_group[%s].ingress", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Security group should not allow SSH from anywhere",
		"keyActualValue": "Security group allows SSH from 0.0.0.0/0",
	}
}
