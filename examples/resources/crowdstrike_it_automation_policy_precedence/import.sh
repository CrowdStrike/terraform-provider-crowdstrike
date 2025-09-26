# it automation policy precedence can be imported by specifying the platform (Windows, Linux, or Mac).
terraform import crowdstrike_it_automation_policy_precedence.example Windows

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_it_automation_policy_precedence.example
  id = "Windows"
}