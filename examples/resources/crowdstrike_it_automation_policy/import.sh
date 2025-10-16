# it automation policy can be imported by specifying the policy id.
terraform import crowdstrike_it_automation_policy.example 717cc96f8c5240bd8126f58153a8b13f

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_it_automation_policy.example
  id = "717cc96f8c5240bd8126f58153a8b13f"
}