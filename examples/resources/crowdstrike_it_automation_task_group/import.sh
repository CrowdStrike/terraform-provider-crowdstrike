# it automation task group can be imported by specifying the task group id.
terraform import crowdstrike_it_automation_task_group.example 05ecd4910ac34f9f8b5f07d9f9b57e80

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_it_automation_task_group.example
  id = "05ecd4910ac34f9f8b5f07d9f9b57e80"
}