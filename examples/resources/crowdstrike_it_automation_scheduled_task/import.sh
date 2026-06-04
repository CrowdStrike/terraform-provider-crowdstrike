# it automation scheduled task can be imported by specifying the scheduled task id.
terraform import crowdstrike_it_automation_scheduled_task.example 005e5b946b1e4320bffb7c71427c0a00

# using import block (requires terraform 1.5+)
import {
  to = crowdstrike_it_automation_scheduled_task.example
  id = "005e5b946b1e4320bffb7c71427c0a00"
}
