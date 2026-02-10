# List dynamic host groups only
list "crowdstrike_host_group" "dynamic_only" {
  provider = crowdstrike
  config {
    filter = "group_type:'dynamic'"
  }
}

# List static host groups only
list "crowdstrike_host_group" "static_only" {
  provider = crowdstrike
  config {
    filter = "group_type:'static'"
  }
}

# List host groups matching a name pattern
list "crowdstrike_host_group" "dev_groups" {
  provider = crowdstrike
  config {
    filter = "name:~'*dev*'"
  }
}
