data "crowdstrike_ioa_exclusion" "by_id" {
  id = "11111111111111111111111111111111"
}

data "crowdstrike_ioa_exclusion" "by_name" {
  name = "Example exclusion"
}
