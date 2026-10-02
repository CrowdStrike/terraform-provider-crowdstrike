data "crowdstrike_ml_file_path_exclusion" "by_id" {
  id = "11111111111111111111111111111111"
}

data "crowdstrike_ml_file_path_exclusion" "by_pattern" {
  pattern = "/opt/example/cache/*"
}
