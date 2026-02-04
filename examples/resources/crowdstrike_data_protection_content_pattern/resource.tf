resource "crowdstrike_data_protection_content_pattern" "api_key" {
  name                = "API Key Pattern"
  description         = "Internal API Key pattern"
  regex               = "api[_-]?key[_-]?[a-zA-Z0-9]{32}"
  min_match_threshold = 1
}
