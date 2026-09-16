data "crowdstrike_custom_ioc" "by_id" {
  id = "11111111111111111111111111111111"
}

data "crowdstrike_custom_ioc" "by_value" {
  type  = "domain"
  value = "sample.example.com"
}
