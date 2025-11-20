# Example 1: Simple single-page query
# Most common use case - fetch a specific page of results
data "crowdstrike_cloud_risks" "high_severity" {
  filter = "severity:'High'+status:'Open'"
  sort   = "first_seen|desc"
  limit  = 10
  offset = 0
}

output "high_severity_info" {
  value = {
    returned_count = data.crowdstrike_cloud_risks.high_severity.returned_count
    total_count    = data.crowdstrike_cloud_risks.high_severity.total_count
    has_more       = data.crowdstrike_cloud_risks.high_severity.has_more
  }
}

# Example 2: Fetching all pages dynamically based on total_count
# Step 1: Fetch first page to get total_count
locals {
  page_size = 100
}

data "crowdstrike_cloud_risks" "first_page" {
  filter = "status:'Open'"
  limit  = local.page_size
  offset = 0
}

# Step 2: Calculate remaining pages needed based on total_count
locals {
  total_count     = data.crowdstrike_cloud_risks.first_page.total_count
  remaining_count = local.total_count - data.crowdstrike_cloud_risks.first_page.returned_count
  remaining_pages = ceil(local.remaining_count / local.page_size)
  # Create range starting from page 1 (we already have page 0)
  remaining_page_numbers = local.remaining_pages > 0 ? range(1, local.remaining_pages + 1) : []
}

# Step 3: Fetch all remaining pages using for_each
data "crowdstrike_cloud_risks" "remaining_pages" {
  for_each = toset([for i in local.remaining_page_numbers : tostring(i)])

  filter = "status:'Open'"
  limit  = local.page_size
  offset = local.page_size * tonumber(each.key)
}

# Step 4: Combine first page with all remaining pages
locals {
  all_risks = concat(
    # First page
    [for risk in data.crowdstrike_cloud_risks.first_page.risks : risk],
    # Remaining pages
    flatten([
      for page_key, page_data in data.crowdstrike_cloud_risks.remaining_pages :
      [for risk in page_data.risks : risk]
    ])
  )
}

output "all_risks_summary" {
  value = {
    total_count         = local.total_count
    total_risks_fetched = length(local.all_risks)
    pages_fetched       = 1 + length(data.crowdstrike_cloud_risks.remaining_pages)
  }
}
