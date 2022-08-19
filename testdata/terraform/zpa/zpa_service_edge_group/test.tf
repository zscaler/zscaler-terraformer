resource "zpa_service_edge_group" "terraform_managed_resource" {
  description              = "Service Edge Group New York"
  enabled                  = false
  latitude                 = "40.7128"
  location                 = "New York, NY, USA"
  longitude                = "-73.935242"
  name                     = "Service Edge Group New York"
  override_version_profile = false
  upgrade_day              = "SUNDAY"
  upgrade_time_in_secs     = "66600"
  version_profile_id       = "0"
}
