resource "zpa_app_connector_group" "terraform_managed_resource" {
  city_country             = "Mumbai, IN"
  country_code             = "IN"
  description              = "Automatically created by Zscaler Deception API for whiskeygolf"
  dns_query_type           = "IPV4_IPV6"
  enabled                  = true
  latitude                 = "19.0728"
  location                 = "Mumbai, Maharashtra, India"
  longitude                = "72.8826"
  lss_app_connector_group  = true
  name                     = "test name"
  override_version_profile = false
  upgrade_day              = "SUNDAY"
  upgrade_time_in_secs     = "66600"
  version_profile_id       = "2"
  version_profile_name     = "New Release"
}