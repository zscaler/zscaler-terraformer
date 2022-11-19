resource "zia_location_management" "terraform_managed_resource" {
  aup_block_internet_until_accepted = false
  aup_enabled                       = false
  aup_force_ssl_inspection          = false
  auth_required                     = true
  caution_enabled                   = false
  country                           = "AUSTRALIA"
  description                       = "Created with Terraform"
  display_time_unit                 = "HOUR"
  idle_time_in_minutes              = 720
  ip_addresses                      = ["61.68.118.237"]
  ips_control                       = true
  name                              = "AU - Sydney - Branch01"
  ofw_enabled                       = true
  profile                           = "CORPORATE"
  ssl_scan_enabled                  = false
  tz                                = "AUSTRALIA_SYDNEY"
  xff_forward_enabled               = true
}