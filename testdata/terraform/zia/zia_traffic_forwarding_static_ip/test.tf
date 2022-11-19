resource "zia_traffic_forwarding_static_ip" "terraform_managed_resource" {
  comment      = "SJC37 - Static IP"
  geo_override = false
  ip_address   = "50.98.112.171"
  latitude     = 49
  longitude    = -123
  last_modified_by {
    id   = 25163058
    name = "ZIA-API"
  }
}