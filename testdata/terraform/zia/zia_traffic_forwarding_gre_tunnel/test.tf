resource "zia_traffic_forwarding_gre_tunnel" "terraform_managed_resource" {
  comment           = "GRE Tunnel Created with Terraform"
  internal_ip_range = "172.18.188.176"
  ip_unnumbered     = false
  source_ip         = "61.68.118.237"
  within_country    = false
  primary_dest_vip {
    id         = 36180
    virtual_ip = "165.225.114.20"
  }
  secondary_dest_vip {
    id         = 88049
    virtual_ip = "165.225.114.21"
  }
}