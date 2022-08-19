resource "zia_firewall_filtering_ip_source_groups" "terraform_managed_resource" {
  description  = "Dynamic source ip group generated for service registered in Consul"
  ip_addresses = ["10.0.31.153", "10.0.31.155", "10.0.31.156"]
  name         = "consul-nginx"
}