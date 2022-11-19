resource "zia_firewall_filtering_network_service" "terraform_managed_resource" {
  description = "ICMP_ANY_DESC"
  name        = "ICMP_ANY"
  tag         = "ICMP_ANY"
  type        = "CUSTOM"
}