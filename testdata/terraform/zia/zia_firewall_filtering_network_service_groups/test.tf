resource "zia_firewall_filtering_network_service_groups" "terraform_managed_resource" {
  description = "example"
  name        = "example"
  services {
    id = [12345]
  }
}
