resource "zpa_application_server" "terraform_managed_resource" {
  address      = "192.168.1.1"
  config_space = "DEFAULT"
  description  = "Zscaler Terraformer"
  enabled      = true
  name         = "Zscaler Terraformer"
}
