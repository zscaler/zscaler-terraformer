resource "zia_firewall_filtering_rule" "terraform_managed_resource" {
  action              = "BLOCK_DROP"
  default_rule        = true
  enable_full_logging = false
  name                = "Default Firewall Filtering Rule 2"
  order               = -1
  predefined          = false
  rank                = 7
  state               = "ENABLED"
}