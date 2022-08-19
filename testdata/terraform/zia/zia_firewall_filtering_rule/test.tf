resource "zia_firewall_filtering_rule" "terraform_managed_resource" {
  access_control      = "READ_WRITE"
  action              = "BLOCK_DROP"
  default_rule        = true
  enable_full_logging = false
  name                = "Default Firewall Filtering Rule"
  order               = -1
  predefined          = false
  rank                = 7
  state               = "ENABLED"
}