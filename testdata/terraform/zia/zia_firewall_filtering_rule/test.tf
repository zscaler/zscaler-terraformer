resource "zia_firewall_filtering_rule" "terraform_managed_resource" {
  action              = "BLOCK_DROP"
  default_rule        = true
  enable_full_logging = false
  name                = "FW_Filtering_Rule"
  order               = -1
  predefined          = false
  rank                = 7
  state               = "ENABLED"
}