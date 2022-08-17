resource "zpa_policy_forwarding_rule" "terraform_managed_resource" {
  action              = "INTERCEPT"
  bypass_default_rule = false
  default_rule        = true
  description         = "This is the default Client Forwarding Policy rule"
  lss_default_rule    = false
  name                = "Default_Rule"
  operator            = "AND"
  policy_type         = "4"
  priority            = "1"
  reauth_default_rule = false
  rule_order          = "1"
}