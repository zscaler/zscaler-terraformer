resource "zpa_policy_forwarding_rule" "terraform_managed_resource" {
  action              = "INTERCEPT"
  bypass_default_rule = false
  description         = "This is the default Client Forwarding Policy rule"
  lss_default_rule    = false
  name                = "Default_Rule2"
  operator            = "AND"
  policy_type         = "4"
  priority            = "1"
  reauth_default_rule = false
  rule_order          = "1"
}