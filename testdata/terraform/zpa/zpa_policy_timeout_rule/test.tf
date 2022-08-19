resource "zpa_policy_timeout_rule" "terraform_managed_resource" {
  action              = "RE_AUTH"
  bypass_default_rule = false
  custom_msg          = "Your access to internal Applications has expired"
  default_rule        = true
  description         = "This is the default Timeout Policy rule"
  lss_default_rule    = false
  name                = "Default_Rule"
  operator            = "AND"
  policy_type         = "2"
  priority            = "1"
  reauth_default_rule = false
  reauth_idle_timeout = "-1"
  reauth_timeout      = "-1"
  rule_order          = "1"
}