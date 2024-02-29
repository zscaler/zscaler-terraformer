resource "zpa_policy_timeout_rule" "terraform_managed_resource" {
  action              = "RE_AUTH"
  custom_msg          = "Your access to internal Applications has expired"
  description         = "This is the default Timeout Policy rule"
  lss_default_rule    = false
  name                = "Default_Rule2"
  operator            = "AND"
  reauth_idle_timeout = "-1"
  reauth_timeout      = "-1"
}