resource "zpa_policy_forwarding_rule" "terraform_managed_resource" {
  action              = "INTERCEPT"
  description         = "This is the default Client Forwarding Policy rule"
  name                = "Default_Rule2"
  operator            = "AND"
  policy_type         = "4"
}