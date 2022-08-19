resource "zpa_policy_inspection_rule" "terraform_managed_resource" {
  action              = "INSPECT"
  bypass_default_rule = false
  description         = "Automatically created by Zscaler Deception API for whiskeygolf"
  lss_default_rule    = false
  name                = "Zscaler Deception"
  operator            = "AND"
  policy_type         = "1"
  priority            = "1"
  reauth_default_rule = false
  rule_order          = "1"
  conditions {
    negated  = false
    operator = "OR"
    operands {
      lhs         = "id"
      name        = "Zscaler Deception"
      object_type = "APP_GROUP"
      rhs         = "216196257331301307"
    }
  }
}