resource "zpa_policy_inspection_rule" "terraform_managed_resource" {
  action              = "INSPECT"
  description         = "Automatically created by Zscaler Deception API for whiskeygolf"
  lss_default_rule    = false
  name                = "test name"
  operator            = "AND"
  policy_type         = "1"
  conditions {
    negated  = false
    operator = "OR"
    operands {
      lhs         = "id"
      name        = "test name"
      object_type = "APP_GROUP"
      rhs         = "216196257331301307"
    }
  }
}