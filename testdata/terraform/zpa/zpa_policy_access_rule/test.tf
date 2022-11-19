resource "zpa_policy_access_rule" "terraform_managed_resource" {
  action              = "ALLOW"
  bypass_default_rule = false
  description         = "Automatically created by Zscaler Deception API for whiskeygolf"
  lss_default_rule    = false
  name                = "test name"
  operator            = "AND"
  policy_type         = "1"
  priority            = "1"
  reauth_default_rule = false
  rule_order          = "1"
  app_connector_groups {
    id = ["216196257331301305"]
  }
  app_server_groups {
    id = ["216196257331301306"]
  }
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
