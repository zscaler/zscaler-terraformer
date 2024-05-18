resource "zpa_policy_isolation_rule" "terraform_managed_resource" {
  action              = "ISOLATE"
  description         = "Example_Isolation_Policy"
  name                = "Example_Isolation_Policy"
  operator            = "AND"
  policy_type         = "5"

  conditions {
    operator = "OR"
    operands {
      object_type = "CLIENT_TYPE"
      lhs = "id"
      rhs = "zpn_client_type_exporter"
    }
  }
}
