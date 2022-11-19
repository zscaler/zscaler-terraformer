resource "zia_admin_users" "terraform_managed_resource" {
  comments                        = "Administrator Group"
  email                           = "john.smith@securitygeek.io"
  is_password_login_allowed       = true
  is_product_update_comm_enabled  = true
  is_security_report_comm_enabled = true
  is_service_update_comm_enabled  = true
  login_name                      = "john.smith@securitygeek.io"
  username                        = "John Smith"
  admin_scope {
    type = "DEPARTMENT"
    scope_entities {
      id = [25684245]
    }
  }
  role {
    id = 11521
  }
}
