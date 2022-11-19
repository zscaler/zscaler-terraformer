resource "zia_user_management" "terraform_managed_resource" {
  email = "test@securitygeek.io"
  name  = "test"
  department {
    id   = 25658545
    name = "Finance"
  }
  groups {
    id = [26231231, 24392492]
  }
}