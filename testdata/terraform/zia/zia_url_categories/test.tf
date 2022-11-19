resource "zia_url_categories" "terraform_managed_resource" {
  custom_category                      = false
  description                          = "OTHER_ADULT_MATERIAL_DESC"
  editable                             = true
  super_category                       = "USER_DEFINED"
  type                                 = "URL_CATEGORY"
  urls_retaining_parent_category_count = 0
}