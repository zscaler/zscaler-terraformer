resource "zia_url_categories" "terraform_managed_resource" {
  configured_name                      = "MS Defender Unsanctioned Apps"
  custom_category                      = true
  custom_urls_count                    = 33
  db_categorized_urls                  = [".creditkarma.com", ".youku.com"]
  description                          = "MCAS Unsanctioned Apps"
  editable                             = true
  type                                 = "URL_CATEGORY"
  urls                                 = [".Logz.io",".aa.com",".accuweather.com",".agoda.com"]
  urls_retaining_parent_category_count = 2
}