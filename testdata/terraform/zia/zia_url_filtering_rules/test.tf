resource "zia_url_filtering_rules" "terraform_managed_resource" {
  action                = "BLOCK"
  block_override        = false
  description           = "Block all inappropriate content for all users."
  name                  = "Block Inappropriate Content"
  order                 = 1
  protocols             = ["ANY_RULE"]
  rank                  = 7
  request_methods       = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "OTHER"]
  state                 = "ENABLED"
  url_categories        = ["OTHER_ADULT_MATERIAL", "ADULT_THEMES", "LINGERIE_BIKINI", "NUDITY", "PORNOGRAPHY", "SEXUALITY", "ADULT_SEX_EDUCATION", "K_12_SEX_EDUCATION", "OTHER_DRUGS", "GAMBLING", "OTHER_ILLEGAL_OR_QUESTIONABLE", "COPYRIGHT_INFRINGEMENT", "COMPUTER_HACKING", "QUESTIONABLE", "PROFANITY", "MATURE_HUMOR", "ANONYMIZER", "SOCIAL_ADULT"]
}