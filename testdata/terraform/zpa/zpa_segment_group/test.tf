resource "zpa_segment_group" "terraform_managed_resource" {
  description            = "Automatically created by Zscaler Deception API for whiskeygolf"
  enabled                = true
  name                   = "test name"
  policy_migrated        = true
  tcp_keep_alive_enabled = "0"
  applications {
    id = "216196257331301317"
  }
}