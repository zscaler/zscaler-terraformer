resource "zpa_server_group" "terraform_managed_resource" {
  config_space      = "DEFAULT"
  description       = "Automatically created by Zscaler Deception API for whiskeygolf"
  dynamic_discovery = true
  enabled           = true
  ip_anchored       = false
  name              = "test name"
  app_connector_groups {
    id = ["216196257331301305"]
  }
  applications {
    id = ["216196257331301317"]
  }
}
