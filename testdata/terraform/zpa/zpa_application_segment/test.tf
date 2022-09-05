resource "zpa_application_segment" "terraform_managed_resource" {
  bypass_type                   = "NEVER"
  config_space                  = "DEFAULT"
  domain_names                  = ["test.acme.com"]
  double_encrypt                = false
  enabled                       = true
  health_check_type             = "DEFAULT"
  health_reporting              = "ON_ACCESS"
  icmp_access_type              = "NONE"
  ip_anchored                   = false
  is_cname_enabled              = true
  name                          = "Example"
  passive_health_enabled        = true
  segment_group_id              = "216196257331307750"
  segment_group_name            = "Example"
  tcp_port_range = [
    {
      from = "80"
      to   = "80"
    }
  ]
  server_groups {
    id = ["216196257331307753"]
  }
}