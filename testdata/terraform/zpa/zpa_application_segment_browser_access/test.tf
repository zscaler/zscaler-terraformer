resource "zpa_application_segment_browser_access" "terraform_managed_resource" {
  bypass_type            = "NEVER"
  description            = "Created by Zscaler Deception. Do not edit"
  domain_names           = ["swift-35.securitygeek.io", "10.10.10.100"]
  double_encrypt         = false
  enabled                = true
  health_check_type      = "NONE"
  health_reporting       = "NONE"
  is_cname_enabled       = true
  name                   = "test name"
  passive_health_enabled = true
  segment_group_id       = "216196257331301307"
  segment_group_name     = "Zscaler Deception"
  tcp_port_ranges        = ["1", "52", "54", "65535"]
  udp_port_ranges        = ["1", "52", "54", "65535"]
  clientless_apps {
    application_port     = "443"
    application_protocol = "HTTPS"
    certificate_id       = "1"
    enabled              = false
    hidden               = false
    name                 = "test"
    trust_untrusted_cert = false
  }
  server_groups {
    id = ["216196257331301306"]
  }
  tcp_port_range {
    from = "443"
    to   = "443"
  }
}
