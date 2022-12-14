resource "zpa_application_segment_browser_access" "terraform_managed_resource" {
  bypass_type            = "NEVER"
  config_space           = "DEFAULT"
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
    allow_options        = false
    application_port     = "80"
    application_protocol = "HTTP"
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
    from = "1"
    to   = "52"
  }
  tcp_port_range {
    from = "54"
    to   = "65535"
  }
  udp_port_range {
    from = "1"
    to   = "52"
  }
  udp_port_range {
    from = "54"
    to   = "65535"
  }
}
