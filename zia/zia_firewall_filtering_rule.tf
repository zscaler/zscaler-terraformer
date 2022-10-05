resource "zia_firewall_filtering_rule" "resource_default_firewall_filtering_rule_184222" {
  access_control      = "READ_WRITE"
  action              = "BLOCK_DROP"
  default_rule        = true
  enable_full_logging = false
  name                = "Default Firewall Filtering Rule"
  order               = -1
  predefined          = false
  rank                = 7
  state               = "ENABLED"
}

resource "zia_firewall_filtering_rule" "resource_office_365_one_click_rule_184226" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  dest_ip_categories  = ["OFFICE_365"]
  enable_full_logging = true
  name                = "Office 365 One Click Rule"
  order               = 2
  predefined          = true
  rank                = 7
  state               = "ENABLED"
}

resource "zia_firewall_filtering_rule" "resource_recommended_firewall_rule_184227" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  enable_full_logging = true
  name                = "Recommended Firewall Rule"
  order               = 6
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  nw_services {
    id = [774003, 774013, 774015]
  }
}

resource "zia_firewall_filtering_rule" "resource_allow_connection_to_pcoip__aws_413554" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  description         = "Allow connection to PCoIP - AWS"
  enable_full_logging = false
  name                = "Allow connection to PCoIP - AWS"
  order               = 5
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  dest_ip_groups {
    id = [1064383, 1064384]
  }
  nw_services {
    id = [1064420]
  }
}

resource "zia_firewall_filtering_rule" "resource_zscaler_proxy_traffic_413555" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  description         = "Zscaler Proxy Traffic"
  enable_full_logging = false
  name                = "Zscaler Proxy Traffic"
  order               = 3
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  nw_services {
    id = [774109]
  }
}

resource "zia_firewall_filtering_rule" "resource_ucaas_one_click_rule_449521" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  dest_ip_categories  = ["GLOBAL_INT_ZOOM"]
  enable_full_logging = false
  name                = "UCaaS One Click Rule"
  order               = 4
  predefined          = true
  rank                = 7
  state               = "ENABLED"
}

resource "zia_firewall_filtering_rule" "resource_testfwrulescr3t_454869" {
  access_control      = "READ_WRITE"
  action              = "ALLOW"
  default_rule        = false
  description         = "test-fw-rule-q03hc8rfg2lils3ccwfi"
  enable_full_logging = false
  name                = "test-fw-rule-scr3t"
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  departments {
    id = [25684245]
  }
  groups {
    id = [26231231]
  }
  nw_services {
    id = [774109]
  }
  time_windows {
    id = [552]
  }
}

