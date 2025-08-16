# __generated__ by Zscaler Terraformer from NewRule 2209 test
resource "zia_dlp_web_rules" "resource_zia_dlp_web_rules_1112360" {
  action                     = "ALLOW"
  description                = <<EOT
Google Finance
123.5.5.6 &*& ^ & && kjsdhfs
123.5.5.6 &*& ^ & && kjsdhfs
C13259587 - Enable HTTP/2 support in SSL inspection policy for test AD group NT0001\fP-CLD-XQZS-A0-01
C13259587 - Enable HTTP/2 support in AD group NT0001\fP-CLD-XQZS-A0-01
EOT
  dlp_download_scan_enabled  = false
  inspect_http_get_enabled   = false
  match_only                 = false
  name                       = "NewRule 2209 test"
  order                      = 1
  protocols                  = ["FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  severity                   = "RULE_SEVERITY_HIGH"
  state                      = "ENABLED"
  user_risk_score_levels     = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  without_content_inspection = false
  zcc_notifications_enabled  = false
  zscaler_incident_receiver  = false
  dlp_engines {
    id = [63, 62]
  }
  location_groups {
    id = [8061255]
  }
  locations {
    id = [22735190]
  }
  source_ip_groups {
    id = [18448894]
  }
  url_categories {
    id = [2, 6, 7]
  }
  workload_groups {
    id   = 17811899
    name = "BD_WORKLOAD_GROUP01"
  }
  workload_groups {
    id   = 17866268
    name = "BD_WORKLOAD_GROUP02"
  }
}

