resource "zpa_inspection_custom_controls" "terraform_managed_resource" {
  action         = "PASS"
  default_action = "PASS"
  description    = "Example"
  name           = "Example"
  paranoia_level = "1"
  severity       = "CRITICAL"
  type           = "RESPONSE"
  associated_inspection_profile_names {
    id = ["1"]
  }
  rules {
    names = ["this"]
    type  = "RESPONSE_HEADERS"
    conditions {
      lhs = "SIZE"
      op  = "GE"
      rhs = "1000"
    }
  }
  rules {
    type = "RESPONSE_BODY"
    conditions {
      lhs = "SIZE"
      op  = "GE"
      rhs = "1000"
    }
  }
}