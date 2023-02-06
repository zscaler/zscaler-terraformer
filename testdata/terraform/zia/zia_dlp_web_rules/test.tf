resource "zia_dlp_web_rules" "terraform_managed_resource" {
  action                    = "ALLOW"
  cloud_applications        = ["BOXNET", "AMAZONDRIVE", "BITPORT_IO"]
  description               = "Test"
  file_types                = ["PYTHON", "BASH_SCRIPTS", "SQL"]
  name                      = "DLP PCI Rule-1"
  order                     = 3
  protocols                 = ["HTTPS_RULE", "HTTP_RULE"]
  rank                      = 7
  state                     = "DISABLED"
  zscaler_incident_reciever = true
  departments {
    id = [25684245, 29485508, 25658545]
  }
  dlp_engines {
    id = [61]
  }
  groups {
    id = [24392492, 26231231, 25684251]
  }
  location_groups {
    id = [24326828]
  }
  locations {
    id = [43966027, 36788696]
  }
  url_categories {
    id = [10, 11]
  }
  users {
    id = [29309057, 29306493, 29309058]
  }
}
