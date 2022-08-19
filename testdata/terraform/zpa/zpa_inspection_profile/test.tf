resource "zpa_inspection_profile" "terraform_managed_resource" {
  common_global_override_actions_config = {
    IS_OVERRIDE_ACTION_COMMON  = "TRUE"
    PREDEF_CNTRL_GLOBAL_ACTION = "PASS"
  }
  description            = "Example"
  global_control_actions = ["CUSTOM:NONE", "PREDEFINED:PASS", "OVERRIDE_ACTION:COMMON"]
  incarnation_number     = "1"
  name                   = "Example"
  paranoia_level         = "2"
  controls_info {
    control_type = "PREDEFINED"
    count        = "7"
  }
}
