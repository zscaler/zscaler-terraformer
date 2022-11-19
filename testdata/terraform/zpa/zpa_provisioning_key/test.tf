resource "zpa_provisioning_key" "terraform_managed_resource" {
  association_type   = "CONNECTOR_GRP"
  enabled            = true
  enrollment_cert_id = "6573"
  max_usage          = "10"
  name               = "New York Provisioning Key"
  usage_count        = "0"
  zcomponent_id      = "216196257331307781"
  zcomponent_name    = "App Connector Group New York"
}