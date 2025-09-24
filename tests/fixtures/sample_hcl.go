package fixtures

// Sample HCL content for testing

const SampleZIAFirewallRule = `# __generated__ by Zscaler Terraformer from Test_Rule
resource "zia_firewall_filtering_rule" "resource_zia_firewall_filtering_rule_1503414" {
  action              = "ALLOW"
  default_rule        = false
  enable_full_logging = false
  name                = "Test_Rule"
  order               = 4
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  dest_ip_groups {
    id = [9883111]
  }
  labels {
    id = [2764153]
  }
  nw_application_groups {
    id = [9241720]
  }
  nw_service_groups {
    id = [9241723]
  }
  nw_services {
    id = [774089]
  }
  src_ip_groups {
    id = [9881286]
  }
  workload_groups {
    id   = 2665545
    name = "BD_WORKLOAD_GROUP01"
  }
}`

const SampleZPAApplicationSegment = `# __generated__ by Zscaler Terraformer from Test_App_Segment
resource "zpa_application_segment" "resource_zpa_application_segment_72058304855047123" {
  name                     = "Test_App_Segment"
  description              = "Test Application Segment"
  enabled                  = true
  health_reporting         = "ON_ACCESS"
  bypass_type              = "NEVER"
  is_cname_enabled         = true
  tcp_port_range {
    from = "80"
    to   = "80"
  }
  udp_port_range {
    from = "80"
    to   = "80"
  }
  segment_group_id = "72058304855047456"
  server_groups {
    id = ["72058304855047789", "72058304855047790"]
  }
  app_connector_groups {
    id = ["72058304855047100", "72058304855047101"]
  }
}`

const SampleZPAPolicyRule = `resource "zpa_policy_access_rule" "test_policy" {
  name = "Test Policy"
  conditions {
    operator = "OR"
    operands {
      idp_id = "216196257331285825"
      lhs = "216196257331285828"
      name = "Email_SGIO-User-Okta"
      object_type = "SAML"
      rhs = "wguilherme@securitygeek.io"
    }
  }
}`

const SampleExpectedDataSource = `# Data sources for attribute ID references
# Generated automatically by Zscaler Terraformer

data "zia_firewall_filtering_ip_source_groups" "this_9881286" {
  id = "9881286"
}

data "zia_firewall_filtering_destination_groups" "this_9883111" {
  id = "9883111"
}

data "zia_rule_labels" "this_2764153" {
  id = "2764153"
}

data "zia_workload_groups" "this_2665545" {
  id   = "2665545"
  name = "BD_WORKLOAD_GROUP01"
}`

const SampleOutputsFile = `output "zia_location_groups_resource_zia_location_groups_123456_id" {
  value = "${zia_location_groups.resource_zia_location_groups_123456.id}"
}

output "zia_device_groups_resource_zia_device_groups_789012_id" {
  value = "${zia_device_groups.resource_zia_device_groups_789012.id}"
}`

// API Error Response samples for testing
const SampleLicenseError = `{
  "code": null,
  "message": "",
  "id": "authz.featureflag.permission.denied",
  "reason": "Feature flag feature.ddil.config disabled for customer 216,196,257,331,281,920",
  "url": "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/216196257331281920/privateCloudControllerGroup?page=1&pagesize=500",
  "status": 401
}`

const SampleRegularAPIError = `{
  "code": "INVALID_REQUEST",
  "message": "Invalid request parameters",
  "id": "request.validation.failed",
  "reason": "The provided request is invalid"
}`

const SampleValidTerraformOutput = `Success! The configuration is valid.`

const SampleInvalidTerraformOutput = `Error: Unclosed configuration block

  on zpa_segment_group.tf line 16, in resource "zpa_segment_group" "resource_zpa_segment_group_216196257331370167":
  16: resource "zpa_segment_group" "resource_zpa_segment_group_216196257331370167" {

There is no closing brace for this block before the end of the file. This may
be caused by incorrect brace nesting elsewhere in this file.`
