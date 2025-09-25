package fixtures

// Mock API response data for testing.

// ZPA API Responses.
const ZPAAppConnectorGroupResponse = `[
  {
    "id": "72058304855047746",
    "name": "Test-App-Connector-Group",
    "description": "Test App Connector Group",
    "enabled": true,
    "cityCountry": "San Jose, US",
    "countryCode": "US",
    "latitude": "37.4181643",
    "longitude": "-121.9531325",
    "location": "San Jose, CA, USA",
    "upgradeDay": "SUNDAY",
    "upgradeTimeInSecs": "66600",
    "overrideVersionProfile": true,
    "versionProfileId": "2",
    "versionProfileName": "New Release"
  }
]`

const ZPAApplicationSegmentResponse = `[
  {
    "id": "72058304855047123",
    "name": "Test_App_Segment", 
    "description": "Test Application Segment",
    "enabled": true,
    "healthReporting": "ON_ACCESS",
    "bypassType": "NEVER",
    "isCnameEnabled": true,
    "segmentGroupId": "72058304855047456",
    "serverGroups": [
      {"id": "72058304855047789"},
      {"id": "72058304855047790"}
    ],
    "appConnectorGroups": [
      {"id": "72058304855047100"},
      {"id": "72058304855047101"}
    ]
  }
]`

const ZPALicenseErrorResponse = `{
  "code": null,
  "message": "",
  "id": "authz.featureflag.permission.denied",
  "reason": "Feature flag feature.ddil.config disabled for customer 216,196,257,331,281,920",
  "url": "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/216196257331281920/privateCloudControllerGroup?page=1&pagesize=500",
  "status": 401
}`

// ZIA API Responses.
const ZIAFirewallRuleResponse = `[
  {
    "id": 1503414,
    "name": "Test_Firewall_Rule",
    "action": "ALLOW",
    "state": "ENABLED",
    "order": 4,
    "rank": 7,
    "defaultRule": false,
    "predefined": false,
    "enableFullLogging": false,
    "srcIpGroups": [{"id": 9881286}],
    "destIpGroups": [{"id": 9883111}],
    "nwServices": [{"id": 774089}],
    "labels": [{"id": 2764153}]
  }
]`

const ZIALocationGroupResponse = `[
  {
    "id": 123456,
    "name": "Test Location Group",
    "description": "Test location group for testing",
    "locations": [
      {"id": 789012, "name": "San Jose Office"},
      {"id": 789013, "name": "New York Office"}
    ]
  }
]`

const ZIAAPIErrorResponse = `{
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded. Please try again later.",
  "timestamp": "2025-09-22T21:45:30Z"
}`

// Expected HCL Output.
const ExpectedZPAApplicationSegmentHCL = `# __generated__ by Zscaler Terraformer from Test_App_Segment
resource "zpa_application_segment" "resource_zpa_application_segment_72058304855047123" {
  name                     = "Test_App_Segment"
  description              = "Test Application Segment"
  enabled                  = true
  health_reporting         = "ON_ACCESS"
  bypass_type              = "NEVER"
  is_cname_enabled         = true
  segment_group_id = data.zpa_segment_group.this_72058304855047456.id
  server_groups {
    id = [data.zpa_server_group.this_72058304855047789.id, data.zpa_server_group.this_72058304855047790.id]
  }
  app_connector_groups {
    id = [data.zpa_app_connector_group.this_72058304855047100.id, data.zpa_app_connector_group.this_72058304855047101.id]
  }
}`

const ExpectedZIAFirewallRuleHCL = `# __generated__ by Zscaler Terraformer from Test_Firewall_Rule
resource "zia_firewall_filtering_rule" "resource_zia_firewall_filtering_rule_1503414" {
  action              = "ALLOW"
  default_rule        = false
  enable_full_logging = false
  name                = "Test_Firewall_Rule"
  order               = 4
  predefined          = false
  rank                = 7
  state               = "ENABLED"
  dest_ip_groups {
    id = [data.zia_firewall_filtering_destination_groups.this_9883111.id]
  }
  labels {
    id = [data.zia_rule_labels.this_2764153.id]
  }
  nw_services {
    id = [data.zia_firewall_filtering_network_service.this_774089.id]
  }
  src_ip_groups {
    id = [data.zia_firewall_filtering_ip_source_groups.this_9881286.id]
  }
}`

// Provider Configuration Templates.
const ZPAProviderConfig = `terraform {
  required_providers {
    zpa = {
      source = "zscaler/zpa"
      version = ">= 4.0.0"
    }
  }
}

provider "zpa" {
  # Configuration will be provided via environment variables
}`

const ZIAProviderConfig = `terraform {
  required_providers {
    zia = {
      source = "zscaler/zia"
      version = ">= 4.0.0"
    }
  }
}

provider "zia" {
  # Configuration will be provided via environment variables
}`
