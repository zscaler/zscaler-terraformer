resource "zia_firewall_filtering_destination_groups" "terraform_managed_resource" {
  addresses   = ["drp-icn.amazonworkspaces.com", "drp-pdt.amazonworkspaces.com", "drp-bom.amazonworkspaces.com", "drp-pdx.amazonworkspaces.com", "drp-iad.amazonworkspaces.com", "drp-yul.amazonworkspaces.com", "drp-gru.amazonworkspaces.com", "drp-lhr.amazonworkspaces.com", "drp-dub.amazonworkspaces.com", "drp-fra.amazonworkspaces.com", "drp-nrt.amazonworkspaces.com", "drp-syd.amazonworkspaces.com", "drp-sin.amazonworkspaces.com"]
  description = "AWS Workspaces - Health Check Servers"
  name        = "AWS Workspaces - Health Check Servers"
  type        = "DSTN_FQDN"
}