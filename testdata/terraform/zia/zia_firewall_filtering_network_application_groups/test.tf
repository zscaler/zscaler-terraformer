resource "zia_firewall_filtering_network_application_groups" "terraform_managed_resource" {
  description          = "Microsoft Office365"
  name                 = "Microsoft Office365"
  network_applications = ["YAMMER", "OFFICE365", "SKYPE_FOR_BUSINESS", "OUTLOOK", "SHAREPOINT", "SHAREPOINT_ADMIN", "SHAREPOINT_BLOG", "SHAREPOINT_CALENDAR", "SHAREPOINT_DOCUMENT", "SHAREPOINT_ONLINE", "ONEDRIVE"]
}