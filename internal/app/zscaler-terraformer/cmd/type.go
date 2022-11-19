package cmd

import (
	"github.com/zscaler/zscaler-sdk-go/zia"
	"github.com/zscaler/zscaler-sdk-go/zia/services/adminuserrolemgmt"
	"github.com/zscaler/zscaler-sdk-go/zia/services/devicegroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/zia/services/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/networkapplications"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/zia/services/firewallpolicies/timewindow"
	"github.com/zscaler/zscaler-sdk-go/zia/services/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/zia/services/locationmanagement/locationgroups"
	"github.com/zscaler/zscaler-sdk-go/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/greinternalipranges"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/gretunnelinfo"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/virtualipaddresslist"
	"github.com/zscaler/zscaler-sdk-go/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/zia/services/usermanagement"
	"github.com/zscaler/zscaler-sdk-go/zpa"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/browseraccess"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/cloudconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/customerversionprofile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/enrollmentcert"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_predefined_controls"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/inspectioncontrol/inspection_profile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/machinegroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/samlattribute"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/serviceedgecontroller"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-sdk-go/zpa/services/trustednetwork"
)

type ZPAClient struct {
	appconnectorgroup              *appconnectorgroup.Service
	appconnectorcontroller         *appconnectorcontroller.Service
	applicationsegment             *applicationsegment.Service
	applicationsegmentpra          *applicationsegmentpra.Service
	applicationsegmentinspection   *applicationsegmentinspection.Service
	appservercontroller            *appservercontroller.Service
	bacertificate                  *bacertificate.Service
	cloudconnectorgroup            *cloudconnectorgroup.Service
	customerversionprofile         *customerversionprofile.Service
	enrollmentcert                 *enrollmentcert.Service
	idpcontroller                  *idpcontroller.Service
	lssconfigcontroller            *lssconfigcontroller.Service
	machinegroup                   *machinegroup.Service
	postureprofile                 *postureprofile.Service
	policysetcontroller            *policysetcontroller.Service
	provisioningkey                *provisioningkey.Service
	samlattribute                  *samlattribute.Service
	scimgroup                      *scimgroup.Service
	scimattributeheader            *scimattributeheader.Service
	segmentgroup                   *segmentgroup.Service
	servergroup                    *servergroup.Service
	serviceedgegroup               *serviceedgegroup.Service
	serviceedgecontroller          *serviceedgecontroller.Service
	trustednetwork                 *trustednetwork.Service
	browseraccess                  *browseraccess.Service
	inspection_custom_controls     *inspection_custom_controls.Service
	inspection_predefined_controls *inspection_predefined_controls.Service
	inspection_profile             *inspection_profile.Service
}

type ZIAClient struct {
	adminuserrolemgmt            *adminuserrolemgmt.Service
	filteringrules               *filteringrules.Service
	ipdestinationgroups          *ipdestinationgroups.Service
	ipsourcegroups               *ipsourcegroups.Service
	networkapplications          *networkapplications.Service
	networkservices              *networkservices.Service
	timewindow                   *timewindow.Service
	urlcategories                *urlcategories.Service
	urlfilteringpolicies         *urlfilteringpolicies.Service
	usermanagement               *usermanagement.Service
	gretunnels                   *gretunnels.Service
	gretunnelinfo                *gretunnelinfo.Service
	greinternalipranges          *greinternalipranges.Service
	staticips                    *staticips.Service
	virtualipaddresslist         *virtualipaddresslist.Service
	vpncredentials               *vpncredentials.Service
	locationmanagement           *locationmanagement.Service
	locationgroups               *locationgroups.Service
	devicegroups                 *devicegroups.Service
	dlpdictionaries              *dlpdictionaries.Service
	dlp_engines                  *dlp_engines.Service
	dlp_notification_templates   *dlp_notification_templates.Service
	dlp_web_rules                *dlp_web_rules.Service
	rule_labels                  *rule_labels.Service
	security_policy_settings     *security_policy_settings.Service
	user_authentication_settings *user_authentication_settings.Service
}

type Client struct {
	zpa       *ZPAClient
	zia       *ZIAClient
	ZiaClient *zia.Client
	ZpaClient *zpa.Client
}
