package cmd

import (
	"github.com/zscaler/zscaler-sdk-go/v2/zia"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/adminuserrolemgmt/admins"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/devicegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_engines"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_notification_templates"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlp_web_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/dlp/dlpdictionaries"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/filteringrules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipdestinationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/ipsourcegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkapplicationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservicegroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/networkservices"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/firewallpolicies/timewindow"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/forwarding_rules"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/location/locationgroups"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/location/locationmanagement"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/rule_labels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/sandbox/sandbox_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/security_policy_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/greinternalipranges"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/gretunnelinfo"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/gretunnels"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/staticips"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/virtualipaddress"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/trafficforwarding/vpncredentials"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlcategories"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/urlfilteringpolicies"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/user_authentication_settings"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/usermanagement/users"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegment"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentinspection"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/applicationsegmentpra"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/appservercontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/bacertificate"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/browseraccess"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudbrowserisolation/cbibannercontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudbrowserisolation/cbicertificatecontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudbrowserisolation/cbiprofilecontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/cloudconnectorgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/customerversionprofile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/enrollmentcert"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/idpcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_custom_controls"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_predefined_controls"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/inspectioncontrol/inspection_profile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/lssconfigcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/machinegroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/microtenants"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/policysetcontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/postureprofile"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/provisioningkey"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/samlattribute"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/scimattributeheader"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/scimgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/segmentgroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/servergroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/serviceedgecontroller"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/serviceedgegroup"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/trustednetwork"
)

type ZPAClient struct {
	appconnectorgroup              *appconnectorgroup.Service
	appconnectorcontroller         *appconnectorcontroller.Service
	applicationsegment             *applicationsegment.Service
	applicationsegmentpra          *applicationsegmentpra.Service
	applicationsegmentinspection   *applicationsegmentinspection.Service
	appservercontroller            *appservercontroller.Service
	bacertificate                  *bacertificate.Service
	cbibannercontroller            *cbibannercontroller.Service
	cbicertificatecontroller       *cbicertificatecontroller.Service
	cbiprofilecontroller           *cbiprofilecontroller.Service
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
	microtenants                   *microtenants.Service
}

type ZIAClient struct {
	admins                       *admins.Service
	filteringrules               *filteringrules.Service
	ipdestinationgroups          *ipdestinationgroups.Service
	ipsourcegroups               *ipsourcegroups.Service
	networkapplicationgroups     *networkapplicationgroups.Service
	networkservicegroups         *networkservicegroups.Service
	networkservices              *networkservices.Service
	timewindow                   *timewindow.Service
	urlcategories                *urlcategories.Service
	urlfilteringpolicies         *urlfilteringpolicies.Service
	users                        *users.Service
	gretunnels                   *gretunnels.Service
	gretunnelinfo                *gretunnelinfo.Service
	greinternalipranges          *greinternalipranges.Service
	staticips                    *staticips.Service
	virtualipaddress             *virtualipaddress.Service
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
	sandbox_settings             *sandbox_settings.Service
	user_authentication_settings *user_authentication_settings.Service
	forwarding_rules             *forwarding_rules.Service
	zpa_gateways                 *zpa_gateways.Service
}

type Client struct {
	zpa       *ZPAClient
	zia       *ZIAClient
	ZiaClient *zia.Client
	ZpaClient *zpa.Client
}
