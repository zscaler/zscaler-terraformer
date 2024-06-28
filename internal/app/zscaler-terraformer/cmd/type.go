package cmd

import (
	"github.com/zscaler/zscaler-sdk-go/v2/zia"
	ziaServices "github.com/zscaler/zscaler-sdk-go/v2/zia/services"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/usermanagement/users"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa"
	zpaServices "github.com/zscaler/zscaler-sdk-go/v2/zpa/services"
)

type ZPAClient struct {
	appconnectorgroup              *zpaServices.Service
	appconnectorcontroller         *zpaServices.Service
	applicationsegment             *zpaServices.Service
	applicationsegmentinspection   *zpaServices.Service
	applicationsegmentpra          *zpaServices.Service
	appservercontroller            *zpaServices.Service
	browseraccess                  *zpaServices.Service
	bacertificate                  *zpaServices.Service
	lssconfigcontroller            *zpaServices.Service
	policysetcontroller            *zpaServices.Service
	policysetcontrollerv2          *zpaServices.Service
	pracredential                  *zpaServices.Service
	praportal                      *zpaServices.Service
	provisioningkey                *zpaServices.Service
	segmentgroup                   *zpaServices.Service
	servergroup                    *zpaServices.Service
	serviceedgegroup               *zpaServices.Service
	serviceedgecontroller          *zpaServices.Service
	inspection_custom_controls     *zpaServices.Service
	inspection_predefined_controls *zpaServices.Service
	inspection_profile             *zpaServices.Service
	microtenants                   *zpaServices.Service
}

type ZIAClient struct {
	admins                       *ziaServices.Service
	filteringrules               *ziaServices.Service
	ipdestinationgroups          *ziaServices.Service
	ipsourcegroups               *ziaServices.Service
	networkapplicationgroups     *ziaServices.Service
	networkservicegroups         *ziaServices.Service
	networkservices              *ziaServices.Service
	urlcategories                *ziaServices.Service
	urlfilteringpolicies         *ziaServices.Service
	users                        *users.Service
	gretunnels                   *ziaServices.Service
	staticips                    *ziaServices.Service
	vpncredentials               *ziaServices.Service
	locationmanagement           *ziaServices.Service
	dlpdictionaries              *ziaServices.Service
	dlp_engines                  *ziaServices.Service
	dlp_notification_templates   *ziaServices.Service
	dlp_web_rules                *ziaServices.Service
	rule_labels                  *ziaServices.Service
	security_policy_settings     *ziaServices.Service
	sandbox_settings             *ziaServices.Service
	user_authentication_settings *ziaServices.Service
	forwarding_rules             *ziaServices.Service
	zpa_gateways                 *zpa_gateways.Service
}

type Client struct {
	zpa       *ZPAClient
	zia       *ZIAClient
	ZiaClient *zia.Client
	ZpaClient *zpa.Client
}
