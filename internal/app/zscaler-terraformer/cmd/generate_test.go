package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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

var (
	// listOfString is an example representation of a key where the value is a
	// list of string values.
	//
	//   resource "example" "example" {
	//     attr = [ "b", "c", "d"]
	//   }
	listOfString = []interface{}{"b", "c", "d"}

	// configBlockOfStrings is an example of where a key is a "block" assignment
	// in HCL.
	//
	//   resource "example" "example" {
	//     attr = {
	//       c = "d"
	//       e = "f"
	//     }
	//   }
	configBlockOfStrings = map[string]interface{}{
		"c": "d",
		"e": "f",
	}
)

func TestGenerate_writeAttrLine(t *testing.T) {
	tests := map[string]struct {
		key   string
		value interface{}
		want  string
	}{
		"value is string":           {key: "a", value: "b", want: fmt.Sprintf("a = %q\n", "b")},
		"value is int":              {key: "a", value: 1, want: "a = 1\n"},
		"value is float":            {key: "a", value: 1.0, want: "a = 1\n"},
		"value is bool":             {key: "a", value: true, want: "a = true\n"},
		"value is list of strings":  {key: "a", value: listOfString, want: "a = [ \"b\", \"c\", \"d\" ]\n"},
		"value is block of strings": {key: "a", value: configBlockOfStrings, want: "a = {\nc = \"d\"\ne = \"f\"\n}\n"},
		"value is nil":              {key: "a", value: nil, want: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := writeAttrLine(tc.key, tc.value, false)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGenerate_ResourceNotSupported(t *testing.T) {
	viper.Set("zpa-terraform-install-path", "")
	viper.Set("zia-terraform-install-path", "")
	viper.Set("terraform-install-path", "../../../../testdata/testnotsupported/.")
	_, output, err := executeCommandC(rootCmd, "generate", "--resource-type", "zpa_notreal", "--verbose")

	if assert.Nil(t, err) {
		assert.Contains(t, output, "\"zpa_notreal\" is not yet supported for automatic generation")
	}
}

func TestResourceGeneration(t *testing.T) {
	tests := map[string]struct {
		identiferType    string
		resourceType     string
		testdataFilename string
	}{
		// ZPA Resource
		"zpa app connector group":                 {identiferType: "group", resourceType: "zpa_app_connector_group", testdataFilename: "zpa_app_connector_group"},
		"zpa application server":                  {identiferType: "server", resourceType: "zpa_application_server", testdataFilename: "zpa_application_server"},
		"zpa application segment":                 {identiferType: "appsegment", resourceType: "zpa_application_segment", testdataFilename: "zpa_application_segment"},
		"zpa application segment pra":             {identiferType: "appsegment", resourceType: "zpa_application_segment_pra", testdataFilename: "zpa_application_segment_pra"},
		"zpa application segment inspection":      {identiferType: "appsegment", resourceType: "zpa_application_segment_inspection", testdataFilename: "zpa_application_segment_inspection"},
		"zpa cloud browser isolation banner":      {identiferType: "isolation", resourceType: "zpa_cloud_browser_isolation_banner", testdataFilename: "zpa_cloud_browser_isolation_banner"},
		"zpa cloud browser isolation certificate": {identiferType: "isolation", resourceType: "zpa_cloud_browser_isolation_certificate", testdataFilename: "zpa_cloud_browser_isolation_certificate"},
		"zpa cloud browser isolation profile":     {identiferType: "isolation", resourceType: "zpa_cloud_browser_isolation_external_profile", testdataFilename: "zpa_cloud_browser_isolation_external_profile"},
		"zpa segment group":                       {identiferType: "group", resourceType: "zpa_segment_group", testdataFilename: "zpa_segment_group"},
		"zpa server group":                        {identiferType: "group", resourceType: "zpa_server_group", testdataFilename: "zpa_server_group"},
		"zpa application segment browser access":  {identiferType: "appsegment", resourceType: "zpa_application_segment_browser_access", testdataFilename: "zpa_application_segment_browser_access"},
		"zpa policy access rule":                  {identiferType: "policy", resourceType: "zpa_policy_access_rule", testdataFilename: "zpa_policy_access_rule"},
		"zpa policy inspection rule":              {identiferType: "policy", resourceType: "zpa_policy_inspection_rule", testdataFilename: "zpa_policy_inspection_rule"},
		"zpa policy timeout rule":                 {identiferType: "policy", resourceType: "zpa_policy_timeout_rule", testdataFilename: "zpa_policy_timeout_rule"},
		"zpa policy forwarding rule":              {identiferType: "policy", resourceType: "zpa_policy_forwarding_rule", testdataFilename: "zpa_policy_forwarding_rule"},
		"zpa policy isolation rule":               {identiferType: "policy", resourceType: "zpa_policy_isolation_rule", testdataFilename: "zpa_policy_isolation_rule"},
		"zpa provisioning key":                    {identiferType: "key", resourceType: "zpa_provisioning_key", testdataFilename: "zpa_provisioning_key"},
		"zpa service edge group":                  {identiferType: "group", resourceType: "zpa_service_edge_group", testdataFilename: "zpa_service_edge_group"},
		"zpa lss config controller":               {identiferType: "lss", resourceType: "zpa_lss_config_controller", testdataFilename: "zpa_lss_config_controller"},
		"zpa inspection custom controls":          {identiferType: "inspection", resourceType: "zpa_inspection_custom_controls", testdataFilename: "zpa_inspection_custom_controls"},
		"zpa inspection profile":                  {identiferType: "inspection", resourceType: "zpa_inspection_profile", testdataFilename: "zpa_inspection_profile"},
		"zpa microtenant controller":              {identiferType: "microtenant", resourceType: "zpa_microtenant_controller", testdataFilename: "zpa_microtenant_controller"},

		// ZIA Resource
		"zia admin users":                                   {identiferType: "users", resourceType: "zia_admin_users", testdataFilename: "zia_admin_users"},
		"zia dlp dictionaries":                              {identiferType: "dlp", resourceType: "zia_dlp_dictionaries", testdataFilename: "zia_dlp_dictionaries"},
		"zia dlp engines":                                   {identiferType: "dlp", resourceType: "zia_dlp_engines", testdataFilename: "zia_dlp_engines"},
		"zia dlp notification templates":                    {identiferType: "dlp", resourceType: "zia_dlp_notification_templates", testdataFilename: "zia_dlp_notification_templates"},
		"zia dlp web rules":                                 {identiferType: "dlp", resourceType: "zia_dlp_web_rules", testdataFilename: "zia_dlp_web_rules"},
		"zia firewall filtering rule":                       {identiferType: "rule", resourceType: "zia_firewall_filtering_rule", testdataFilename: "zia_firewall_filtering_rule"},
		"zia firewall filtering destination groups":         {identiferType: "rule", resourceType: "zia_firewall_filtering_destination_groups", testdataFilename: "zia_firewall_filtering_destination_groups"},
		"zia firewall filtering ip_source groups":           {identiferType: "rule", resourceType: "zia_firewall_filtering_ip_source_groups", testdataFilename: "zia_firewall_filtering_ip_source_groups"},
		"zia firewall filtering network service":            {identiferType: "rule", resourceType: "zia_firewall_filtering_network_service", testdataFilename: "zia_firewall_filtering_network_service"},
		"zia firewall filtering network service groups":     {identiferType: "rule", resourceType: "zia_firewall_filtering_network_service_groups", testdataFilename: "zia_firewall_filtering_network_service_groups"},
		"zia firewall filtering network application groups": {identiferType: "rule", resourceType: "zia_firewall_filtering_network_application_groups", testdataFilename: "zia_firewall_filtering_network_application_groups"},
		"zia traffic forwarding gre tunnel":                 {identiferType: "traffic", resourceType: "zia_traffic_forwarding_gre_tunnel", testdataFilename: "zia_traffic_forwarding_gre_tunnel"},
		"zia traffic forwarding static ip":                  {identiferType: "traffic", resourceType: "zia_traffic_forwarding_static_ip", testdataFilename: "zia_traffic_forwarding_static_ip"},
		"zia traffic forwarding vpn credentials":            {identiferType: "traffic", resourceType: "zia_traffic_forwarding_vpn_credentials", testdataFilename: "zia_traffic_forwarding_vpn_credentials"},
		"zia location management":                           {identiferType: "traffic", resourceType: "zia_location_management", testdataFilename: "zia_location_management"},
		"zia url categories":                                {identiferType: "url", resourceType: "zia_url_categories", testdataFilename: "zia_url_categories"},
		"zia url filtering rules":                           {identiferType: "url", resourceType: "zia_url_filtering_rules", testdataFilename: "zia_url_filtering_rules"},
		"zia user management":                               {identiferType: "users", resourceType: "zia_user_management", testdataFilename: "zia_user_management"},
		"zia rule labels":                                   {identiferType: "rule", resourceType: "zia_rule_labels", testdataFilename: "zia_rule_labels"},
		"zia auth settings urls":                            {identiferType: "auth", resourceType: "zia_auth_settings_urls", testdataFilename: "zia_auth_settings_urls"},
		"zia security settings":                             {identiferType: "security", resourceType: "zia_security_settings", testdataFilename: "zia_security_settings"},
		"zia forward control rule":                          {identiferType: "forward", resourceType: "zia_forwarding_control_rule", testdataFilename: "zia_forwarding_control_rule"},
		"zia zpa gateway":                                   {identiferType: "forward", resourceType: "zia_forwarding_control_zpa_gateway", testdataFilename: "zia_forwarding_control_zpa_gateway"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cloudType := "zpa"
			if strings.HasPrefix(tc.resourceType, "zia_") {
				cloudType = "zia"
			}
			viper.Set("zpa-terraform-install-path", "")
			viper.Set("zia-terraform-install-path", "")
			viper.Set("terraform-install-path", "../../../../testdata/terraform/"+cloudType+"/"+tc.resourceType+"/")
			r, err := recorder.New("../../../../testdata/" + cloudType + "/" + tc.testdataFilename)
			if err != nil {
				log.Fatal(err)
			}
			defer func() {
				_ = r.Stop()
			}()
			r.AddFilter(func(i *cassette.Interaction) error {
				delete(i.Request.Headers, "Authorization")
				i.Request.Form.Del("client_id")
				i.Request.Form.Del("client_secret")
				return nil
			})

			output := ""

			api = createClientMock(r, tc.resourceType, viper.GetString("zpaClientID"), viper.GetString("zpaClientSecret"), viper.GetString("zpaCustomerID"), viper.GetString("zpaCloud"), viper.GetString("ziaUsername"), viper.GetString("ziaPassword"), viper.GetString("ziaApiKey"), viper.GetString("ziaCloud"))
			_, output, _ = executeCommandC(rootCmd, "generate", "--resource-type", tc.resourceType, "--verbose")

			expected := testDataFile(tc.testdataFilename, cloudType)
			assert.Equal(t, strings.TrimRight(expected, "\n"), strings.TrimRight(output, "\n"))
		})
	}
}

func createClientMock(r http.RoundTripper, resourceType, zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud, ziaUsername, ziaPassword, ziaApiKey, ziaCloud string) *Client {
	var cli *Client
	if strings.HasPrefix(resourceType, "zpa_") {
		zpaConfig, err := zpa.NewConfig(zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud, "zscaler-terraformer")
		if err != nil {
			log.Fatal("failed to initialize mock zscaler-sdk-go (zpa)", err)
		}
		zpaClient := zpa.NewClient(zpaConfig)
		zpaClient.Config.GetHTTPClient().Transport = r
		cli = &Client{
			ZpaClient: zpaClient,
			zpa: &ZPAClient{
				appconnectorgroup:              appconnectorgroup.New(zpaClient),
				appconnectorcontroller:         appconnectorcontroller.New(zpaClient),
				applicationsegment:             applicationsegment.New(zpaClient),
				applicationsegmentpra:          applicationsegmentpra.New(zpaClient),
				applicationsegmentinspection:   applicationsegmentinspection.New(zpaClient),
				cbibannercontroller:            cbibannercontroller.New(zpaClient),
				cbicertificatecontroller:       cbicertificatecontroller.New(zpaClient),
				cbiprofilecontroller:           cbiprofilecontroller.New(zpaClient),
				appservercontroller:            appservercontroller.New(zpaClient),
				bacertificate:                  bacertificate.New(zpaClient),
				cloudconnectorgroup:            cloudconnectorgroup.New(zpaClient),
				customerversionprofile:         customerversionprofile.New(zpaClient),
				enrollmentcert:                 enrollmentcert.New(zpaClient),
				idpcontroller:                  idpcontroller.New(zpaClient),
				lssconfigcontroller:            lssconfigcontroller.New(zpaClient),
				machinegroup:                   machinegroup.New(zpaClient),
				postureprofile:                 postureprofile.New(zpaClient),
				policysetcontroller:            policysetcontroller.New(zpaClient),
				provisioningkey:                provisioningkey.New(zpaClient),
				samlattribute:                  samlattribute.New(zpaClient),
				scimgroup:                      scimgroup.New(zpaClient),
				scimattributeheader:            scimattributeheader.New(zpaClient),
				segmentgroup:                   segmentgroup.New(zpaClient),
				servergroup:                    servergroup.New(zpaClient),
				serviceedgegroup:               serviceedgegroup.New(zpaClient),
				serviceedgecontroller:          serviceedgecontroller.New(zpaClient),
				trustednetwork:                 trustednetwork.New(zpaClient),
				browseraccess:                  browseraccess.New(zpaClient),
				inspection_custom_controls:     inspection_custom_controls.New(zpaClient),
				inspection_predefined_controls: inspection_predefined_controls.New(zpaClient),
				inspection_profile:             inspection_profile.New(zpaClient),
				microtenants:                   microtenants.New(zpaClient),
			},
		}
	} else if strings.HasPrefix(resourceType, "zia_") {
		// init zia
		ziaClient, err := zia.NewClient(ziaUsername, ziaPassword, ziaApiKey, ziaCloud, "zscaler-terraformer")
		if err != nil {
			log.Fatal("failed to initialize mock zscaler-sdk-go (zia)", err)
		}
		ziaClient.HTTPClient.Transport = r
		cli = &Client{
			ZiaClient: ziaClient,
			zia: &ZIAClient{
				admins:                       admins.New(ziaClient),
				filteringrules:               filteringrules.New(ziaClient),
				ipdestinationgroups:          ipdestinationgroups.New(ziaClient),
				ipsourcegroups:               ipsourcegroups.New(ziaClient),
				networkapplicationgroups:     networkapplicationgroups.New(ziaClient),
				networkservicegroups:         networkservicegroups.New(ziaClient),
				networkservices:              networkservices.New(ziaClient),
				timewindow:                   timewindow.New(ziaClient),
				urlcategories:                urlcategories.New(ziaClient),
				urlfilteringpolicies:         urlfilteringpolicies.New(ziaClient),
				virtualipaddress:             virtualipaddress.New(ziaClient),
				vpncredentials:               vpncredentials.New(ziaClient),
				gretunnels:                   gretunnels.New(ziaClient),
				gretunnelinfo:                gretunnelinfo.New(ziaClient),
				greinternalipranges:          greinternalipranges.New(ziaClient),
				staticips:                    staticips.New(ziaClient),
				locationmanagement:           locationmanagement.New(ziaClient),
				locationgroups:               locationgroups.New(ziaClient),
				devicegroups:                 devicegroups.New(ziaClient),
				dlpdictionaries:              dlpdictionaries.New(ziaClient),
				dlp_engines:                  dlp_engines.New(ziaClient),
				dlp_notification_templates:   dlp_notification_templates.New(ziaClient),
				dlp_web_rules:                dlp_web_rules.New(ziaClient),
				rule_labels:                  rule_labels.New(ziaClient),
				security_policy_settings:     security_policy_settings.New(ziaClient),
				user_authentication_settings: user_authentication_settings.New(ziaClient),
				users:                        users.New(ziaClient),
				forwarding_rules:             forwarding_rules.New(ziaClient),
				zpa_gateways:                 zpa_gateways.New(ziaClient),
			},
		}
	}
	return cli
}
