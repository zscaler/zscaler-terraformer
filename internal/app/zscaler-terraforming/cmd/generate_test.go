package cmd

/*
import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/dnaeon/go-vcr/cassette"
	"github.com/dnaeon/go-vcr/recorder"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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

	cloudflareTestZoneID    = "0da42c8d2132a9ddaf714f9e7c920711"
	cloudflareTestAccountID = "f037e56e89293a057740de681ac9abbe"
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
	_, output, err := executeCommandC(rootCmd, "generate", "--resource-type", "notreal")

	if assert.Nil(t, err) {
		assert.Contains(t, output, "\"notreal\" is not yet supported for automatic generation")
	}
}

func TestResourceGeneration(t *testing.T) {
	tests := map[string]struct {
		identiferType    string
		resourceType     string
		testdataFilename string
	}{
		// ZPA Resource
		"zpa app connector group":            {identiferType: "group", resourceType: "zpa_app_connector_group", testdataFilename: "zpa_app_connector_group"},
		"zpa application server":             {identiferType: "server", resourceType: "zpa_application_server", testdataFilename: "zpa_application_server"},
		"zpa application segment":            {identiferType: "appsegment", resourceType: "zpa_application_segment", testdataFilename: "zpa_application_segment"},
		"zpa application segment pra":        {identiferType: "appsegment", resourceType: "zpa_application_segment_pra", testdataFilename: "zpa_application_segment_pra"},
		"zpa application segment inspection": {identiferType: "appsegment", resourceType: "zpa_application_segment_inspection", testdataFilename: "zpa_application_segment"},
		"zpa segment group":                  {identiferType: "group", resourceType: "zpa_segment_group", testdataFilename: "zpa_segment_group"},
		"zpa server group":                   {identiferType: "group", resourceType: "zpa_server_group", testdataFilename: "zpa_server_group"},
		"zpa browser access":                 {identiferType: "appsegment", resourceType: "zpa_browser_access", testdataFilename: "zpa_browser_access"},
		"zpa policy access rule":             {identiferType: "policy", resourceType: "zpa_policy_access_rule", testdataFilename: "zpa_policy_access_rule"},
		"zpa policy inspection rule":         {identiferType: "policy", resourceType: "zpa_policy_inspection_rule", testdataFilename: "zpa_policy_inspection_rule"},
		"zpa policy timeout rule":            {identiferType: "policy", resourceType: "zpa_policy_timeout_rule", testdataFilename: "zpa_policy_timeout_rule"},
		"zpa policy forwarding rule":         {identiferType: "policy", resourceType: "zpa_policy_forwarding_rule", testdataFilename: "zpa_policy_forwarding_rule"},
		"zpa provisioning key":               {identiferType: "key", resourceType: "zpa_provisioning_key", testdataFilename: "zpa_provisioning_key"},
		"zpa service edge group":             {identiferType: "group", resourceType: "zpa_service_edge_group", testdataFilename: "zpa_service_edge_group"},
		"zpa lss config controller":          {identiferType: "lss", resourceType: "zpa_lss_config_controller", testdataFilename: "zpa_lss_config_controller"},
		"zpa inspection custom controls":     {identiferType: "inspection", resourceType: "zpa_inspection_custom_controls", testdataFilename: "zpa_inspection_custom_controls"},
		"zpa inspection profile":             {identiferType: "inspection", resourceType: "zpa_inspection_profile", testdataFilename: "zpa_inspection_profile"},

		// ZIA Resource
		"zia admin users":                                   {identiferType: "users", resourceType: "zia_admin_users", testdataFilename: "zia_admin_users"},
		"zia dlp dictionaries":                              {identiferType: "dlp", resourceType: "zia_dlp_dictionaries", testdataFilename: "zia_dlp_dictionaries"},
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
		"zia activation status":                             {identiferType: "activation", resourceType: "zia_activation_status", testdataFilename: "zia_activation_status"},
		"zia rule labels":                                   {identiferType: "rule", resourceType: "zia_rule_labels", testdataFilename: "zia_rule_labels"},
		"zia auth settings urls":                            {identiferType: "auth", resourceType: "zia_auth_settings_urls", testdataFilename: "zia_auth_settings_urls"},
		"zia security settings":                             {identiferType: "security", resourceType: "zia_security_settings", testdataFilename: "zia_security_settings"},
	}

	for name, tc := range tests {

		t.Run(name, func(t *testing.T) {
			// Reset the environment variables used in test to ensure we don't
			// have both present at once.
			viper.Set("zone", "")
			viper.Set("account", "")

			r, err := recorder.New("../../../../testdata/zpa/" + tc.testdataFilename)
			if err != nil {
				log.Fatal(err)
			}
			defer r.Stop()

			r.AddFilter(func(i *cassette.Interaction) error {
				delete(i.Request.Headers, "X-Auth-Email")
				delete(i.Request.Headers, "X-Auth-Key")
				delete(i.Request.Headers, "Authorization")
				return nil
			})

			output := ""

			if tc.identiferType == "account" {
				viper.Set("account", cloudflareTestAccountID)
				api, _ = cloudflare.New(viper.GetString("key"), viper.GetString("email"), cloudflare.HTTPClient(
					&http.Client{
						Transport: r,
					},
				), cloudflare.UsingAccount(cloudflareTestAccountID))

				_, output, _ = executeCommandC(rootCmd, "generate", "--resource-type", tc.resourceType, "--account", cloudflareTestAccountID)

			} else {
				viper.Set("zone", cloudflareTestZoneID)
				api, _ = cloudflare.New(viper.GetString("key"), viper.GetString("email"), cloudflare.HTTPClient(
					&http.Client{
						Transport: r,
					},
				))

				_, output, _ = executeCommandC(rootCmd, "generate", "--resource-type", tc.resourceType, "--zone", cloudflareTestZoneID)

			}

			expected := testDataFile(tc.testdataFilename)
			assert.Equal(t, strings.TrimRight(expected, "\n"), strings.TrimRight(output, "\n"))
		})
	}
}
*/
