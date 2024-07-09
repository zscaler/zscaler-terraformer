package zia

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/zscaler/zscaler-sdk-go/v2/zia"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services"
	"github.com/zscaler/zscaler-sdk-go/v2/zia/services/forwarding_control_policy/zpa_gateways"
)

type Client struct {
	Admins                     *services.Service
	FilteringRules             *services.Service
	IPDestinationGroups        *services.Service
	IPSourceGroups             *services.Service
	NetworkApplicationGroups   *services.Service
	NetworkServiceGroups       *services.Service
	NetworkServices            *services.Service
	URLCategories              *services.Service
	URLFilteringPolicies       *services.Service
	GRETunnels                 *services.Service
	StaticIPs                  *services.Service
	VPNCredentials             *services.Service
	LocationManagement         *services.Service
	DLPDictionaries            *services.Service
	DLPEngines                 *services.Service
	DLPNotificationTemplates   *services.Service
	DLPWebRules                *services.Service
	RuleLabels                 *services.Service
	SecurityPolicySettings     *services.Service
	SandboxSettings            *services.Service
	UserAuthenticationSettings *services.Service
	ForwardingRules            *services.Service
	ZpaGateways                *zpa_gateways.Service
}

func NewClient() (*Client, error) {
	ziaCloud := viper.GetString("zia_cloud")
	ziaUsername := viper.GetString("zia_username")
	ziaPassword := viper.GetString("zia_password")
	ziaAPIKey := viper.GetString("zia_api_key")

	if ziaUsername == "" || ziaPassword == "" || ziaAPIKey == "" {
		logrus.Fatal("ZIA credentials are not set")
	}

	client, err := zia.NewClient(ziaUsername, ziaPassword, ziaAPIKey, ziaCloud, "zscaler-terraformer")
	if err != nil {
		return nil, err
	}

	return &Client{
		Admins:                     services.New(client),
		FilteringRules:             services.New(client),
		IPDestinationGroups:        services.New(client),
		IPSourceGroups:             services.New(client),
		NetworkApplicationGroups:   services.New(client),
		NetworkServiceGroups:       services.New(client),
		NetworkServices:            services.New(client),
		URLCategories:              services.New(client),
		URLFilteringPolicies:       services.New(client),
		GRETunnels:                 services.New(client),
		StaticIPs:                  services.New(client),
		VPNCredentials:             services.New(client),
		LocationManagement:         services.New(client),
		DLPDictionaries:            services.New(client),
		DLPEngines:                 services.New(client),
		DLPNotificationTemplates:   services.New(client),
		DLPWebRules:                services.New(client),
		RuleLabels:                 services.New(client),
		SecurityPolicySettings:     services.New(client),
		SandboxSettings:            services.New(client),
		UserAuthenticationSettings: services.New(client),
		ForwardingRules:            services.New(client),
		ZpaGateways:                zpa_gateways.New(client),
	}, nil
}
