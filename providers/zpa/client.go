package zpa

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services"
)

type Client struct {
	AppConnectorGroup            *services.Service
	AppConnectorController       *services.Service
	ApplicationSegment           *services.Service
	ApplicationSegmentInspection *services.Service
	ApplicationSegmentPRA        *services.Service
	AppServerController          *services.Service
	BrowserAccess                *services.Service
	BACertificate                *services.Service
	LSSConfigController          *services.Service
	PolicySetController          *services.Service
	PolicySetControllerV2        *services.Service
	PRAApproval                  *services.Service
	PRACredential                *services.Service
	PRAConsole                   *services.Service
	PRAPortal                    *services.Service
	ProvisioningKey              *services.Service
	SegmentGroup                 *services.Service
	ServerGroup                  *services.Service
	ServiceEdgeGroup             *services.Service
	InspectionCustomControls     *services.Service
	MicroTenants                 *services.Service
}

func NewClient() (*Client, error) {
	zpaCloud := viper.GetString("zpa_cloud")
	zpaClientID := viper.GetString("zpa_client_id")
	zpaClientSecret := viper.GetString("zpa_client_secret")
	zpaCustomerID := viper.GetString("zpa_customer_id")

	if zpaClientID == "" || zpaClientSecret == "" || zpaCustomerID == "" {
		logrus.Fatal("ZPA credentials are not set")
	}

	config, err := zpa.NewConfig(zpaClientID, zpaClientSecret, zpaCustomerID, zpaCloud, "zscaler-terraformer")
	if err != nil {
		return nil, err
	}

	client := zpa.NewClient(config)

	return &Client{
		AppConnectorGroup:            services.New(client),
		AppConnectorController:       services.New(client),
		ApplicationSegment:           services.New(client),
		ApplicationSegmentInspection: services.New(client),
		ApplicationSegmentPRA:        services.New(client),
		AppServerController:          services.New(client),
		BrowserAccess:                services.New(client),
		BACertificate:                services.New(client),
		LSSConfigController:          services.New(client),
		PolicySetController:          services.New(client),
		PolicySetControllerV2:        services.New(client),
		PRAApproval:                  services.New(client),
		PRACredential:                services.New(client),
		PRAConsole:                   services.New(client),
		PRAPortal:                    services.New(client),
		ProvisioningKey:              services.New(client),
		SegmentGroup:                 services.New(client),
		ServerGroup:                  services.New(client),
		ServiceEdgeGroup:             services.New(client),
		InspectionCustomControls:     services.New(client),
		MicroTenants:                 services.New(client),
	}, nil
}
