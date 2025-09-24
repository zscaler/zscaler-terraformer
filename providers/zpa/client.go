/*
Copyright (c) 2023 Zscaler Inc, <devrel@zscaler.com>

                            MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package zpa

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler"
	"github.com/zscaler/zscaler-sdk-go/v3/zscaler/zpa"
	"github.com/zscaler/zscaler-terraformer/v2/terraformutils/helpers"
)

// Client is the high-level client returned by NewClient().
// We only keep one Service pointer, and at runtime.
// it will be backed by either the legacy (V2) client or the new (V3) client.
type Client struct {
	Service *zscaler.Service
}

// Config holds all the configuration settings used to initialize the SDK clients.
// Adapt as needed, mirroring what you have in config.go of the Terraform provider.
type Config struct {
	useLegacyClient bool

	// V3 fields (OneAPI)
	clientID      string
	clientSecret  string
	privateKey    string
	vanityDomain  string
	customerID    string
	microtenantID string
	cloud         string

	// V2 fields (Legacy)
	zpaClientID     string
	zpaClientSecret string
	zpaCustomerID   string
	BaseURL         string

	httpProxy      string
	requestTimeout int
	retryCount     int
}

// NewClient is the main entry point: it reads config (from viper/env).
// and initializes the appropriate client (V2 or V3).
func NewClient() (*Client, error) {
	// Build up our internal config object from environment variables, viper, etc.
	cfg := newConfigFromEnv() // No error returned now.

	var svc *zscaler.Service

	if cfg.useLegacyClient {
		logrus.Infof("[INFO] Initializing Legacy ZPA client...")
		legacySvc, err := zscalerSDKV2Client(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Legacy ZPA client: %w", err)
		}
		// Wrap the underlying client in zscaler.Service so usage is consistent.
		svc = zscaler.NewService(legacySvc.Client, nil)
	} else {
		logrus.Infof("[INFO] Initializing Zscaler ONEAPI client...")
		v3Client, err := zscalerSDKV3Client(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Zscaler ONEAPI client: %w", err)
		}
		// Wrap the underlying client in zscaler.Service so usage is consistent.
		svc = zscaler.NewService(v3Client, nil)
	}

	return &Client{
		Service: svc,
	}, nil
}

func newConfigFromEnv() *Config {
	viper.AutomaticEnv()

	// The parameter or env var controlling legacy usage.
	useLegacyClient := viper.GetBool("use_legacy_client")
	if os.Getenv("ZSCALER_USE_LEGACY_CLIENT") != "" {
		useLegacyClient = strings.EqualFold(os.Getenv("ZSCALER_USE_LEGACY_CLIENT"), "true")
	}

	// For the new OneAPI
	clientID := viper.GetString("client_id")
	if clientID == "" && os.Getenv("ZSCALER_CLIENT_ID") != "" {
		clientID = os.Getenv("ZSCALER_CLIENT_ID")
	}

	clientSecret := viper.GetString("client_secret")
	if clientSecret == "" && os.Getenv("ZSCALER_CLIENT_SECRET") != "" {
		clientSecret = os.Getenv("ZSCALER_CLIENT_SECRET")
	}

	privateKey := viper.GetString("private_key")
	if privateKey == "" && os.Getenv("ZSCALER_PRIVATE_KEY") != "" {
		privateKey = os.Getenv("ZSCALER_PRIVATE_KEY")
	}

	vanityDomain := viper.GetString("vanity_domain")
	if vanityDomain == "" && os.Getenv("ZSCALER_VANITY_DOMAIN") != "" {
		vanityDomain = os.Getenv("ZSCALER_VANITY_DOMAIN")
	}

	customerID := viper.GetString("customer_id")
	if customerID == "" && os.Getenv("ZPA_CUSTOMER_ID") != "" {
		customerID = os.Getenv("ZPA_CUSTOMER_ID")
	}

	microtenantID := viper.GetString("microtenant_id")
	if microtenantID == "" && os.Getenv("ZSCALER_MICROTENANT_ID") != "" {
		microtenantID = os.Getenv("ZSCALER_MICROTENANT_ID")
	}

	cloud := viper.GetString("zscaler_cloud")
	if cloud == "" && os.Getenv("ZSCALER_CLOUD") != "" {
		cloud = os.Getenv("ZSCALER_CLOUD")
	}

	// For the legacy V2 approach.
	zpaClientID := viper.GetString("zpa_client_id")
	if zpaClientID == "" && os.Getenv("ZPA_CLIENT_ID") != "" {
		zpaClientID = os.Getenv("ZPA_CLIENT_ID")
	}

	zpaClientSecret := viper.GetString("zpa_client_secret")
	if zpaClientSecret == "" && os.Getenv("ZPA_CLIENT_SECRET") != "" {
		zpaClientSecret = os.Getenv("ZPA_CLIENT_SECRET")
	}

	zpaCustomerID := viper.GetString("zpa_customer_id")
	if zpaCustomerID == "" && os.Getenv("ZPA_CUSTOMER_ID") != "" {
		zpaCustomerID = os.Getenv("ZPA_CUSTOMER_ID")
	}

	baseURL := viper.GetString("zpa_cloud")
	if baseURL == "" && os.Getenv("ZPA_CLOUD") != "" {
		baseURL = os.Getenv("ZPA_CLOUD")
	}

	httpProxy := viper.GetString("zscaler_http_proxy")
	if httpProxy == "" && os.Getenv("ZSCALER_HTTP_PROXY") != "" {
		httpProxy = os.Getenv("ZSCALER_HTTP_PROXY")
	}

	retryCount := viper.GetInt("zscaler_retry_count")
	if retryCount == 0 {
		if val := os.Getenv("ZSCALER_RETRY_COUNT"); val != "" {
			if converted, err := strconv.Atoi(val); err == nil {
				retryCount = converted
			}
		}
		if retryCount == 0 {
			retryCount = 5
		}
	}

	requestTimeout := viper.GetInt("zscaler_request_timeout")
	if requestTimeout == 0 {
		if val := os.Getenv("ZSCALER_REQUEST_TIMEOUT"); val != "" {
			if converted, err := strconv.Atoi(val); err == nil {
				requestTimeout = converted
			}
		}
	}

	// Build the config struct.
	config := &Config{
		useLegacyClient: useLegacyClient,

		// V3 fields.
		clientID:      clientID,
		clientSecret:  clientSecret,
		privateKey:    privateKey,
		vanityDomain:  vanityDomain,
		customerID:    customerID,
		microtenantID: microtenantID,
		cloud:         cloud,

		// V2 fields.
		zpaClientID:     zpaClientID,
		zpaClientSecret: zpaClientSecret,
		zpaCustomerID:   zpaCustomerID,
		BaseURL:         baseURL,

		httpProxy:      httpProxy,
		retryCount:     retryCount,
		requestTimeout: requestTimeout,
	}

	return config
}

// zscalerSDKV2Client initializes the legacy ZPA client (V2).
func zscalerSDKV2Client(c *Config) (*zscaler.Service, error) {
	// You can set a custom user agent if desired.
	customUserAgent := helpers.GenerateUserAgent()

	// Start building config setters for the V2 zpa library.
	setters := []zpa.ConfigSetter{
		zpa.WithCache(false),
		zpa.WithHttpClientPtr(http.DefaultClient),
		zpa.WithRateLimitMaxRetries(int32(c.retryCount)),
		zpa.WithRequestTimeout(time.Duration(c.requestTimeout) * time.Second),
		zpa.WithZPAClientID(c.zpaClientID),
		zpa.WithZPAClientSecret(c.zpaClientSecret),
		zpa.WithZPACustomerID(c.zpaCustomerID),
		zpa.WithZPACloud(c.BaseURL),
	}

	// Handle microtenant if present.
	if c.microtenantID != "" {
		setters = append(setters, zpa.WithZPAMicrotenantID(c.microtenantID))
	}

	// Proxy.
	if c.httpProxy != "" {
		parsedURL, err := url.Parse(c.httpProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		setters = append(setters, zpa.WithProxyHost(parsedURL.Hostname()))

		sPort := parsedURL.Port()
		if sPort == "" {
			sPort = "80"
		}
		port64, err := strconv.ParseInt(sPort, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy port: %w", err)
		}
		if port64 < 1 || port64 > 65535 {
			return nil, fmt.Errorf("invalid port number: must be between 1 and 65535, got: %d", port64)
		}
		setters = append(setters, zpa.WithProxyPort(int32(port64)))
	}

	zpaCfg, err := zpa.NewConfiguration(setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Legacy ZPA configuration: %w", err)
	}
	zpaCfg.UserAgent = customUserAgent

	// Now wrap it in a zscaler.Service so usage is uniform.
	wrappedV2Client, err := zscaler.NewLegacyZpaClient(zpaCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Legacy ZPA client: %w", err)
	}

	log.Println("[INFO] Successfully initialized Legacy ZPA client")
	return wrappedV2Client, nil
}

// zscalerSDKV3Client initializes the new OneAPI-based Zscaler client.
func zscalerSDKV3Client(c *Config) (*zscaler.Client, error) {
	customUserAgent := helpers.GenerateUserAgent()

	setters := []zscaler.ConfigSetter{
		zscaler.WithCache(false),
		zscaler.WithHttpClientPtr(http.DefaultClient),
		zscaler.WithRateLimitMaxRetries(int32(c.retryCount)),
		zscaler.WithRequestTimeout(time.Duration(c.requestTimeout) * time.Second),
	}

	// Proxy.
	if c.httpProxy != "" {
		parsedURL, err := url.Parse(c.httpProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		setters = append(setters, zscaler.WithProxyHost(parsedURL.Hostname()))

		sPort := parsedURL.Port()
		if sPort == "" {
			sPort = "80"
		}
		port64, err := strconv.ParseInt(sPort, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy port: %w", err)
		}
		if port64 < 1 || port64 > 65535 {
			return nil, fmt.Errorf("invalid port number: %d", port64)
		}
		setters = append(setters, zscaler.WithProxyPort(int32(port64)))
	}

	// Check which auth method we have.
	// 1) clientID + clientSecret + vanityDomain + customerID.
	// 2) clientID + privateKey + vanityDomain + customerID.
	switch {
	case c.clientID != "" && c.clientSecret != "" && c.vanityDomain != "" && c.customerID != "":
		setters = append(setters,
			zscaler.WithClientID(c.clientID),
			zscaler.WithClientSecret(c.clientSecret),
			zscaler.WithVanityDomain(c.vanityDomain),
			zscaler.WithZPACustomerID(c.customerID),
		)
		if c.microtenantID != "" {
			setters = append(setters, zscaler.WithZPAMicrotenantID(c.microtenantID))
		}
		if c.cloud != "" {
			setters = append(setters, zscaler.WithZscalerCloud(c.cloud))
		}

	case c.clientID != "" && c.privateKey != "" && c.vanityDomain != "" && c.customerID != "":
		setters = append(setters,
			zscaler.WithClientID(c.clientID),
			zscaler.WithPrivateKey(c.privateKey),
			zscaler.WithVanityDomain(c.vanityDomain),
			zscaler.WithZPACustomerID(c.customerID),
		)
		if c.microtenantID != "" {
			setters = append(setters, zscaler.WithZPAMicrotenantID(c.microtenantID))
		}
		if c.cloud != "" {
			setters = append(setters, zscaler.WithZscalerCloud(c.cloud))
		}
	default:
		return nil, fmt.Errorf("invalid authentication configuration: missing required parameters")
	}

	conf, err := zscaler.NewConfiguration(setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Zscaler ONEAPI configuration: %w", err)
	}
	conf.UserAgent = customUserAgent

	// Build the client.
	v3Client, err := zscaler.NewOneAPIClient(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create Zscaler OneAPI client: %w", err)
	}

	log.Println("[INFO] Successfully initialized Zscaler ONEAPI client")
	return v3Client.Client, nil
}
