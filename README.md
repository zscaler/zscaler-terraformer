<a href="https://terraform.io">
    <img src="https://raw.githubusercontent.com/hashicorp/terraform-website/master/public/img/logo-text.svg" alt="Terraform logo" title="Terraform" height="50" />
</a>

<a href="https://www.zscaler.com/">
    <img src="https://raw.githubusercontent.com/zscaler/zscaler-terraformer/master/images/zscaler_terraformer-logo.svg" alt="Zscaler logo" title="Zscaler" height="50" />
</a>

# Zscaler Terraformer Tool

[![GitHub release](https://img.shields.io/github/release/zscaler/zscaler-terraformer.svg)](https://github.com/zscaler/zscaler-terraformer/releases/)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/zscaler/zscaler-terraformer)](https://github.com/zscaler/zscaler-terraformer/blob/master/.go-version)
[![Go Report Card](https://goreportcard.com/badge/github.com/zscaler/zscaler-terraformer)](https://goreportcard.com/report/github.com/zscaler/zscaler-terraformer)
[![GitHub releases](https://img.shields.io/github/downloads/zscaler/zscaler-terraformer/total.svg)](https://GitHub.com/zscaler/zscaler-terraformer/releases/)
[![Zscaler Community](https://img.shields.io/badge/zscaler-community-blue)](https://community.zscaler.com/)

## Support Disclaimer

-> **Disclaimer:** Please refer to our [General Support Statement](docs/guides/support.md) before proceeding with the use of this provider. You can also refer to our [troubleshooting guide](docs/guides/troubleshooting.md) for guidance on typical problems.

## Overview

`zscaler-terraformer` is A CLI tool that generates ``tf`` and ``tfstate`` files based on existing ZPA and/or ZIA resources.
It does this by using your respective API credentials in each platform to retrieve your configurations from the [ZPA API](https://help.zscaler.com/zpa/getting-started-zpa-api) and/or [ZIA API](https://help.zscaler.com/zia/getting-started-zia-api) and converting them to Terraform configurations so that it can be used with the
[ZPA Terraform Provider](https://registry.terraform.io/providers/zscaler/zpa/latest) and/or [ZIA Terraform Provider](https://registry.terraform.io/providers/zscaler/zia/latest)

This tool is ideal if you already have ZPA and/or ZIA resources defined but want to
start managing them via Terraform, and don't want to spend the time to manually
write the Terraform configuration to describe them.

> NOTE: This tool has been developed and tested with Terraform v1.x.x only.

[![Zscaler Terraformer Migration Tool](https://raw.githubusercontent.com/zscaler/zscaler-terraformer/master/images/zscaler_terraformer.svg)](https://fast.wistia.net/embed/channel/07fhl9bbvr?wchannelid=07fhl9bbvr&wvideoid=sfd7h33q2e)

## Zscaler - OneAPI Authentication New Framework

As of version v4.0.0, this provider supports authentication via the new Zscaler API framework [OneAPI](https://help.zscaler.com/oneapi/understanding-oneapi)

Zscaler OneAPI uses the OAuth 2.0 authorization framework to provide secure access to Zscaler Internet Access (ZIA) APIs. OAuth 2.0 allows third-party applications to obtain controlled access to protected resources using access tokens. OneAPI uses the Client Credentials OAuth flow, in which client applications can exchange their credentials with the authorization server for an access token and obtain access to the API resources, without any user authentication involved in the process.

**NOTE** As of version v2.0.0, Zscaler-Terraformer offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** Notice that OneAPI and Zidentity is NOT currently supported for the following ZIA and ZPA clouds respectively: `zscalergov` and `zscalerten` or `GOV` and `GOVUS`. Refer to the [Legacy API Framework](#legacy-api-framework) for more information on how authenticate to these environments

``zscaler-terraformer`` for ZPA supports the following environment variables:

## Authentication

Both ZPA and ZIA follow its respective authentication methods as described in the Terraform registry documentation:

* [ZPA Terraform Provider](https://registry.terraform.io/providers/zscaler/zpa/latest/docs)
* [ZIA Terraform Provider](https://registry.terraform.io/providers/zscaler/zia/latest/docs)

For details on how to generate API credentials visit:

* ZPA [Getting Started](https://help.zscaler.com/zpa/getting-started-zpa-api)
* ZIA [Getting Started](https://help.zscaler.com/zia/getting-started-zia-api)

!> **A note on storing your credentials securely**: We recommend that you store
your ZPA and/or ZIA credentials as environment variables as
demonstrated below.

## Examples Usage - ZPA OneAPI Client Secret Authentication (Environment Variables)

```bash
export ZSCALER_CLIENT_ID      = "xxxxxxxxxxxxxxxx"
export ZSCALER_CLIENT_SECRET  = "xxxxxxxxxxxxxxxx"
export ZSCALER_VANITY_DOMAIN  = "xxxxxxxxxxxxxxxx"
export ZPA_CUSTOMER_ID        = "xxxxxxxxxxxxxxxx"
export ZSCALER_CLOUD          = "beta" ## Optional for alternative clouds
```

## Examples Usage - ZPA OneAPI Client Secret Authentication (Inline Authenticatiion)

```bash
zscaler-terraformer import \
--resources="zpa" \
--client_id="xxxxxxxxxxxxxxxx" \
--client_secret="xxxxxxxxxxxxxxxx" \
--vanity_domain="xxxxxxxxxxxxxxxx" \
--customer_id="xxxxxxxxxxxxxxxx" \
--zscaler_cloud="beta" ## Optional for alternative clouds
```

## Examples Usage - ZIA OneAPI Client Secret Authentication (Environment Variables)

```bash
export ZSCALER_CLIENT_ID      = "xxxxxxxxxxxxxxxx"
export ZSCALER_CLIENT_SECRET  = "xxxxxxxxxxxxxxxx"
export ZSCALER_VANITY_DOMAIN  = "xxxxxxxxxxxxxxxx"
export ZSCALER_CLOUD          = "beta" ## Optional for alternative clouds
```

## Examples Usage - ZIA OneAPI Client Secret Authentication (Inline Authenticatiion)

```bash
zscaler-terraformer import \
--resources="zia" \
--client_id="xxxxxxxxxxxxxxxx" \
--client_secret="xxxxxxxxxxxxxxxx" \
--vanity_domain="xxxxxxxxxxxxxxxx" \
--zscaler_cloud="beta" ## Optional for alternative clouds
```

### Default Environment variables

You can provide credentials via the `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET`, `ZSCALER_VANITY_DOMAIN`, `ZSCALER_CLOUD` environment variables, representing your Zidentity OneAPI credentials `clientId`, `clientSecret`, `vanityDomain` and `cloud` respectively.

| Argument        | Description                                                                                         | Environment Variable     |
|-----------------|-----------------------------------------------------------------------------------------------------|--------------------------|
| `client_id`     | _(String)_ Zscaler API Client ID, used with `clientSecret` or `PrivateKey` OAuth auth mode.         | `ZSCALER_CLIENT_ID`      |
| `client_secret` | _(String)_ Secret key associated with the API Client ID for authentication.                         | `ZSCALER_CLIENT_SECRET`  |
| `privateKey`    | _(String)_ A string Private key value.                                                              | `ZSCALER_PRIVATE_KEY`    |
| `customer_id`   | _(String)_ A string that contains the ZPA customer ID which identifies the tenant                   | `ZPA_CUSTOMER_ID`    |
| `microtenant_id`| _(String)_ A string that contains the ZPA microtenant ID which identifies the tenant                | `ZPA_MICROTENANT_ID`    |
| `vanity_domain` | _(String)_ Refers to the domain name used by your organization.                                     | `ZSCALER_VANITY_DOMAIN`  |
| `cloud`         | _(String)_ The name of the Zidentity cloud, e.g., beta.                                             | `ZSCALER_CLOUD`          |

### Alternative OneAPI Cloud Environments

OneAPI supports authentication and can interact with alternative Zscaler enviornments i.e `beta`. To authenticate to these environments you must provide the following values:

| Argument         | Description                                                                                         |   | Environment Variable     |
|------------------|-----------------------------------------------------------------------------------------------------|---|--------------------------|
| `vanity_domain`   | _(String)_ Refers to the domain name used by your organization |   | `ZSCALER_VANITY_DOMAIN`  |
| `cloud`          | _(String)_ The name of the Zidentity cloud i.e beta      |   | `ZSCALER_CLOUD`          |

For example: Authenticating to Zscaler Beta environment:

```sh
export ZSCALER_VANITY_DOMAIN="acme"
export ZSCALER_CLOUD="beta"
```

### OneAPI (API Client Scope)

OneAPI Resources are automatically created within the ZIdentity Admin UI based on the RBAC Roles
applicable to APIs within the various products. For example, in ZIA, navigate to `Administration -> Role
Management` and select `Add API Role`.

Once this role has been saved, return to the ZIdentity Admin UI and from the Integration menu
select API Resources. Click the `View` icon to the right of Zscaler APIs and under the ZIA
dropdown you will see the newly created Role. In the event a newly created role is not seen in the
ZIdentity Admin UI a `Sync Now` button is provided in the API Resources menu which will initiate an
on-demand sync of newly created roles.

## Legacy API Framework

### ZPA Environment Variables

* As of version v2.0.0, Zscaler Terraformer offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** The use of of the attribute `use_legacy_client` is mandatory when not authenticating through OneAPI.

``zscaler-terraformer`` for ZPA supports the following environment variables:

```bash
export ZPA_CLIENT_ID      = "xxxxxxxxxxxxxxxx"
export ZPA_CLIENT_SECRET  = "xxxxxxxxxxxxxxxx"
export ZPA_CUSTOMER_ID    = "xxxxxxxxxxxxxxxx"
export ZPA_CLOUD          = "BETA", "GOV", "GOVUS", "PRODUCTION" or "ZPATWO"
export ZSCALER_USE_LEGACY_CLIENT=true
```

### ZPA Inline Authentication

```bash
zscaler-terraformer import --resources="zpa" \
--zpa_client_id="xxxxxxxxxxxxxxxx" \
--zpa_client_secret="xxxxxxxxxxxxxxxx" \
--zpa_customer_id="xxxxxxxxxxxxxxxx" \
--zpa_cloud="BETA", "GOV", "GOVUS", "PRODUCTION" or "ZPATWO" \
--use_legacy_client=true
```

### ZPA Environment variables (Legacy)

You can provide credentials via the `ZPA_CLIENT_ID`, `ZPA_CLIENT_SECRET`, `ZPA_CUSTOMER_ID`, `ZPA_CLOUD` environment variables, representing your ZPA `client_id`, `client_secret`, `customer_id` and `cloud` of your ZPA account, respectively.

~> **NOTE** `ZPA_CLOUD` environment variable is required, and is used to identify the correct API gateway where the API requests should be forwarded to.

| Argument     | Description | Environment variable |
|--------------|-------------|-------------------|
| `client_id`       | _(String)_ The ZPA API client ID generated from the ZPA console.| `ZPA_CLIENT_ID` |
| `client_secret`       | _(String)_ The ZPA API client secret generated from the ZPA console.| `ZPA_CLIENT_SECRET` |
| `customer_id`       | _(String)_ The ZPA tenant ID found in the Administration > Company menu in the ZPA console.| `ZPA_CUSTOMER_ID` |
| `cloud`       | _(String)_ The Zscaler cloud for your tenancy.| `ZPA_CLOUD` |
| `use_legacy_client`       | _(Bool)_ Enable use of the legacy ZIA API Client.| `ZSCALER_USE_LEGACY_CLIENT` |

### ZIA Environment Variables (Legacy)

* As of version v2.0.0, Zscaler Terraformer offers backwards compatibility to the Zscaler legacy API framework. This is the recommended authentication method for organizations whose tenants are still not migrated to [Zidentity](https://help.zscaler.com/zidentity/what-zidentity).

**NOTE** The use of of the attribute `use_legacy_client` is mandatory when not authenticating through OneAPI.

``zscaler-terraformer`` for ZIA supports the following environment variables:

```bash
export ZIA_USERNAME = "xxxxxxxxxxxxxxxx"
export ZIA_PASSWORD = "xxxxxxxxxxxxxxxx"
export ZIA_API_KEY  = "xxxxxxxxxxxxxxxx"
export ZIA_CLOUD    = "xxxxxxxxxxxxxxxx" (i.e zscalerthree)
export ZSCALER_USE_LEGACY_CLIENT=true
```

### ZIA Inline Authentication

```bash
zscaler-terraformer import --resources="zia" \
--zia_username="xxxxxxxxxxxxxxxx" \
--zia_password="xxxxxxxxxxxxxxxx" \
--zia_api_key="xxxxxxxxxxxxxxxx" \
--zia_cloud=(i.e zscalerthree) \
--use_legacy_client=true
```

### ZIA Environment variables (Legacy)

You can provide credentials via the `ZIA_USERNAME`, `ZIA_PASSWORD`, `ZIA_API_KEY`, `ZIA_CLOUD` environment variables, representing your ZIA `username`, `password`, `api_key` and `cloud` respectively.

| Argument     | Description | Environment variable |
|--------------|-------------|-------------------|
| `username`       | _(String)_ A string that contains the email ID of the API admin.| `ZIA_USERNAME` |
| `password`       | _(String)_ A string that contains the password for the API admin.| `ZIA_PASSWORD` |
| `api_key`       | _(String)_ A string that contains the obfuscated API key (i.e., the return value of the obfuscateApiKey() method).| `ZIA_API_KEY` |
| `cloud`       | _(String)_ The host and basePath for the cloud services API is `$zsapi.<Zscaler Cloud Name>/api/v1`.| `ZIA_CLOUD` |
| `use_legacy_client`       | _(Bool)_ Enable use of the legacy ZIA API Client.| `ZSCALER_USE_LEGACY_CLIENT` |

## Usage

### Version Information

To check the version of zscaler-terraformer, you can use either of these commands:

```bash
# Display version information (recommended)
zscaler-terraformer --version

# Alternative: Use the version command
zscaler-terraformer version
```

Both commands will display:
- Zscaler Terraformer version
- Terraform version (if installed)
- Platform information
- Update notifications (if a newer version is available)

```bash
Usage:
  zscaler-terraformer [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  generate    Fetch resources from the ZPA and ZIA API and generate the respective Terraform stanzas
  help        Help about any command
  import      Output `terraform import` compatible commands in order to import resources into state
  version     Print the version number of zscaler-terraformer

Flags:
      --client_id string                    OneAPI client_id (required in V3 mode)
      --client_secret string                OneAPI client_secret (required in V3 mode)
      --customer_id string                  OneAPI optional customer_id
      --exclude string                      Which resources you wish to exclude
  -h, --help                                Show help for zscaler-terraformer
      --microtenant_id string               OneAPI optional microtenant_id
      --resource-type string                Which resource you wish to generate
      --resources string                    Which resources you wish to import
      --supported-resources string          List supported resources for ZPA or ZIA
      --terraform-install-path string       Path to the default Terraform installation (default ".")
      --use_legacy_client                   Enable Legacy Mode (true/false)
      --vanity_domain string                OneAPI vanity_domain (required in V3 mode)
  -v, --verbose                             Enable verbose debug output
      --version                             Display the release version
      --zia-provider-namespace string       Custom namespace for the ZIA provider
      --zia-terraform-install-path string   Path to the ZIA Terraform installation (default ".")
      --zia_api_key string                  ZIA legacy api_key (required)
      --zia_cloud string                    ZIA Cloud environment (required for ZIA legacy, e.g. zscalerthree)
      --zia_password string                 ZIA legacy password (required)
      --zia_username string                 ZIA legacy username (required if using legacy mode for ZIA resources)
      --zpa-provider-namespace string       Custom namespace for the ZPA provider
      --zpa-terraform-install-path string   Path to the ZPA Terraform installation (default ".")
      --zpa_client_id string                ZPA legacy client ID (required if using legacy mode for ZPA resources)
      --zpa_client_secret string            ZPA legacy client secret
      --zpa_cloud string                     ZPA Cloud (``BETA``, ``GOV``, ``GOVUS``, ``PRODUCTION``, ``ZPATWO``)
      --zpa_customer_id string              ZPA legacy customer ID
      --zpa_microtenant_id string           ZPA legacy microtenant_id (optional)
      --zscaler_cloud string                OneAPI optional zscaler_cloud (e.g. PRODUCTION)

Use "zscaler-terraformer [command] --help" for more information about a command.
```

## ZPA Example usage

To get started with the zscaler-terraformer CLI to export your ZPA configuration, create a directory where you want the configuration to stored. See ZPA Demo:

[![asciicast](https://asciinema.org/a/537966.svg)](https://asciinema.org/a/537966)

**Option 1**

### Import All ZPA Configuration

```bash
zscaler-terraformer import --resources="zpa"
```

### Import Specific ZPA Resource

```bash
zscaler-terraformer import --resources="zpa_application_segment"
```

### Exclude specific ZPA resources from Importing

```bash
zscaler-terraformer import --resources="zpa" --exclude='zpa_segment_group, zpa_server_group'
```

By default, ``zscaler-terraformer`` will create a local configuration directory where it is being executed. You can also indicate the path where the imported configuration should be stored by using the folowing environment variable ``ZSCALER_ZPA_TERRAFORM_INSTALL_PATH``.

```bash
$ export ZSCALER_ZPA_TERRAFORM_INSTALL_PATH="$HOME/Desktop/zpa_configuration"
$ zscaler-terraformer generate \
  --resource-type "zpa_application_segment"
```

## ZIA Example usage

To get started with the zscaler-terraformer CLI to export your ZIA configuration, create a directory where you want the configuration to stored.

https://user-images.githubusercontent.com/23208337/204072949-a6f9bfb7-aaf0-4f76-87f8-ebc577c88247.mp4

**Option 1**

### Import All ZIA Configuration

```bash
zscaler-terraformer import --resources="zia"
```

### Import Specific ZIA Resource

```bash
zscaler-terraformer import --resources="zia_firewall_filtering_rule"
```

### Exclude specific ZIA resources from Importing

```bash
zscaler-terraformer import --resources="zia" --exclude='zia_forwarding_control_rule,zia_forwarding_control_zpa_gateway,zia_user_management'
```

By default, ``zscaler-terraformer`` will create a local configuration directory where it is being executed. You can also indicate the path where the imported configuration should be stored by using the folowing environment variable ``ZSCALER_ZIA_TERRAFORM_INSTALL_PATH``.

```bash
$ export ZSCALER_ZIA_TERRAFORM_INSTALL_PATH="$HOME/Desktop/zia_configuration"
$ zscaler-terraformer generate \
  --resource-type "zia_firewall_filtering_rule"
```

**Generate HCL Configuration**

To simply generate the HCL configuration output without importing and creating the state file, use the command ``zscaler-terraformer generate``

```bash
$ zscaler-terraformer generate \
  --zia-terraform-install-path $HOME/Desktop/zia_configuration \
  --resource-type "zia_firewall_filtering_rule"
```

## Prerequisites

* A ZIA and/or ZPA tenant with resources defined.
* Valid ZIA and or/ZPA API credentials with sufficient permissions to access the resources
  you are requesting via the API
* ``zscaler-terraformer`` utility installed on the local machine.

## Installation

### Homebrew on MacOS

If you use Homebrew on MacOS, you can run one of the following commands:

```bash
brew tap zscaler/tap
brew install zscaler/tap/zscaler-terraformer
```

or

```bash
brew tap zscaler/tap
brew install --cask zscaler/tap/zscaler-terraformer
```
### Windows - Chocolatey Package Manager

If you want to run the tool on Windows, you can use Chocolatey package manager:

```pwsh
choco install zscaler-terraformer
```

### Linux

From releases you can execute the following commands:

```shell
LATEST_TAG=$(curl -s https://api.github.com/repos/zscaler/zscaler-terraformer/releases/latest | grep '"tag_name":' | cut -d '"' -f 4)
LATEST_VERSION=$(echo "$LATEST_TAG" | sed 's/v//')
ZIP_FILE="zscaler-terraformer_${LATEST_VERSION}_linux_amd64.zip"
curl -LO "https://github.com/zscaler/zscaler-terraformer/releases/download/${LATEST_TAG}/${ZIP_FILE}"
unzip "$ZIP_FILE"
chmod +x zscaler-terraformer
sudo mv zscaler-terraformer /usr/local/bin
```

## Importing with Terraform state

`zscaler-terraformer` will output the `terraform import` compatible commands for you
when you invoke the `import` command. This command assumes you have already ran
`zscaler-terraformer generate ...` to output your resources.

In the future this process will be further automated; however for now, it is a manual step to
allow flexibility in directory structure.

```bash
$ zscaler-terraformer import \
  --resource-type "zpa_app_connector_group"
```

## ZPA Supported Resources

Any resources not listed are currently not supported.

Last updated July 11, 2024

Use the following command once the tool is installed to visualize the table of supported ZPA resources:
```shell
zscaler-terraformer --supported-resources="zpa"
```

| Resource | Resource Scope | Generate Supported | Import Supported |
|----------|-----------|----------|----------|
| [zpa_app_connector_group](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_app_connector_group) | group | ✅ | ✅ |
| [zpa_service_edge_group](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_service_edge_group) | group | ✅ | ✅ |
| [zpa_application_server](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_application_server) | application | ✅ | ✅ |
| [zpa_application_segment](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_application_segment) | application segment | ✅ | ✅ |
| [zpa_application_segment_browser_access](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_application_segment_browser_access) | application segment | ✅ | ✅ |
| [zpa_application_segment_inspection](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_application_segment_inspection) | application segment | ✅ | ✅ |
| [zpa_application_segment_pra](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_application_segment_pra) | application segment | ✅ | ✅ |
| [zpa_cloud_browser_isolation_banner](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_cloud_browser_isolation_banner) | isolation | ✅ | ✅ |
| [zpa_cloud_browser_isolation_certificate](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_cloud_browser_isolation_certificate) | isolation | ✅ | ✅ |
| [zpa_cloud_browser_isolation_external_profile](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_cloud_browser_isolation_external_profile) | isolation | ✅ | ✅ |
| [zpa_segment_group](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_segment_group) | group | ✅ | ✅ |
| [zpa_server_group](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_server_group) | group | ✅ | ✅ |
| [zpa_lss_config_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_lss_config_controller) | lss | ✅ | ✅ |
| [zpa_microtenant_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_microtenant_controller) | microtenant | ✅ | ✅ |
| [zpa_provisioning_key](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_provisioning_key) | key | ✅ | ✅ |
| [zpa_inspection_custom_controls](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_inspection_custom_control) | Inspection | ✅ | ✅ |
| [zpa_pra_approval_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_pra_approval_controller) | PRA | ✅ | ✅ |
| [zpa_pra_console_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_pra_console_controller) | PRA | ✅ | ✅ |
| [zpa_pra_credential_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_pra_credential_controller) | PRA | ✅ | ✅ |
| [zpa_pra_portal_controller](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_pra_portal_controller) | PRA | ✅ | ✅ |
| [zpa_policy_access_rule](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_policy_access_rule) | Policy | ✅ | ✅ |
| [zpa_policy_timeout_rule](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_policy_access_timeout_rule) | Policy | ✅ | ✅ |
| [zpa_policy_forwarding_rule](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_policy_access_forwarding_rule) | Policy | ✅ | ✅ |
| [zpa_policy_access_inspection_rule](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_policy_access_inspection_rule) | Policy | ✅ | ✅ |
| [zpa_policy_redirection_rule](https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_policy_access_redirection_rule) | Policy | ✅ | ✅ |

## ZIA Supported Resources

Any resources not listed are currently not supported.

Last updated July 11, 2024

Use the following command once the tool is installed to visualize the table of supported ZIA resources:

```shell
zscaler-terraformer --supported-resources="zia"
```

| Resource | Resource Scope | Generate Supported | Import Supported |
|----------|-----------|----------|----------|
| [zia_dlp_engines](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_dlp_engines) | DLP | ✅ | ✅ |
| [zia_dlp_dictionaries](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_dlp_dictionaries) | DLP | ✅ | ✅ |
| [zia_dlp_notification_templates](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_dlp_notification_templates) | DLP | ✅ | ✅ |
| [zia_dlp_web_rules](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_dlp_web_rules) | DLP | ✅ | ✅ |
| [zia_firewall_filtering_destination_groups](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_ip_destination_groups) | Cloud Firewall | ✅ | ✅ |
| [zia_firewall_filtering_ip_source_groups](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_ip_source_groups) | Cloud Firewall | ✅ | ✅ |
| [zia_firewall_filtering_network_application_groups](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_network_application_groups) | Cloud Firewall  | ✅ | ✅ |
| [zia_firewall_filtering_network_service](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_network_service) | Cloud Firewall  | ✅ | ✅ |
| [zia_firewall_filtering_network_service_groups](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_network_service_groups) | Cloud Firewall | ✅ | ✅ |
| [zia_firewall_filtering_rule](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_filtering_rule) | Cloud Firewall | ✅ | ✅ |
| [zia_firewall_dns_rule](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_dns_rules) | Cloud Firewall | ✅ | ✅ |
| [zia_firewall_ips_rule](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_firewall_ips_rules) | Cloud Firewall | ✅ | ✅ |
| [zia_location_management](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_location_management) | Location | ✅ | ✅ |
| [zia_traffic_forwarding_gre_tunnel](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_traffic_forwarding_gre_tunnel) | Traffic | ✅ | ✅ |
| [zia_traffic_forwarding_static_ip](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_traffic_forwarding_static_ip) | Traffic | ✅ | ✅ |
| [zia_traffic_forwarding_vpn_credentials](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_traffic_forwarding_vpn_credentials) | Traffic | ✅ | ✅ |
| [zia_rule_labels](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_rule_labels) | Labels | ✅ | ✅ |
| [zia_url_categories](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_url_categories) | URL | ✅ | ✅ |
| [zia_url_filtering_rules](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_url_filtering_rules) | URL | ✅ | ✅ |
| [zia_auth_settings_urls](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_auth_settings_urls) | URL | ✅ | ✅ |
| [zia_security_policy_settings](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_security_policy_settings) | URL | ✅ | ✅ |
| [zia_sandbox_behavioral_analysis](https://https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_sandbox_behavioral_analysis) | URL | ✅ | ✅ |
| [zia_forwarding_control_rule](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_forwarding_control_rule) | Forward | ✅ | ✅ |
| [zia_forwarding_control_zpa_gateway](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_forwarding_control_zpa_gateway) | Forward | ✅ | ✅ |
| [zia_sandbox_rules](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_sandbox_rules) | Sandbox | ✅ | ✅ |
| [zia_file_type_control_rules](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_file_type_control_rules) | File Types | ✅ | ✅ |
| [zia_ssl_inspection_rules](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_ssl_inspection_rules) | SSL Inspection | ✅ | ✅ |
| [zia_advanced_settings](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_advanced_settings) | Settings | ✅ | ✅ |
| [zia_advanced_threat_settings](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_advanced_threat_settings) | Threat Settings | ✅ | ✅ |
| [zia_atp_malware_inspection](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_atp_malware_inspection) | Malware Protection | ✅ | ✅ |
| [zia_atp_malware_policy](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_atp_malware_policy) | Malware Protection | ✅ | ✅ |
| [zia_atp_malware_protocols](https://registry.terraform.io/providers/zscaler/zia/latest/docs/data-sources/zia_atp_malware_protocols) | Malware Protection | ✅ | ✅ |
| [zia_atp_malware_protocols](https://registry.terraform.io/providers/zscaler/zia/latest/docs/data-sources/zia_atp_malware_protocols) | Malware Protection | ✅ | ✅ |
| [zia_atp_malware_settings](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_atp_malware_settings) | Malware Protection | ✅ | ✅ |
| [zia_atp_security_exceptions](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_atp_security_exceptions) | Threat Protection | ✅ | ✅ |
| [zia_atp_malicious_urls](https://registry.terraform.io/providers/zscaler/zia/latest/docs/data-sources/zia_atp_malicious_urls) | Threat Protection | ✅ | ✅ |
| [zia_url_filtering_and_cloud_app_settings](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_url_filtering_and_cloud_app_settings) | URL | ✅ | ✅ |
| [zia_end_user_notification](https://registry.terraform.io/providers/zscaler/zia/latest/docs/resources/zia_end_user_notification) | Notification | ✅ | ✅ |

## Testing

To ensure changes don't introduce regressions this tool uses an automated test
suite consisting of HTTP mocks via go-vcr and Terraform configuration files to
assert against. The premise is that we mock the HTTP responses from the
ZPA and/or ZIA APIs to ensure we don't need to create and delete real resources to
test. The Terraform files then allow us to build what the resource structure is
expected to look like and once the tool parses the API response, we can compare
that to the static file.

License
=========

MIT License

=======

Copyright (c) 2022 [Zscaler](https://github.com/zscaler)

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
