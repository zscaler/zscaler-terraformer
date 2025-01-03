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
## Usage

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
      --exclude string                      Which resources you wish to exclude
  -h, --help                                help for zscaler-terraformer
      --resource-type string                Which resource you wish to generate
      --resources string                    Which resources you wish to import
      --terraform-install-path string       Path to the default Terraform installation (default ".")
  -v, --verbose                             Specify verbose output (same as setting log level to debug)
      --version                              Display the release version
      --zia-terraform-install-path string    Path to the ZIA Terraform installation (default ".")
      --zia_api_key string                   ZIA API Key
      --zia_cloud string                     ZIA Cloud (i.e zscalerthree)
      --zia_password string                  ZIA password
      --zia_username string                  ZIA username
      --zpa-terraform-install-path string    Path to the ZPA Terraform installation (default ".")
      --zpa_client_id string                 ZPA client ID
      --zpa_client_secret string             ZPA client secret
      --zpa_customer_id string               ZPA Customer ID
      --zpa_cloud string                     ZPA Cloud (``BETA``, ``GOV``, ``GOVUS``, ``PRODUCTION``, ``ZPATWO``)

Use "zscaler-terraformer [command] --help" for more information about a command.

```

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

### ZPA Environment Variables

``zscaler-terraformer`` for ZPA supports the following environment variables:

```bash
export ZPA_CLIENT_ID      = "xxxxxxxxxxxxxxxx"
export ZPA_CLIENT_SECRET  = "xxxxxxxxxxxxxxxx"
export ZPA_CUSTOMER_ID    = "xxxxxxxxxxxxxxxx"
export ZPA_CLOUD          = "BETA", "GOV", "GOVUS", "PRODUCTION" or "ZPATWO"
```

### ZPA Inline Authentication

```bash
zscaler-terraformer import --resources="zpa" \
--zpa_client_id="xxxxxxxxxxxxxxxx" \
--zpa_client_secret="xxxxxxxxxxxxxxxx" \
--zpa_customer_id="xxxxxxxxxxxxxxxx" \
--zpa_cloud="BETA", "GOV", "GOVUS", "PRODUCTION" or "ZPATWO"
```

### ZIA Environment Variables

``zscaler-terraformer`` for ZIA supports the following environment variables:

```bash
export ZIA_USERNAME = "xxxxxxxxxxxxxxxx"
export ZIA_PASSWORD = "xxxxxxxxxxxxxxxx"
export ZIA_API_KEY  = "xxxxxxxxxxxxxxxx"
export ZIA_CLOUD    = "xxxxxxxxxxxxxxxx" (i.e zscalerthree)

```

### ZIA Inline Authentication

```bash
zscaler-terraformer import --resources="zia" \
--zia_username="xxxxxxxxxxxxxxxx" \
--zia_password="xxxxxxxxxxxxxxxx" \
--zia_api_key="xxxxxxxxxxxxxxxx" \
--zia_cloud=(i.e zscalerthree)
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
curl -LO "https://github.com/zscaler/zscaler-terraformer/releases/download/$(curl -s https://api.github.com/repos/zscaler/zscaler-terraformer/releases/latest | grep tag_name | cut -d '"' -f 4)/zscaler-terraformer_1.3.0_linux_amd64.zip"
unzip zscaler-terraformer_1.3.0_linux_amd64.zip
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
