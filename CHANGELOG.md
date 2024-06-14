# Changelog

## 1.2.1 (June, 13 2024)

### Notes

- Release date: **(June, 13 2024)**
- Supported Terraform version: **v1.x.x**

### Fixes
- [PR #203](https://github.com/zscaler/zscaler-terraformer/pull/203) Improved the command ``zscaler-terraformer version`` output to display the CLI version, terraform version and latest available version.

## 1.2.0 (June, 7 2024)

### Notes

- Release date: **(June, 7 2024)**
- Supported Terraform version: **v1.x.x**

### Deprecations
- [PR #199](https://github.com/zscaler/zscaler-terraformer/pull/199) Deprecated the following ZPA resource:
    - `zpa_cloud_browser_isolation_banner`
    - `zpa_cloud_browser_isolation_certificate`
    - `zpa_cloud_browser_isolation_external_profile`

### Fixes
- [PR #199](https://github.com/zscaler/zscaler-terraformer/pull/199) Implemented fix to resource `zpa_microtenant_controller`, to ignore the importing of `Default` Microtenant.

## 1.1.3 (May, 18 2024)

### Notes

- Release date: **(May, 18 2024)**
- Supported Terraform version: **v1.x.x**

### Fixes
- [PR #191](https://github.com/zscaler/zscaler-terraformer/pull/191) Fixed ZPA `provisioning_key` computed attribute. The attribute is now excluded from the HCL generation during the import process.

- [PR #191](https://github.com/zscaler/zscaler-terraformer/pull/191) Fixed ZPA `zpa_service_edge_group` to convert `is_public` attribute to expected bool format.

- [PR #191](https://github.com/zscaler/zscaler-terraformer/pull/191) Fixed ZPA `zpa_service_edge_group` to properly convert nested attribute blocks `service_edge` and `trusted_networks`

## 1.1.2 (May, 17 2024)

### Notes

- Release date: **(May, 17 2024)**
- Supported Terraform version: **v1.x.x**

### Fixes
- [PR #190](https://github.com/zscaler/zscaler-terraformer/pull/190) Fixed ZPA `provisioning_key` computed attribute. The attribute is now excluded from the HCL generation during the import process.

## 1.1.1 (May, 7 2024)

### Notes

- Release date: **(May, 7 2024)**
- Supported Terraform version: **v1.x.x**

### Fixes
- [PR #187](https://github.com/zscaler/zscaler-terraformer/pull/187) Fixed importing issue with `zia_url_filtering_rules` attributes: `override_users` and `override_groups`. Attributes are now correctly imported as a list of IDs.

## 1.1.0 (March, 7 2024)

### Notes

- Release date: **(March, 7 2024)**
- Supported Terraform version: **v1.x.x**

### Enhancements

- [PR #176](https://github.com/zscaler/zscaler-terraformer/pull/176) Updated [support guide](/docs/guides/support.md) with new Zscaler support model.
- [PR #176](https://github.com/zscaler/zscaler-terraformer/pull/176) Introduced importing support for the following ZIA resource(s):
    * ``zia_sandbox_behavioral_analysis``
### Fixes
- [PR #176](https://github.com/zscaler/zscaler-terraformer/pull/176) Fixed importing issue with the following ZIA resources:
    * ``zia_security_settings``
    * ``zia_url_categories``

## 1.0.3 (February, 29 2024)

### Notes

- Release date: **(February, 29 2024)**
- Supported Terraform version: **v1.x.x**

### Enhancements

- [PR #173](https://github.com/zscaler/zscaler-terraformer/pull/173) Introduced the ability to exclude multiple resource names during the importing process.

## 1.0.2 (February, 15 2024)

### Notes

- Release date: **(February, 15 2024)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #171](https://github.com/zscaler/zscaler-terraformer/pull/171) Fixed ZIA ``zia_forwarding_control_rule`` missformatted ID for `zpa_gateway` nested block `id` attribute.
- [PR #171](https://github.com/zscaler/zscaler-terraformer/pull/171) Implemented exclusion of pre-built unmanaged resources for ZIA.

## 1.0.1 (February, 14 2024)

### Notes

- Release date: **(February, 14 2024)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #170](https://github.com/zscaler/zscaler-terraformer/pull/170) Fixed ZIA ``zia_firewall_filtering_rule`` missformatted ID for rules containing the `users` nested block
- [PR #170](https://github.com/zscaler/zscaler-terraformer/pull/170) Upgraded to [Zscaler-SDK-GO v2.3.9](https://github.com/zscaler/zscaler-sdk-go/releases/tag/v2.3.9)

## 1.0.0 (January, 30 2024)

### Notes

- Release date: **(January, 30 2024)**
- Supported Terraform version: **v1.x.x**

### Enhacements

- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZIA Custom ZPA Gateway import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZIA Forwarding Control Rule import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZIA DLP Engine import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZPA Microtenant import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZPA Browser Access import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZPA Cloud Browser Isolation Banner import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZPA Cloud Browser Isolation Certificate import.
- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) ✨ Added support for ZPA Cloud Browser Isolation External Profile import.

### Bug Fixes

- [PR #167](https://github.com/zscaler/zscaler-terraformer/pull/167) Fixed license error for ZPA unlicensed .

## 0.3.4 (December, 11 2023)

### Notes

- Release date: **(December, 11 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #151](https://github.com/zscaler/zscaler-terraformer/pull/151) Fixed ZIA ``zia_admin_users`` resource schema
- [PR #151](https://github.com/zscaler/zscaler-terraformer/pull/151) Upgraded to [Zscaler-SDK-GO v2.2.2](https://github.com/zscaler/zscaler-sdk-go/releases/tag/v2.2.2)

## 0.3.3 (October 18, 2023)

### Notes

- Release date: **(August 18, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #139](https://github.com/zscaler/zscaler-terraformer/pull/139) Fixed ZIA ``zia_location_management`` resource to ensure sub-locations are also imported.

## 0.3.2 (October 3, 2023)

### Notes

- Release date: **(October 3, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #134](https://github.com/zscaler/zscaler-terraformer/pull/134) Implement condition to exclude ``applications`` block from the ZPA resources `zpa_segment_group` and `zpa_server_group`.

## 0.3.1 (August 25, 2023)

### Notes

- Release date: **(August 25, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #123](https://github.com/zscaler/zscaler-terraformer/pull/123) Implemented feature flag check to `zpa_app_connector_group` to ensure import continues when error `Feature flag ui.waf disabled` error is returned.

## 0.3.0 (June 21, 2023)

### Notes

- Release date: **(June 21, 2023)**
- Supported Terraform version: **v1.x.x**

### Enhancements

- [PR #97](https://github.com/zscaler/zscaler-terraformer/pull/97) Each generated resource, will not contain the internal numeric ID generated by the ZPA Cloud. This will prevent potential name duplication during the import process.
- [PR #115](https://github.com/zscaler/zscaler-terraformer/pull/115) The Zscaler Terraformer tool now checks for existing Terraform binary version installations. If the binary is not installed, ZT will automatically download and install the latest terarform binary.
- [PR #116](https://github.com/zscaler/zscaler-terraformer/pull/116) All imported resources will not contain the following message: ``__generated__ by Zscaler Terraformer from [Resource Name]`` in the auto-generated configuration file.

### Bug Fixes

- [PR #96](https://github.com/zscaler/zscaler-terraformer/pull/96) - Fixed import of ``zpa_segment_group`` and ``zpa_server_group`` resources where the ``applications`` attribute was being imported as a Set instead of a list of IDs.

## 0.2.2 (March 01, 2023)

### Notes

- Release date: **(March 01, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #81](https://github.com/zscaler/zscaler-terraformer/pull/81) Fixed issue where the tool was not import the resource ``zia_traffic_forwarding_gre_tunnel``
- [PR #81](https://github.com/zscaler/zscaler-terraformer/pull/81) Fixed multiple issues where computed IDs for ``zia_traffic_forwarding_gre_tunnel`` and ``zia_traffic_forwarding_static_ip`` was being included in the generated HCL configuration. The fix will remove any automatic computed values generated by the upstream API.
- [PR #81](https://github.com/zscaler/zscaler-terraformer/pull/81) Fixed multiple documentation and test issues

## 0.2.1 (January 31, 2023)

### Notes

- Release date: **(January 31, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #60](https://github.com/zscaler/zscaler-terraformer/pull/60) Fixed ``zia_traffic_forwarding_static_ip`` attributes ``latitude`` and ``longitude`` to return float instead of a rounded value

## 0.2.0 (January 31, 2023)

### Notes

- Release date: **(January 31, 2023)**
- Supported Terraform version: **v1.x.x**

### Bug Fixes

- [PR #60](https://github.com/zscaler/zscaler-terraformer/pull/60) Fixed ``zia_traffic_forwarding_static_ip`` attributes ``latitude`` and ``longitude`` to return float instead of a rounded value

### Enhancements

- [PR #61](https://github.com/zscaler/zscaler-terraformer/pull/61) The tool now will format the internal resource name according to the name of the resource upstream without appending the resource ID.

## 0.1.0 (December 5, 2022)

### Notes

- Release date: **(December 5, 2022)**
- Supported Terraform version: **v1.x.x**

### Enhancements

- [PR #43](https://github.com/zscaler/zscaler-sdk-go/pull/43) Included new flag command ``--exclude`` to allow for the exclusion of specific resources when importing all provider resources.
- [PR #44](https://github.com/zscaler/zscaler-sdk-go/pull/44) Included new flag command ``--version`` to display the version of the zscaler-terraformer tool in use to facilitate troubleshooting.

### Bug Fixes

- [PR #42](https://github.com/zscaler/zscaler-sdk-go/pull/42) Fixed issue with resource import ``zia_url_categories`` where the parameter ``super_category = USER_DEFINED`` was not being set.

## 0.0.1 (November 17, 2022)

### Notes

- Release date: **(November 17, 2022)**
- Supported Terraform version: **v1.x.x**

🎉 **Initial Release** 🎉
