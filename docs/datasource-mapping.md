# Data Source ID Replacement Feature

## Overview

The Zscaler Terraformer now automatically replaces resource attribute IDs with data source references, making the generated Terraform code more maintainable and user-friendly.

## Problem Solved

**Before**: Resource attributes contained hard-coded IDs that were difficult for users to understand and maintain:

```hcl
resource "zia_firewall_filtering_rule" "resource_zia_firewall_filtering_rule_1499949" {
  action              = "ALLOW"
  name                = "Firewall_5"
  device_groups {
    id = [35235179]
  }
  location_groups {
    id = [66754722, 66754723]
  }
  time_windows {
    id = [554, 553]
  }
}
```

**After**: IDs are automatically replaced with readable data source references:

```hcl
resource "zia_firewall_filtering_rule" "resource_zia_firewall_filtering_rule_1499949" {
  action              = "ALLOW"
  name                = "Firewall_5"
  device_groups {
    id = [data.zia_device_groups.this_35235179.id]
  }
  location_groups {
    id = [data.zia_location_groups.this_66754722.id, data.zia_location_groups.this_66754723.id]
  }
  time_windows {
    id = [data.zia_firewall_filtering_time_window.this_554.id, data.zia_firewall_filtering_time_window.this_553.id]
  }
}
```

And a corresponding `datasource.tf` file is automatically generated:

```hcl
# Data sources for attribute ID references
# Generated automatically by Zscaler Terraformer

data "zia_device_groups" "this_35235179" {
  id = 35235179
}

data "zia_location_groups" "this_66754722" {
  id = 66754722
}

data "zia_location_groups" "this_66754723" {
  id = 66754723
}

data "zia_firewall_filtering_time_window" "this_554" {
  id = 554
}

data "zia_firewall_filtering_time_window" "this_553" {
  id = 553
}
```

## How It Works

### Architecture

The data source replacement system works in three phases:

1. **Collection Phase**: Scans all generated `.tf` files to identify IDs in mapped attributes
2. **Generation Phase**: Creates a `datasource.tf` file with data sources for all collected IDs
3. **Replacement Phase**: Replaces the raw IDs with data source references in all `.tf` files

### Integration

The system is integrated into the existing post-processing pipeline:

1. **Resource Import & Generation**: Normal import and generation process (unchanged)
2. **Resource Reference Processing**: Existing resource-to-resource reference replacement (unchanged)
3. **Data Source Processing**: New data source ID replacement (isolated and non-interfering)

## Configuration

### Current Mappings

The following attribute-to-data-source mappings are currently supported:

| Attribute Name | Data Source Type |
|----------------|------------------|
| `location_groups` | `zia_location_groups` |
| `time_windows` | `zia_firewall_filtering_time_window` |
| `users` | `zia_user_management` |
| `groups` | `zia_group_management` |
| `departments` | `zia_department_management` |
| `proxy_gateways` | `zia_forwarding_control_proxy_gateway` |
| `device_groups` | `zia_device_groups` |
| `devices` | `zia_devices` |
| `workload_groups` | `zia_workload_groups` |

### Adding New Mappings

To add support for new attributes, simply update the `GetDataSourceMappings()` function in `terraformutils/helpers/datasource_processor.go`:

```go
func GetDataSourceMappings() []DataSourceMapping {
	return []DataSourceMapping{
		// Existing mappings...
		{"location_groups", "zia_location_groups"},
		{"time_windows", "zia_firewall_filtering_time_window"},
		// Add new mappings here:
		{"new_attribute", "zia_new_data_source"},
	}
}
```

## Usage

The data source replacement feature is automatically enabled and requires no additional configuration. When you run:

```bash
zscaler-terraformer import zia --resources=zia_firewall_filtering_rule
```

The system will:

1. Import and generate the resource `.tf` files
2. Process resource-to-resource references (existing functionality)
3. Collect data source IDs from mapped attributes
4. Generate `datasource.tf` with required data sources
5. Replace raw IDs with data source references

## Files Generated

### Resource Files
- `zia_firewall_filtering_rule.tf` - Contains resources with data source references
- Other resource type files as requested

### Supporting Files
- `outputs.tf` - Resource outputs (existing functionality)
- `datasource.tf` - Data sources for attribute references (new)
- `zia-provider.tf` - Provider configuration

## Technical Details

### Pattern Matching

The system uses regex patterns with word boundaries to ensure exact attribute name matches:

```go
pattern := fmt.Sprintf(`(?ms)\b%s\s*\{[^}]*id\s*=\s*\[([^\]]+)\][^}]*\}`, regexp.QuoteMeta(attributeName))
```

This ensures that:
- `device_groups` matches only `device_groups`, not `location_groups`
- Multi-line blocks are properly handled
- Nested structures are correctly parsed

### ID Extraction

The system handles various ID formats:
- Single IDs: `[123]`
- Multiple IDs: `[123, 456, 789]`
- Quoted IDs: `["123", "456"]`
- Mixed formats: `["123, 456"]`

### Reference Generation

Data source references follow the pattern:
```
data.<data_source_type>.this_<id>.id
```

For example:
- ID `123` for `zia_location_groups` becomes `data.zia_location_groups.this_123.id`

## Error Handling

The system is designed to be non-disruptive:

- **Collection Errors**: Logged as warnings, processing continues
- **Generation Errors**: Logged as warnings, existing functionality unaffected
- **Replacement Errors**: Individual file errors logged, other files processed normally
- **Type Mismatches**: IDs kept as-is if data source type doesn't match expected type

## Performance

- **Minimal Overhead**: Only processes files that contain mapped attributes
- **Efficient Regex**: Uses compiled patterns with word boundaries for fast matching
- **Deduplication**: Tracks processed IDs to avoid duplicates
- **Isolated Processing**: Runs after existing functionality to avoid interference

## Troubleshooting

### Common Issues

1. **IDs not replaced**: Check if the attribute name is in the mapping configuration
2. **Wrong data source type**: Verify the mapping points to the correct data source
3. **Missing datasource.tf**: Check logs for collection or generation errors
4. **Partial replacement**: Some IDs might not have matching data source types

### Debug Information

Enable debug logging to see detailed processing information:
```bash
export LOG_LEVEL=debug
zscaler-terraformer import zia --resources=zia_firewall_filtering_rule
```

### Log Messages

- `[INFO] Collected X unique data source IDs` - Shows how many IDs were found
- `[INFO] Generated datasource.tf with X data sources` - Confirms file generation
- `[INFO] Updated data source references in <file>` - Shows which files were processed
- `[WARNING] Data source post-processing failed` - Indicates errors (non-fatal)

## Future Enhancements

Potential improvements for future versions:

1. **Custom Naming**: Allow custom data source naming patterns
2. **Conditional Processing**: Enable/disable processing per resource type
3. **Advanced Filtering**: Skip certain IDs based on criteria
4. **ZPA Support**: Extend to ZPA resources and data sources
5. **Validation**: Verify data source references are valid before replacement
