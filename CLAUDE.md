# Zscaler Terraformer

This project uses Cursor rules and Claude skills for AI assistance.

## Cursor Rules (.cursor/rules/)

| Rule | Description |
|------|-------------|
| `zscaler-terraformer-add-resource.mdc` | Pattern for adding new ZIA/ZPA/ZTC resources |
| `zscaler-terraformer-tests.mdc` | Mandatory test requirements for new resources |
| `zscaler-terraformer-debug.mdc` | Debug logging (env vars, --collect-logs) |
| `zscaler-terraformer-datasource-mapping.mdc` | Resource/datasource attribute mapping |
| `zscaler-terraformer-computed-attributes.mdc` | Strip computed attributes (id) from HCL |
| `zscaler-terraformer-release-docs.mdc` | README, CHANGELOG, release-notes, version.go updates |

## Claude Skills (.claude/skills/)

| Skill | Use when |
|-------|----------|
| `zscaler-terraformer-add-resource` | Implementing support for a new resource |
| `zscaler-terraformer-debug` | Troubleshooting, capturing SDK debug output |
| `zscaler-terraformer-datasource-mapping` | Adding attribute→datasource mappings |
| `zscaler-terraformer-computed-attributes` | Stripping computed attributes (id) from HCL |
| `zscaler-terraformer-release-docs` | README, CHANGELOG, release-notes, version.go updates |
| `zscaler-terraformer-tests` | Adding or running tests for resources |

## Quick reference

- **SDK:** `github.com/zscaler/zscaler-sdk-go` (vendor in this repo)
- **Debug:** `export ZSCALER_SDK_LOG=true ZSCALER_SDK_VERBOSE=true` or `--collect-logs`
- **Tests:** `go test ./tests/unit/... -v`
