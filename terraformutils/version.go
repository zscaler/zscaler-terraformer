package terraformutils

// version is the fallback version reported by the CLI. Release builds override
// this at link time via -ldflags "-X .../terraformutils.version={{.Version}}"
// (see .goreleaser.yml and the Makefile). Keep this in sync with the latest
// release so non-release/dev builds report a sensible value.
var version = "2.1.19"

// Version returns version of provider.
func Version() string {
	return version
}
