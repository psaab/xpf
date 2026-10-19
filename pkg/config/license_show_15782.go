package config

import (
	"fmt"
	"io"
)

// LicenseText renders `show system license` identically on local CLI and
// gRPC ShowText (#15782). URLs are redacted: they may carry entitlement
// tokens (#6733). No licensing runtime exists, so say so explicitly.
func LicenseText(cfg *Config, w io.Writer) {
	fmt.Fprintln(w, "License: open-source (no license required)")
	if cfg == nil || len(cfg.System.LicenseAutoUpdateURLs) == 0 {
		if cfg != nil && cfg.System.LicenseAutoUpdate != "" {
			fmt.Fprintf(w, "License autoupdate URL: %s (configured but NOT applied — xpf has no licensing runtime)\n", RedactURL(cfg.System.LicenseAutoUpdate))
		}
		return
	}
	for _, u := range cfg.System.LicenseAutoUpdateURLs {
		fmt.Fprintf(w, "License autoupdate URL: %s (configured but NOT applied — xpf has no licensing runtime)\n", RedactURL(u))
	}
}
