package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15782: request system license fails closed with clear unimplemented error.
func TestRequestSystemLicenseFailClosed15782(t *testing.T) {
	c := &CLI{}
	for _, args := range [][]string{{"license"}, {"license", "update"}, {"license", "add", "key"}} {
		err := c.handleRequestSystem(args)
		if err == nil || !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("handleRequestSystem(%v) = %v, want not implemented", args, err)
		}
	}
}

// #15782: shared license renderer (used by both local CLI and ShowText).
func TestLicenseText15782(t *testing.T) {
	var sb strings.Builder
	config.LicenseText(nil, &sb)
	if !strings.Contains(sb.String(), "License: open-source") {
		t.Errorf("nil cfg: %q", sb.String())
	}
	sb.Reset()
	cfg := &config.Config{}
	cfg.System.LicenseAutoUpdateURLs = []string{"https://user:secret@lic.example/k?token=x", "https://b.example/k"}
	cfg.System.LicenseAutoUpdate = cfg.System.LicenseAutoUpdateURLs[0]
	config.LicenseText(cfg, &sb)
	out := sb.String()
	if !strings.Contains(out, "lic.example") || !strings.Contains(out, "b.example") {
		t.Errorf("urls missing: %q", out)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, "token=x") {
		t.Errorf("secret leaked: %q", out)
	}
}
