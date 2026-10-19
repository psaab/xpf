package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15652 V12-04: show paths must expand via ResolveApplication/ExpandApplicationSet.
// Predefined, term-based and set-backed apps must render protocol/port/ALG.

func show15652Store(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(`
applications {
    application web-term {
        term t-http { protocol tcp; destination-port 8080; }
        term t-https { protocol tcp; destination-port 8443; alg https; }
    }
    application myweb { protocol tcp; destination-port 8080; }
    application-set my-set { application myweb; application junos-https; }
}
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy p1 { match { source-address any; destination-address any; application my-set; } then { permit; } }
            policy p2 { match { source-address any; destination-address any; application junos-https; } then { permit; } }
            policy p3 { match { source-address any; destination-address any; application web-term; } then { permit; } }
        }
    }
}
`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	return &CLI{store: store}
}

func TestShowPolicyDetailExpandsApps15652(t *testing.T) {
	c := show15652Store(t)
	cfg := c.store.ActiveConfig()
	out := captureStdout(t, func() { _ = c.showPoliciesDetail(cfg, "trust", "untrust") })
	// predefined junos-https tcp/443 must appear in detail
	if !strings.Contains(out, "443") {
		t.Fatalf("policy detail must render predefined junos-https port 443 via resolver:\n%s", out)
	}
	// set-backed my-set -> myweb 8080 and junos-https 443
	if !strings.Contains(out, "8080") {
		t.Fatalf("policy detail must expand application-set my-set to myweb 8080:\n%s", out)
	}
	// term-based web-term -> 8080/8443
	if !strings.Contains(out, "8443") {
		t.Fatalf("policy detail must expand term-based web-term to 8443:\n%s", out)
	}
}

func TestShowApplicationsExpandsSets15652(t *testing.T) {
	c := show15652Store(t)
	// Filtering by set must show member details resolved (predefined member too)
	out := captureStdout(t, func() { _ = c.showApplications([]string{"my-set"}) })
	if !strings.Contains(out, "8080") {
		t.Fatalf("show applications my-set must render myweb 8080:\n%s", out)
	}
	if !strings.Contains(out, "443") {
		t.Fatalf("show applications my-set must render predefined member junos-https 443:\n%s", out)
	}
	// Filtering by term-based app must show term ports
	out2 := captureStdout(t, func() { _ = c.showApplications([]string{"web-term"}) })
	if !strings.Contains(out2, "8080") || !strings.Contains(out2, "8443") {
		t.Fatalf("show applications web-term must render term ports 8080/8443:\n%s", out2)
	}
	// Predefined filtered
	out3 := captureStdout(t, func() { _ = c.showApplications([]string{"junos-https"}) })
	if !strings.Contains(out3, "443") {
		t.Fatalf("show applications junos-https must render 443:\n%s", out3)
	}
}
