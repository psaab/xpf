package cli

import (
	"path/filepath"
	"strings"
	"testing"

	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15174 (B18-03): the two local-CLI PermView renderers in
// show_services_ddns.go printed update-server raw, while show configuration
// and both gRPC twins (server_show_dhcp_lldp_snmp.go) redact it through
// config.RedactURL (#9497). A userinfo-bearing value (user:secret@host) reached
// every view-class console/SSH login and captured command output.
//
// This mirrors the #9497 gRPC test against the LOCAL CLI renderers
// (showServicesDynamicDNS / showDHCPDynamicDNS), driving both normal and
// detail mode. Fixtures go through the store (LoadOverride+Commit) so the
// config value is exactly what ActiveConfig() returns at render time.

const (
	cliSecret15174 = "s3cr3t"
	cliCred15174   = "user:" + cliSecret15174 + "@dns.example.com"
)

func assertDDNSRedacted15174(t *testing.T, surface string, detail bool, out string) {
	t.Helper()
	if strings.Contains(out, cliSecret15174) {
		t.Errorf("#15174: %s (detail=%v) leaked the update-server credential:\n%s", surface, detail, out)
	}
	if !strings.Contains(out, "<redacted>@dns.example.com") {
		t.Errorf("%s (detail=%v): expected the redacted update-server with its host kept:\n%s", surface, detail, out)
	}
}

func TestShowServicesDynamicDNSLocalCLIRedactsUpdateServer15174(t *testing.T) {
	for _, detail := range []bool{false, true} {
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`
system {
    services {
        dynamic-dns {
            provider p1 {
                backend rfc2136;
                update-server "` + cliCred15174 + `";
                tsig-key k1;
            }
        }
    }
}
`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if got := store.ActiveConfig().System.Services.DynamicDNS.Providers["p1"].UpdateServer; got != cliCred15174 {
			t.Fatalf("fixture premise: provider update-server = %q, want %q (config must retain the raw value; redaction is display-only)", got, cliCred15174)
		}
		c := &CLI{
			store: store,
			surfaceADDNSStatsFn: func() *ddnspkg.SurfaceAStats {
				return &ddnspkg.SurfaceAStats{}
			},
			surfaceADDNSStatusFn: func() []ddnspkg.SurfaceAStatusView { return nil },
		}
		var callErr error
		out := captureStdout(t, func() { callErr = c.showServicesDynamicDNS(detail) })
		if callErr != nil {
			t.Fatalf("showServicesDynamicDNS(detail=%v): %v", detail, callErr)
		}
		assertDDNSRedacted15174(t, "CLI services dynamic-dns", detail, out)
	}
}

func TestShowDHCPDynamicDNSLocalCLIRedactsUpdateServer15174(t *testing.T) {
	for _, detail := range []bool{false, true} {
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`
system {
    services {
        dhcp-local-server {
            dynamic-dns {
                enable;
                domain example.com;
                backend rfc2136;
                update-server "` + cliCred15174 + `";
                tsig-key k1;
            }
        }
    }
}
`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if got := store.ActiveConfig().System.DHCPServer.DynamicDNS.UpdateServer; got != cliCred15174 {
			t.Fatalf("fixture premise: dhcp ddns update-server = %q, want %q", got, cliCred15174)
		}
		c := &CLI{
			store:       store,
			ddnsStatsFn: func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{} },
			ddnsOwnedRecordsFn: func() []dhcpserver.DDNSOwnedRecordView {
				return nil
			},
		}
		var callErr error
		out := captureStdout(t, func() { callErr = c.showDHCPDynamicDNS(detail) })
		if callErr != nil {
			t.Fatalf("showDHCPDynamicDNS(detail=%v): %v", detail, callErr)
		}
		assertDDNSRedacted15174(t, "CLI dhcp-server dynamic-dns", detail, out)
	}
}

// CONTROL: a clean host:port renders unchanged, so redaction is not hiding
// the field altogether (mirrors the #9497 control).
func TestShowDDNSLocalCLICleanUpdateServerUnchanged15174(t *testing.T) {
	for _, detail := range []bool{false, true} {
		// Surface A
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`
system {
    services {
        dynamic-dns {
            provider p1 {
                backend rfc2136;
                update-server "ns1.example.com:53";
            }
        }
        dhcp-local-server {
            dynamic-dns {
                enable;
                domain example.com;
                backend rfc2136;
                update-server "ns1.example.com:53";
            }
        }
    }
}
`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		c := &CLI{
			store: store,
			surfaceADDNSStatsFn: func() *ddnspkg.SurfaceAStats {
				return &ddnspkg.SurfaceAStats{}
			},
			surfaceADDNSStatusFn: func() []ddnspkg.SurfaceAStatusView { return nil },
			ddnsStatsFn:          func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{} },
			ddnsOwnedRecordsFn:   func() []dhcpserver.DDNSOwnedRecordView { return nil },
		}
		var err1 error
		outSvc := captureStdout(t, func() { err1 = c.showServicesDynamicDNS(detail) })
		if err1 != nil {
			t.Fatalf("showServicesDynamicDNS(detail=%v): %v", detail, err1)
		}
		if !strings.Contains(outSvc, "ns1.example.com:53") {
			t.Errorf("CLI services dynamic-dns (detail=%v): clean host:port must render unchanged:\n%s", detail, outSvc)
		}
		var err2 error
		outDHCP := captureStdout(t, func() { err2 = c.showDHCPDynamicDNS(detail) })
		if err2 != nil {
			t.Fatalf("showDHCPDynamicDNS(detail=%v): %v", detail, err2)
		}
		if !strings.Contains(outDHCP, "ns1.example.com:53") {
			t.Errorf("CLI dhcp-server dynamic-dns (detail=%v): clean host:port must render unchanged:\n%s", detail, outDHCP)
		}
	}
}
