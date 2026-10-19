package cli

import (
	"path/filepath"
	"strings"
	"testing"

	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15700: show dhcp-server dynamic-dns ignored DynamicDNSv6 and
// show services dynamic-dns printed blank update-server= for HTTP backends.

func TestShowDHCPDynamicDNS_V6Only_15700(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    services {
        dhcpv6-local-server {
            dynamic-dns {
                enable;
                domain v6.example.com;
                backend rfc2136;
                update-server "2001:db8::53";
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
	if store.ActiveConfig().System.DHCPServer.DynamicDNS != nil || store.ActiveConfig().System.DHCPServer.DynamicDNSv6 == nil {
		t.Fatalf("fixture premise: want v6-only, got v4=%v v6=%v", store.ActiveConfig().System.DHCPServer.DynamicDNS, store.ActiveConfig().System.DHCPServer.DynamicDNSv6)
	}
	c := &CLI{store: store, ddnsStatsFn: func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{OwnedRecords: 3} }, ddnsOwnedRecordsFn: func() []dhcpserver.DDNSOwnedRecordView { return nil }}
	var err error
	out := captureStdout(t, func() { err = c.showDHCPDynamicDNS(false) })
	if err != nil {
		t.Fatalf("showDHCPDynamicDNS: %v", err)
	}
	if strings.Contains(out, "not configured") {
		t.Fatalf("v6-only config must not print not-configured:\n%s", out)
	}
	if !strings.Contains(out, "v6.example.com") || !strings.Contains(out, "2001:db8::53") || !strings.Contains(out, "IPv6") || !strings.Contains(out, "applies to IPv4 by inheritance") {
		t.Fatalf("v6 policy section missing:\n%s", out)
	}
	if !strings.Contains(out, "Owned records: 3") {
		t.Fatalf("shared runtime counters must render for v6-only:\n%s", out)
	}
}

func TestShowDHCPDynamicDNS_BothFamilies_15700(t *testing.T) {
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
                domain v4.example.com;
                update-server "192.0.2.53";
            }
        }
        dhcpv6-local-server {
            dynamic-dns {
                enable;
                domain v6.example.com;
                update-server "2001:db8::53";
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
	c := &CLI{store: store, ddnsStatsFn: func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{} }}
	var err error
	out := captureStdout(t, func() { err = c.showDHCPDynamicDNS(false) })
	if err != nil {
		t.Fatalf("showDHCPDynamicDNS: %v", err)
	}
	if !strings.Contains(out, "v4.example.com") || !strings.Contains(out, "v6.example.com") || strings.Contains(out, "inheritance") {
		t.Fatalf("both independent policies must render without inheritance note:\n%s", out)
	}
}

func TestShowServicesDynamicDNS_ProviderTargets_15700(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    services {
        dynamic-dns {
            provider cf {
                backend cloudflare;
                api-token tok;
                zone example.net;
            }
            provider dyn {
                backend dyndns2;
                server "https://user:pw@members.dyndns.org/nic/update";
                username u;
                password p;
            }
            provider aws {
                backend route53;
                aws-access-key AKID;
                aws-secret-key SECRET;
                hosted-zone-id Z123;
            }
            provider gen {
                backend generic;
                url-template "https://user:pw@dns.example/upd?token=SECRET&h=%h";
            }
            provider duck {
                backend duckdns;
                api-token tok;
                server "https://www.duckdns.org/update";
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
	c := &CLI{store: store, surfaceADDNSStatsFn: func() *ddnspkg.SurfaceAStats { return &ddnspkg.SurfaceAStats{} }}
	var err error
	out := captureStdout(t, func() { err = c.showServicesDynamicDNS(false) })
	if err != nil {
		t.Fatalf("showServicesDynamicDNS: %v", err)
	}
	for _, want := range []string{"zone=example.net", "hosted-zone-id=Z123", "server=https://<redacted>@members.dyndns.org/nic/update", "server=https://www.duckdns.org/update", "url-template=https://<redacted>@dns.example/upd?<redacted>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing backend target %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "update-server=") {
		t.Errorf("non-RFC2136 providers must not print blank update-server=:\n%s", out)
	}
	if strings.Contains(out, "pw@") || strings.Contains(out, "token=SECRET") {
		t.Errorf("provider target leaked credential:\n%s", out)
	}
}
