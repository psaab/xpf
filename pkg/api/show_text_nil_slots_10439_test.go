package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10439 (GEMINI-049-082): every REST /show-text map/slice iteration must skip
// (or otherwise safely render) present-but-nil entries without panicking. A nil
// map value is admitted by the tolerant-load / peer-sync path (#1960) that the
// application-set loop already tolerates via its #5221 guard; the remaining
// loops dereferenced the value unconditionally, so one nil slot made the whole
// topic panic (net/http recovers a handler panic into a 500, with repeated
// panic/log churn on retry).
//
// Each cell below commits one real entry, injects a nil slot into the live
// ActiveConfig map/slice, and drives the live showTextHandler for that topic.
// Reverting any `if v == nil { continue }` guard in show_text.go makes its cell
// panic (RED on revert). The panic is recovered into a hard test failure so one
// RED cell cannot crash the package test binary; the recovery is test harness
// only, never the correctness mechanism.

// renderShowTextNoPanic drives the live show-text handler for topic and fails
// the test if the handler panics on a nil slot instead of skipping it.
func renderShowTextNoPanic(t *testing.T, s *Server, topic, what string) string {
	t.Helper()
	var out string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("show-text %s handler panicked on a nil %s "+
					"(must skip, not panic): %v", topic, what, r)
			}
		}()
		out = renderShowTextBody(t, s, topic)
	}()
	return out
}

func TestAPIShowTextNilScheduler10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set schedulers scheduler workday daily start-time 09:00:00",
		"set schedulers scheduler workday daily stop-time 17:00:00",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || len(cfg.Schedulers) == 0 {
		t.Fatalf("fixture missing schedulers")
	}
	cfg.Schedulers["zz-nil-sched"] = nil

	out := renderShowTextNoPanic(t, s, "schedulers", "scheduler value")
	if !strings.Contains(out, "Scheduler: workday") {
		t.Fatalf("show-text schedulers missing the real scheduler; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-sched") {
		t.Fatalf("show-text schedulers rendered the nil scheduler slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilSNMPCommunity10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set snmp community comm_real authorization read-only",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.Communities) == 0 {
		t.Fatalf("fixture missing snmp communities")
	}
	cfg.System.SNMP.Communities["zz-nil-comm"] = nil

	out := renderShowTextNoPanic(t, s, "snmp", "community value")
	// #5315: the community string is masked, so the sibling-preserved signal
	// is the visible authorization mode plus exactly one redaction token —
	// the nil slot must not render a second (empty) row.
	if !strings.Contains(out, "read-only") {
		t.Fatalf("show-text snmp missing the real community authorization; got:\n%s", out)
	}
	if n := strings.Count(out, config.SecretDataPlaceholder); n != 1 {
		t.Fatalf("show-text snmp rendered %d redacted community rows, want 1 "+
			"(nil slot must be skipped); got:\n%s", n, out)
	}
}

func TestAPIShowTextNilSNMPTrapGroup10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set snmp trap-group primary targets 192.0.2.10",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.TrapGroups) == 0 {
		t.Fatalf("fixture missing snmp trap-groups")
	}
	cfg.System.SNMP.TrapGroups["zz-nil-tg"] = nil

	out := renderShowTextNoPanic(t, s, "snmp", "trap-group value")
	if !strings.Contains(out, "primary") || !strings.Contains(out, "192.0.2.10") {
		t.Fatalf("show-text snmp missing the real trap-group; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-tg") {
		t.Fatalf("show-text snmp rendered the nil trap-group slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilDHCPServerGroup10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil ||
		len(cfg.ForwardingOptions.DHCPRelay.ServerGroups) == 0 {
		t.Fatalf("fixture missing dhcp-relay server-groups")
	}
	cfg.ForwardingOptions.DHCPRelay.ServerGroups["zz-nil-sg"] = nil

	out := renderShowTextNoPanic(t, s, "dhcp-relay", "server-group value")
	if !strings.Contains(out, "sg") || !strings.Contains(out, "10.1.1.1") {
		t.Fatalf("show-text dhcp-relay missing the real server-group; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-sg") {
		t.Fatalf("show-text dhcp-relay rendered the nil server-group slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilDHCPRelayGroup10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil ||
		len(cfg.ForwardingOptions.DHCPRelay.Groups) == 0 {
		t.Fatalf("fixture missing dhcp-relay groups")
	}
	cfg.ForwardingOptions.DHCPRelay.Groups["zz-nil-group"] = nil

	out := renderShowTextNoPanic(t, s, "dhcp-relay", "relay-group value")
	if !strings.Contains(out, "lan") || !strings.Contains(out, "ge-0/0/0.0") {
		t.Fatalf("show-text dhcp-relay missing the real relay-group; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-group") {
		t.Fatalf("show-text dhcp-relay rendered the nil relay-group slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilFirewallFilter10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || len(cfg.Firewall.FiltersInet) == 0 {
		t.Fatalf("fixture missing inet firewall filters")
	}
	cfg.Firewall.FiltersInet["zz-nil-filter"] = nil

	out := renderShowTextNoPanic(t, s, "firewall", "filter value")
	if !strings.Contains(out, "Filter: f1") || !strings.Contains(out, "Term: t1") {
		t.Fatalf("show-text firewall missing the real filter; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-filter") {
		t.Fatalf("show-text firewall rendered the nil filter slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilFirewallTerm10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then accept",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Firewall.FiltersInet["f1"] == nil ||
		len(cfg.Firewall.FiltersInet["f1"].Terms) == 0 {
		t.Fatalf("fixture missing firewall filter terms")
	}
	// A nil element inside a live filter's Terms slice — the inner loop must
	// skip it while still rendering the valid sibling term.
	cfg.Firewall.FiltersInet["f1"].Terms = append(cfg.Firewall.FiltersInet["f1"].Terms, nil)

	out := renderShowTextNoPanic(t, s, "firewall", "filter term")
	if !strings.Contains(out, "Term: t1") {
		t.Fatalf("show-text firewall missing the real term; got:\n%s", out)
	}
}

func TestAPIShowTextNilDynamicAddressFeed10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name bad-actors profile feed-name malware",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		t.Fatalf("fixture missing dynamic-address feed-servers")
	}
	cfg.Security.DynamicAddress.FeedServers["zz-nil-feed"] = nil

	out := renderShowTextNoPanic(t, s, "dynamic-address", "feed-server value")
	if !strings.Contains(out, "Feed server: threat") {
		t.Fatalf("show-text dynamic-address missing the real feed; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-feed") {
		t.Fatalf("show-text dynamic-address rendered the nil feed slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilAddressBookEntry10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set security address-book global address host_real 10.0.0.1/32",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil ||
		len(cfg.Security.AddressBook.Addresses) == 0 {
		t.Fatalf("fixture missing address-book addresses")
	}
	cfg.Security.AddressBook.Addresses["zz-nil-addr"] = nil

	out := renderShowTextNoPanic(t, s, "address-book", "address value")
	if !strings.Contains(out, "host_real") || !strings.Contains(out, "10.0.0.1/32") {
		t.Fatalf("show-text address-book missing the real address; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-addr") {
		t.Fatalf("show-text address-book rendered the nil address slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilAddressBookSet10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set security address-book global address host_real 10.0.0.1/32",
		"set security address-book global address-set set_real address host_real",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil ||
		len(cfg.Security.AddressBook.AddressSets) == 0 {
		t.Fatalf("fixture missing address-book address-sets")
	}
	cfg.Security.AddressBook.AddressSets["zz-nil-set"] = nil

	out := renderShowTextNoPanic(t, s, "address-book", "address-set value")
	if !strings.Contains(out, "set_real") {
		t.Fatalf("show-text address-book missing the real address-set; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-set") {
		t.Fatalf("show-text address-book rendered the nil address-set slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilApplication10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set applications application my-app protocol tcp",
		"set applications application my-app destination-port 8080",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || len(cfg.Applications.Applications) == 0 {
		t.Fatalf("fixture missing applications")
	}
	cfg.Applications.Applications["zz-nil-app"] = nil

	out := renderShowTextNoPanic(t, s, "applications", "application value")
	if !strings.Contains(out, "my-app") {
		t.Fatalf("show-text applications missing the real application; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-app") {
		t.Fatalf("show-text applications rendered the nil application slot; got:\n%s", out)
	}
}

func TestAPIShowTextNilFlowTemplate10439(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set services flow-monitoring version9 template t1 flow-active-timeout 60",
	})
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Services.FlowMonitoring == nil ||
		cfg.Services.FlowMonitoring.Version9 == nil ||
		len(cfg.Services.FlowMonitoring.Version9.Templates) == 0 {
		t.Fatalf("fixture missing flow-monitoring v9 templates")
	}
	cfg.Services.FlowMonitoring.Version9.Templates["zz-nil-tmpl"] = nil

	out := renderShowTextNoPanic(t, s, "flow-monitoring", "template value")
	if !strings.Contains(out, "Template: t1") {
		t.Fatalf("show-text flow-monitoring missing the real template; got:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-tmpl") {
		t.Fatalf("show-text flow-monitoring rendered the nil template slot; got:\n%s", out)
	}
}
