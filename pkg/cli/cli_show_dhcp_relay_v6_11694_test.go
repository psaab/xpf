package cli

import (
	"github.com/psaab/xpf/pkg/dhcprelay"
	"path/filepath"
	"strings"
	"testing"
)

// #11694: `show dhcp-relay` rendered no DHCPv6 relay config at all — a v6-only
// configuration printed an empty section. The v6 server-groups/groups must be
// named on the CLI surface.
func TestShowDHCPRelayV6OnlyNamesGroupAndServers11694(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set forwarding-options dhcp-relay dhcpv6 server-group sg6 2001:db8::5",
		"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group sg6",
		"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}
	got := captureStdout(t, func() {
		if err := c.showDHCPRelay(); err != nil {
			t.Fatalf("showDHCPRelay: %v", err)
		}
	})
	for _, want := range []string{"sg6", "2001:db8::5", "g6", "ge-0/0/0.0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("v6-only show dhcp-relay output missing %q; got:\n%s", want, got)
		}
	}
}

// #11694: the v6 rendering is purely additive — a v4-only configuration must
// render byte-identical output before and after the fix.
func TestShowDHCPRelayV4OnlyByteStable11694(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}
	got := captureStdout(t, func() {
		if err := c.showDHCPRelay(); err != nil {
			t.Fatalf("showDHCPRelay: %v", err)
		}
	})
	want := "Server groups:\n" +
		"  sg: 10.1.1.1\n" +
		"Relay groups:\n" +
		"  lan:\n" +
		"    Interfaces: ge-0/0/0.0\n" +
		"    Active server group: sg\n"
	if got != want {
		t.Fatalf("v4-only showDHCPRelay output drifted\n got: %q\nwant: %q", got, want)
	}
}

func TestWriteDHCPRelayStatsV4OnlyByteStable11694(t *testing.T) {
	var output strings.Builder
	writeDHCPRelayStats(&output, []dhcprelay.RelayStats{{
		Interface: "lan", KernelInterface: "eth0",
		RequestsRelayed: 1, RepliesForwarded: 2, RequestsDroppedMaxHops: 3,
		RequestsDroppedRateLimit: 4, RepliesL2Unicast: 5, RepliesUnicastCiaddr: 6,
		RepliesBroadcastFlag1: 7, RepliesBroadcastForced: 8,
		RepliesBroadcastNoTarget: 9, RepliesBroadcastL2Fallback: 10,
		RepliesBroadcastNak: 11, RepliesDroppedUnknownServer: 12,
		PendingSize: 13, PendingCapacity: 14, RepliesDroppedNoRequest: 15,
		PendingEvicted: 16, RepliesDroppedForceRenew: 17,
	}})
	got := output.String()
	want := "\nRelay statistics:\n" +
		"  Interface        Bound device     Requests relayed   Replies forwarded  Dropped (max-hops) Dropped (rate-limit)\n" +
		"  lan              eth0             1                  2                  3                  4\n" +
		"\nReply delivery (#2076):\n" +
		"  Interface        L2-unicast ciaddr     bcast-flag bcast-fwd  no-target  L2-fallback  nak-bcast\n" +
		"  lan              5          6          7          8          9          10           11\n" +
		"\nReply source validation (#4163):\n" +
		"  Interface        Dropped (unknown server)\n" +
		"  lan              12\n" +
		"\nReply request binding (#6562):\n" +
		"  Interface        Pending        Dropped (no-request)   Pending evicted  Refused (forcerenew)\n" +
		"  lan              13/14          15                     16               17\n"
	if got != want {
		t.Fatalf("v4-only relay statistics output drifted\n got: %q\nwant: %q", got, want)
	}
}
func TestWriteDHCPRelayStatsSeparatesFamilies11694(t *testing.T) {
	var output strings.Builder
	writeDHCPRelayStats(&output, []dhcprelay.RelayStats{
		{Interface: "v4lan", RequestsRelayed: 4},
		{
			Family: "inet6", Interface: "v6lan", RequestsRelayed: 6, RequestsDroppedBackup: 14,
			RequestsDroppedNested: 1, RequestsDroppedParse: 2, RequestsDroppedPort: 3,
			RequestsDroppedPeer: 4, RequestsDroppedBuild: 5,
			RepliesDroppedIID: 6, RepliesDroppedParse: 7, RepliesDroppedInvalid: 8,
			RepliesDroppedNested: 9, RepliesDroppedDispatcherParse: 10,
			RepliesDroppedDispatcherEmptyIID: 11, RepliesDroppedDispatcherUnknownIID: 12,
			RepliesDroppedDispatcherAmbiguous: 13,
		},
	})
	got := output.String()
	v6Start := strings.Index(got, "\nDHCPv6 relay statistics (inet6):\n")
	if v6Start < 0 {
		t.Fatalf("missing family-labeled DHCPv6 statistics; got:\n%s", got)
	}
	if v4 := got[:v6Start]; !strings.Contains(v4, "v4lan") || strings.Contains(v4, "v6lan") {
		t.Fatalf("v4 statistics are not isolated from inet6 rows:\n%s", v4)
	}
	v6 := got[v6Start:]
	if !strings.Contains(v6, "v6lan") || strings.Contains(v6, "v4lan") {
		t.Fatalf("inet6 statistics are not isolated from v4 rows:\n%s", v6)
	}
	dropSection := v6[strings.Index(v6, "DHCPv6 drop reasons (inet6):"):]
	foundDropRow := false
	for _, line := range strings.Split(dropSection, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "v6lan" {
			foundDropRow = strings.Join(fields, " ") == "v6lan 1 2 3 4 5 6 7 8 9 10 11 12/13"
		}
	}
	if !foundDropRow {
		t.Fatalf("DHCPv6 drop counters not rendered with their correct values:\n%s", dropSection)
	}

	foundFamilyRow := false
	for _, line := range strings.Split(v6, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "v6lan" {
			foundFamilyRow = strings.Join(fields, " ") == "v6lan v6lan 6 0 14 0"
			break
		}
	}
	if !foundFamilyRow {
		t.Fatalf("DHCPv6 family stats did not render backup-drop value in family-specific table:\n%s", v6)
	}
}
