package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// server_show_golden_test.go is the byte-identity guard for the #1700
// decomposition of server_show.go. It drives ShowText over a broad set
// of topics against a fixed configuration + deterministic runtime stubs
// and asserts the rendered output matches a golden baseline captured
// BEFORE any code motion (testdata/server_show_golden.json).
//
// The baseline is captured on the pre-split tree by running:
//
//	UPDATE_SHOW_GOLDEN=1 go test ./pkg/grpcapi/ -run TestShowTextGolden
//
// and is then committed in the FIRST commit of the refactor, so every
// subsequent extraction commit is gated by exact byte equality.
//
// Runtime-bearing branches (dynamic-address feed counts + last-fetch
// age, screen/firewall-filter hit counters, RA status) are exercised
// via deterministic stubs so they are not silently skipped. A
// normalizer maps any residual non-deterministic tokens (durations,
// timestamps, byte sizes, runtime numbers) to stable placeholders so
// genuinely environment-dependent topics (storage/core-dumps/task/log)
// still get a normalized byte-assert rather than a weak non-empty
// check.
//
// Coverage scoping (precise per Codex review):
//   - Gated behind a live netlink-backed routing.Manager (nil here →
//     "Routing manager not available" guard, itself part of the moved
//     body): route-table/route-protocol/route-prefix/test-routing.
//   - Gated behind the FRR manager (nil here → "FRR not available"):
//     route-map, bfd-peers.
//   - Gated behind a loaded dataplane (not loaded here): screen-
//     statistics*.
//   - route-instance hits the missing-filter usage path (no filter set
//     on the request) — also a moved guard branch.
//   - routing-options renders real config from the fixture (static
//     routes, AS number), not a guard.
//   - test-policy and test-zone DO exercise the real comma/key=value
//     parse + cfg lookup paths (fixture has zones + policy p1).
//   - dynamic-address and firewall-filter exercise their runtime
//     feedsFn / hit-counter branches via the stubbed feedsFn and
//     FilterTermCounters.
// The full active routing/FRR render paths are covered by the routing
// and frr packages' own tests, not duplicated here.

// goldenFixedFetch is a fixed timestamp used for the dynamic-address
// feed "last fetch ... ago" rendering so its output is deterministic.
// It is normalized away anyway, but pinning it keeps the captured
// baseline stable across runs.
var goldenFixedFetch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// goldenShowTopics is the topic set driven through ShowText. It spans
// every domain file that receives a helper in #1700 so the guard
// covers the full surface of the decomposition.
var goldenShowTopics = []string{
	// prefix-dispatch handlers
	"route-table:inet.0",
	"route-protocol:static",
	"route-prefix:10.0.0.0/8 orlonger",
	"class-of-service",
	"screen-ids-option:untrust-screen",
	"screen-statistics:untrust-screen",
	"screen-statistics-all",
	"screen-ids-option-detail:untrust-screen",
	// test-* topics are comma-separated key=value (matching the cmd/cli
	// producers in cmd/cli/main.go and the helpers' comma/`=` parsers).
	"test-policy:from=trust,to=untrust,src=10.0.1.1,dst=10.0.2.1,port=80,proto=tcp",
	"test-routing:dest=10.0.2.1",
	"test-zone:interface=ge-0-0-0.0",
	// #2118: lock the per-policy hit-count table SHAPE (headers, columns,
	// the gated render path) so a future regression in the rendered table
	// fails the golden. The golden config has `policy-stats system-wide
	// enable` set (showGoldenConfigCommands) so the table takes the
	// stats-enabled branch; the golden server's dataplane is unloaded
	// (dataplane.New(), IsLoaded()==false), so the counter columns read
	// 0/0 — the regression value is the table layout and the fact that
	// the gated path renders, not non-zero counts (those are covered by
	// the dedicated gate tests with a fake loaded dataplane).
	"policies-hit-count",
	"firewall-filter:bandwidth-output",
	"firewall-filter:bandwidth-output:inet",
	// switch cases (cfg-rendered)
	"alg",
	"dynamic-address",
	"address-book",
	"backup-router",
	"ike",
	"event-options",
	"routing-options",
	"forwarding-options",
	"forwarding-options-port-mirroring",
	"vlans",
	"routing-instances",
	"routing-instances-detail",
	"route-instance",
	"login",
	"screen",
	"internet-options",
	"root-authentication",
	"bfd-peers",
	"route-map",
	"ipv6-router-advertisement",
	// default arm
	"monitor-security-flow",
	// shell-out / runtime topics (normalized)
	"buffers",
	"buffers-detail",
	"task",
	"core-dumps",
}

// goldenNormalizers collapse non-deterministic tokens so the captured
// baseline is stable and the post-split output can be compared even
// for runtime/shell-out topics.
var goldenNormalizers = []struct {
	re   *regexp.Regexp
	repl string
}{
	// "... ago" durations
	{regexp.MustCompile(`\([0-9hmsµ.]+ ago\)`), "(<AGE> ago)"},
	// RFC-ish timestamps the fixture may surface
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`), "<TS>"},
	// runtime goroutine / alloc / size numbers in buffers/task output
	{regexp.MustCompile(`\b\d+(\.\d+)?\s?(KB|MB|GB|bytes|B)\b`), "<SIZE>"},
	// Go-duration uptime (e.g. "3601h57m13s", "12m4s") — derived from
	// time.Now(), inherently non-deterministic.
	{regexp.MustCompile(`\b(\d+h)?(\d+m)?\d+(\.\d+)?[mµu]?s\b`), "<DUR>"},
	// runtime goroutine / GC counters in task output
	{regexp.MustCompile(`(Goroutines|GC cycles): \d+`), "$1: <NUM>"},
}

func normalizeGolden(s string) string {
	for _, n := range goldenNormalizers {
		s = n.re.ReplaceAllString(s, n.repl)
	}
	return s
}

func newShowGoldenStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range showGoldenConfigCommands {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// showGoldenConfigCommands is a representative configuration exercising
// the topics under test. It deliberately touches firewall filters,
// screen profiles, IKE gateways, dynamic-address feeds, routing
// options/instances, VLANs, and login so the corresponding ShowText
// branches render non-empty output.
var showGoldenConfigCommands = []string{
	"interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
	"interfaces ge-0-0-1 unit 0 family inet address 10.0.1.1/24",
	"security zones security-zone trust interfaces ge-0-0-0.0",
	"security zones security-zone untrust interfaces ge-0-0-1.0",
	"security screen ids-option untrust-screen tcp syn-flood",
	"security screen ids-option untrust-screen tcp land",
	"security screen ids-option untrust-screen icmp ping-death",
	"security policies from-zone trust to-zone untrust policy p1 match source-address any",
	"security policies from-zone trust to-zone untrust policy p1 match destination-address any",
	"security policies from-zone trust to-zone untrust policy p1 match application any",
	"security policies from-zone trust to-zone untrust policy p1 then permit",
	// #2118: enable policy-stats so the policies-hit-count golden topic
	// takes the stats-enabled display branch. (The golden server's
	// dataplane is unloaded, so the counter columns still render 0/0;
	// non-zero counter behavior is covered by the dedicated gate tests.)
	"security policy-stats system-wide enable",
	"security alg sip disable",
	"security dynamic-address feed-server office url http://example.com/feed feed-name blocklist",
	"security address-book global address host1 10.0.1.1/32",
	"security ipsec vpn v1 vpn-monitor optimized",
	"security ipsec vpn v1 bind-interface st0",
	"security ike gateway gw1 address 198.51.100.1",
	"security ike gateway gw1 external-interface ge-0-0-1.0",
	"security ike gateway gw1 ike-policy pol1",
	"firewall family inet filter bandwidth-output term 0 from destination-port 80",
	"firewall family inet filter bandwidth-output term 0 then accept",
	"system backup-router 192.0.2.1 destination 10.0.0.0/8",
	"system login user admin class super-user",
	"system internet-options tcp-mss 1400",
	"routing-options static route 0.0.0.0/0 next-hop 192.0.2.254",
	"routing-options autonomous-system 65000",
	"routing-instances vr1 instance-type virtual-router",
	"routing-instances vr1 interface ge-0-0-0.0",
	// #8990: `vlans v100 vlan-id 100` stood here and was NEVER modelled --
	// there is no top-level `vlans` keyword in pkg/config, so the line was
	// silently discarded and the golden recorded "No VLANs configured" for a
	// topic the product supports. The #8965 unmodeled-stanza gate turned that
	// silent discard into a commit rejection, which is how it surfaced.
	// Replaced with the grammar `show vlans` actually reads (unit.VlanID and
	// ifc.VlanTagging), so this topic now exercises the renderer instead of
	// its empty branch -- including the trunk mode, which derives from
	// vlan-tagging.
	"interfaces ge-0-0-1 vlan-tagging",
	"interfaces ge-0-0-1 unit 100 vlan-id 100",
	"interfaces ge-0-0-1 unit 100 family inet address 10.0.100.1/24",
	"policy-options policy-statement export-statics term t1 then accept",
	"event-options policy ep1 events SNMP_TRAP_LINK_DOWN",
	"event-options policy ep1 then execute-commands commands \"show interfaces\"",
}

func newShowGoldenServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		store: newShowGoldenStore(t),
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{SYNCookieChallenges: 2, SYNCookieAckValid: 5},
				},
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{Family: "inet", FilterName: "bandwidth-output", TermName: "0", Packets: 7, Bytes: 1024},
				},
			},
		},
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"office": {Prefixes: 42, LastFetch: goldenFixedFetch},
			}
		},
		startTime: goldenFixedFetch,
		version:   "test-golden",
	}
}

func TestShowTextGolden(t *testing.T) {
	s := newShowGoldenServer(t)
	got := make(map[string]string, len(goldenShowTopics))
	for _, topic := range goldenShowTopics {
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
		if err != nil {
			t.Fatalf("ShowText(%q) error = %v", topic, err)
		}
		got[topic] = normalizeGolden(resp.GetOutput())
	}

	goldenPath := filepath.Join("testdata", "server_show_golden.json")
	if os.Getenv("UPDATE_SHOW_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		blob, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(blob, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden baseline %s (%d topics)", goldenPath, len(got))
		return
	}

	blob, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with UPDATE_SHOW_GOLDEN=1)", goldenPath, err)
	}
	var want map[string]string
	if err := json.Unmarshal(blob, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	topics := make([]string, 0, len(got))
	for k := range got {
		topics = append(topics, k)
	}
	sort.Strings(topics)
	for _, topic := range topics {
		if want[topic] != got[topic] {
			t.Errorf("ShowText(%q) output drift\n--- want ---\n%s\n--- got ---\n%s", topic, want[topic], got[topic])
		}
	}
	if len(want) != len(got) {
		t.Errorf("golden topic count = %d, captured = %d (regenerate with UPDATE_SHOW_GOLDEN=1 if the topic set changed deliberately)", len(want), len(got))
	}
}
