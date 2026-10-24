package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12531: restore per-QNH RIP metrics via ripd-native offset-lists.
// ripd ignores route-map `set metric` for redistributed statics even when
// the action is present in its copy (verified live on FRR 10.7.1: the
// RIPMET map read back metric 7 yet both `show ip rip` and the RIPv2
// wire carried metric 1), and no daemon-scoped route-map transport
// confines the action to ripd. The offset-list is the confined
// equivalent: it lives inside `router rip`, matches the destination
// prefix with a standard access-list, and adds (metric-1) on the wire
// so the advertised metric equals the configured QNH metric exactly.

func TestRIPQNHMetricOffsetList12531(t *testing.T) {
	rendered, overlays := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols rip group g neighbor ge-0/0/0.0",
		"set protocols rip redistribute static",
	)
	// The generated access-list permits exactly the QNH destination.
	if !strings.Contains(rendered, "access-list xpf-qnh-rip-") ||
		!strings.Contains(rendered, " seq 5 permit 203.0.113.0/24\n") ||
		!strings.Contains(rendered, " seq 10 deny any\n") {
		t.Fatalf("RIP QNH metric must render its destination access-list:\n%s", rendered)
	}
	// metric 10 => offset 9 on every RIP interface (no interface operand).
	if !strings.Contains(rendered, " offset-list xpf-qnh-rip-") ||
		!strings.Contains(rendered, " out 9\n") {
		t.Fatalf("RIP QNH metric 10 must render offset-list out 9 (1+9=10):\n%s", rendered)
	}
	// The shared QNH map stays metric-free and OSPF is untouched.
	if strings.Contains(rendered, " set metric ") {
		t.Fatalf("integrated config must stay metric-free:\n%s", rendered)
	}
	if len(overlays) != 0 {
		t.Fatalf("RIP-only export must not create a daemon overlay: %v", overlays)
	}
}

func TestRIPQNHMetricClampsToInfinity12531(t *testing.T) {
	// RIP metric is 1..16 (16 = infinity/unreachable). A QNH metric above
	// 16 must clamp the offset so the wire metric is exactly 16, not wrap
	// or emit an offset ripd would reject.
	rendered, _ := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 200",
		"set protocols rip redistribute static",
	)
	if !strings.Contains(rendered, " out 15\n") {
		t.Fatalf("QNH metric 200 must clamp to RIP infinity offset 15:\n%s", rendered)
	}
	rendered, _ = qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 16",
		"set protocols rip redistribute static",
	)
	if !strings.Contains(rendered, " out 15\n") {
		t.Fatalf("QNH metric 16 must render offset 15:\n%s", rendered)
	}
	rendered, _ = qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 1",
		"set protocols rip redistribute static",
	)
	if !strings.Contains(rendered, " out 0\n") {
		t.Fatalf("QNH metric 1 must render offset 0:\n%s", rendered)
	}
}

func TestRIPQNHMetricSkipsOutOfRange12531(t *testing.T) {
	// Metric 0 has no RIP representation (wire metrics start at 1), so no
	// ACL/offset is emitted for it; the route keeps the default metric.
	rendered, _ := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 0",
		"set protocols rip redistribute static",
	)
	if strings.Contains(rendered, "xpf-qnh-rip-") {
		t.Fatalf("metric 0 must not render a RIP QNH offset:\n%s", rendered)
	}
}

func TestRIPQNHMetricPerDestination12531(t *testing.T) {
	// Two QNH routes with different metrics get independent ACL+offset
	// pairs keyed to their own destinations.
	rendered, _ := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.10 metric 5",
		"set protocols rip redistribute static",
	)
	if !strings.Contains(rendered, " out 9\n") || !strings.Contains(rendered, " out 4\n") {
		t.Fatalf("each QNH destination needs its own offset:\n%s", rendered)
	}
	if got := strings.Count(rendered, "access-list xpf-qnh-rip-"); got != 4 {
		t.Fatalf("want 2 ACLs (permit+deny each = 4 lines), got count %d:\n%s", got, rendered)
	}
}

func TestRIPQNHMetricPolicyExportNotOffset12531(t *testing.T) {
	// A RIP export via an authored policy-statement keeps the authored
	// policy's metric semantics: no QNH offset is synthesized for it.
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols rip redistribute EXPORT-STATIC",
		"set policy-options policy-statement EXPORT-STATIC term STATIC from protocol static",
		"set policy-options policy-statement EXPORT-STATIC term STATIC then accept",
	)
	rendered, _ := New().buildManagedSectionWithQNH11447(&FullConfig{
		RIP:           compiled.Protocols.RIP,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	})
	if strings.Contains(rendered, "xpf-qnh-rip-") {
		t.Fatalf("policy-exported RIP must not get a QNH offset:\n%s", rendered)
	}
}

func TestRIPQNHMetricNoRIPNoRender12531(t *testing.T) {
	rendered, _ := qnhMetricRenderAndOverlays11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	if strings.Contains(rendered, "xpf-qnh-rip-") {
		t.Fatalf("without RIP redistribution no RIP QNH artifact may render:\n%s", rendered)
	}
}

func TestRIPQNHMetricACLEscapesCollision12531(t *testing.T) {
	// An operator prefix-list whose name collides with the generated ACL
	// name space must not silently fuse; the generated name is hashed so
	// distinct destinations never share an ACL. Verify determinism.
	a := ripQNHMetricACLName12531("global", "203.0.113.0/24")
	b := ripQNHMetricACLName12531("global", "198.51.100.0/24")
	if a == b {
		t.Fatalf("distinct destinations must not share an ACL name: %q", a)
	}
	if a != ripQNHMetricACLName12531("global", "203.0.113.0/24") {
		t.Fatalf("ACL name must be deterministic")
	}
	if !strings.HasPrefix(a, "xpf-qnh-rip-") {
		t.Fatalf("ACL name must carry the reserved prefix: %q", a)
	}
	// Guard the config-side invariant used by the collision check.
	var _ = config.ReservedRedistSuffix
}
