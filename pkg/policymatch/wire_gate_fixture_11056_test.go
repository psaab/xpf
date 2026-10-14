package policymatch

import (
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #11056 — the hermetic FIXTURE leg of the three wire gates that have zero
// rows in the tracked ledger (wire_policy_deny, wire_hostinbound_deny,
// wire_appmatch_twins).
//
// Each of those gates commits a CLI fixture onto the loss cluster and then
// reads its verdict off the wire. The live leg is operator-held (see the
// issue's 2026-09-27/2026-10-09 triage), but the fixture itself is CODE, and
// a fixture that fails to narrow the policy the way the gate's verdict
// assumes could only be discovered by a live run that then VOIDs or
// false-FAILs on a cluster this campaign cannot drive. These tests close
// that gap hermetically:
//
//   - the fixture text is EXTRACTED from the shipped gate script, so the
//     script stays the single source of truth and an edit that changes the
//     fixture (or a pinned default it substitutes) fails here loudly;
//   - it is applied to docs/ha-cluster-userspace.conf — the committed
//     baseline the loss cluster runs — through the same set/delete replay
//     primitives the CLI store uses (config.ParseSetVerbGroupedClosed +
//     ConfigTree.SetPathQuotedGrouped/DeletePathGrouped, mirroring
//     configstore.applyEditLine);
//   - the compiled config is evaluated by the policy simulator
//     (policymatch.Match) at the exact probe/control tuples the gate bursts
//     on the wire.
//
// What this proves: the BASELINE admits every gate tuple (the same-path
// baseline the live gates require before fixing), and the FIXTURE narrows
// exactly the legs the verdicts name — probe falls to default-deny, control
// stays permitted. What it does NOT prove: that the running daemon enforces
// it on the wire. That remains the live leg.

const (
	wire11056ClusterConf = "../../docs/ha-cluster-userspace.conf"
	wire11056PolicyDeny  = "../../test/incus/wire-policy-deny.sh"
	wire11056Twins       = "../../test/incus/wire-appmatch-twins.sh"
	wire11056HostInbound = "../../test/incus/wire-hostinbound-deny.sh"
)

// wire11056Var pairs a substituted shell variable with the script literal
// that pins its default. If a gate changes either half, the pin check fails
// here instead of the test silently evaluating a different fixture than the
// one the gate commits.
type wire11056Var struct {
	name string
	val  string
	pin  string
}

// wire11056PinnedVars asserts every pin against the script text and returns
// the substitution map.
func wire11056PinnedVars(t *testing.T, script string, vars []wire11056Var) map[string]string {
	t.Helper()
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read %s: %v", script, err)
	}
	text := string(body)
	out := make(map[string]string, len(vars))
	for _, v := range vars {
		if !strings.Contains(text, v.pin) {
			t.Fatalf("%s no longer carries the pinned default %q for $%s — the fixture this test evaluates has drifted from the script",
				script, v.pin, v.name)
		}
		out[v.name] = v.val
	}
	return out
}

// wire11056FixtureCommands extracts the `set`/`delete` lines of a gate
// script's FIXTURE_CMDS block (the commit-check heredoc the live gate pipes
// to the DUT CLI) and substitutes the pinned shell variables, so the test
// applies exactly the commands the gate commits.
func wire11056FixtureCommands(t *testing.T, script string, vars map[string]string) []string {
	t.Helper()
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read %s: %v", script, err)
	}
	re := regexp.MustCompile(`(?s)FIXTURE_CMDS="configure\n(.*?)\ncommit check"`)
	m := re.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("%s: no FIXTURE_CMDS=\"configure … commit check\" block found — the fixture extraction no longer matches the script", script)
	}
	var cmds []string
	for _, line := range strings.Split(m[1], "\n") {
		if !strings.HasPrefix(line, "set ") && !strings.HasPrefix(line, "delete ") {
			t.Fatalf("%s: unexpected non-edit line in FIXTURE_CMDS: %q", script, line)
		}
		for name, val := range vars {
			line = strings.ReplaceAll(line, "$"+name, val)
		}
		if strings.Contains(line, "$") {
			t.Fatalf("%s: fixture line still carries an unsubstituted variable: %q", script, line)
		}
		cmds = append(cmds, line)
	}
	if len(cmds) == 0 {
		t.Fatalf("%s: FIXTURE_CMDS block carried no set/delete commands", script)
	}
	return cmds
}

// applyWire11056Lines replays flat set/delete lines onto a tree through the
// same primitives the CLI store's applyEditLine uses (configstore is not
// importable from here without widening its API, so the verb switch is
// mirrored; only set/delete are accepted and anything else fails the test).
func applyWire11056Lines(t *testing.T, tree *config.ConfigTree, lines []string) {
	t.Helper()
	for _, line := range lines {
		verb, path, quoted, grouped, closed, err := config.ParseSetVerbGroupedClosed(line)
		if err != nil {
			t.Fatalf("ParseSetVerbGroupedClosed(%q): %v", line, err)
		}
		switch verb {
		case "delete":
			err = tree.DeletePathGrouped(path, grouped)
		case "set":
			err = tree.SetPathQuotedGrouped(path, quoted, grouped, closed)
		default:
			t.Fatalf("wire fixture uses verb %q, which this replay does not cover", verb)
		}
		if err != nil {
			t.Fatalf("apply %q: %v", line, err)
		}
	}
}

// wire11056Baseline parses the committed loss-cluster baseline and expands
// the `${node}` apply-group the same way the #6722 shipped-config test does
// (node0 is the topology every smoke targets).
func wire11056Baseline(t *testing.T) *config.ConfigTree {
	t.Helper()
	src, err := os.ReadFile(wire11056ClusterConf)
	if err != nil {
		t.Fatalf("read the shipped cluster config: %v", err)
	}
	tree, errs := config.NewParser(string(src)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse docs/ha-cluster-userspace.conf: %v", errs)
	}
	if err := tree.ExpandGroupsWithVars(map[string]string{"node": "node0"}); err != nil {
		t.Fatalf("ExpandGroupsWithVars: %v", err)
	}
	return tree
}

func compileWire11056(t *testing.T, tree *config.ConfigTree) *config.Config {
	t.Helper()
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig on baseline+wire fixture: %v — the live gate's `commit check` would refuse this fixture", err)
	}
	return cfg
}

// wire11056Tuple is one probe/control burst the gates put on the wire: from
// the cluster LAN host to the VLAN-80 sink, matching the live topology the
// gate scripts print at startup.
func wire11056Tuple(proto string, dstPort int) Query {
	return Query{
		FromZone: "lan", ToZone: "wan",
		SrcIP:    net.ParseIP("10.0.61.102"), // CLUSTER_LAN_HOST, the burst sender
		DstIP:    net.ParseIP("172.16.80.201"), // the VLAN-80 capture point
		Protocol: proto, DstPort: dstPort,
	}
}

// TestWirePolicyDenyFixtureFallsToDefaultDeny_11056 proves the #9531
// default-deny gate's fixture narrows lan→wan allow-all to the control
// application ONLY: the probe tuple keeps NO permit rule (it falls to the
// configured default-policy deny-all), while the near-miss control — the
// same tuple differing only in destination port — stays matched by
// allow-all. That asymmetry is the entire live claim; without it the gate
// would measure either a permit-everything baseline (nothing denied) or a
// deny-everything fixture (no liveness control).
func TestWirePolicyDenyFixtureFallsToDefaultDeny_11056(t *testing.T) {
	vars := wire11056PinnedVars(t, wire11056PolicyDeny, []wire11056Var{
		{"APP_NAME", "wire-9531-ctl", `APP_NAME="wire-9531-ctl"`},
		{"SET_NAME", "wire-9531-set", `SET_NAME="wire-9531-set"`},
		{"CONTROL_PORT", "54902", `CONTROL_PORT="${CONTROL_PORT:-54902}"`},
		{"FROM_ZONE", "lan", `FROM_ZONE="${FROM_ZONE:-lan}"`},
		{"TO_ZONE", "wan", `TO_ZONE="${TO_ZONE:-wan}"`},
	})
	fixture := wire11056FixtureCommands(t, wire11056PolicyDeny, vars)

	probe := wire11056Tuple("udp", 54901)
	control := wire11056Tuple("udp", 54902)

	// Same-path baseline: BOTH tuples forward pre-fixture, exactly what the
	// live gate's Phase-1 baseline burst asserts on the cluster.
	base := compileWire11056(t, wire11056Baseline(t))
	for _, q := range []Query{probe, control} {
		res := Match(base, q)
		if !res.Matched || res.PolicyName != "allow-all" || res.Action != config.PolicyPermit {
			t.Fatalf("baseline must permit udp/%d via allow-all (same-path baseline); got matched=%t default=%t policy=%q action=%v",
				q.DstPort, res.Matched, res.DefaultUsed, res.PolicyName, res.Action)
		}
	}

	tree := wire11056Baseline(t)
	applyWire11056Lines(t, tree, fixture)
	cfg := compileWire11056(t, tree)

	res := Match(cfg, probe)
	if res.Matched || !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("probe tuple udp/54901 must fall to the default policy (no permit rule); got matched=%t default=%t action=%v — the gate's zero-leak claim would be unfounded",
			res.Matched, res.DefaultUsed, res.Action)
	}
	res = Match(cfg, control)
	if !res.Matched || res.PolicyName != "allow-all" || res.Action != config.PolicyPermit {
		t.Fatalf("control tuple udp/54902 must stay permitted by the narrowed allow-all (capture-liveness leg); got matched=%t policy=%q action=%v",
			res.Matched, res.PolicyName, res.Action)
	}
}

// TestWireAppmatchTwinsFixturePermitsOnlyTwinApps_11056 proves the #9531
// twins fixture narrows allow-all to exactly the two permitted applications:
// both permit twins (tcp/80, udp/53) stay matched, both deny twins (tcp/8080,
// udp/5353 — the protocol-only widening class) fall to default-deny.
func TestWireAppmatchTwinsFixturePermitsOnlyTwinApps_11056(t *testing.T) {
	vars := wire11056PinnedVars(t, wire11056Twins, []wire11056Var{
		{"APP_TCP", "wire-9531-http", `APP_TCP="wire-9531-http"`},
		{"APP_UDP", "wire-9531-dns", `APP_UDP="wire-9531-dns"`},
		{"SET_NAME", "wire-9531-twins", `SET_NAME="wire-9531-twins"`},
		{"T80", "80", "T80=80"},
		{"U53", "53", "U53=53"},
		{"FROM_ZONE", "lan", `FROM_ZONE="${FROM_ZONE:-lan}"`},
		{"TO_ZONE", "wan", `TO_ZONE="${TO_ZONE:-wan}"`},
	})
	fixture := wire11056FixtureCommands(t, wire11056Twins, vars)

	permit := []Query{wire11056Tuple("tcp", 80), wire11056Tuple("udp", 53)}
	deny := []Query{wire11056Tuple("tcp", 8080), wire11056Tuple("udp", 5353)}

	base := compileWire11056(t, wire11056Baseline(t))
	for _, q := range append(append([]Query{}, permit...), deny...) {
		res := Match(base, q)
		if !res.Matched || res.PolicyName != "allow-all" {
			t.Fatalf("baseline must forward all four twins (same-path baseline); port %d got matched=%t policy=%q",
				q.DstPort, res.Matched, res.PolicyName)
		}
	}

	tree := wire11056Baseline(t)
	applyWire11056Lines(t, tree, fixture)
	cfg := compileWire11056(t, tree)

	for _, q := range permit {
		res := Match(cfg, q)
		if !res.Matched || res.PolicyName != "allow-all" || res.Action != config.PolicyPermit {
			t.Fatalf("permit twin port %d must stay matched by the narrowed allow-all; got matched=%t policy=%q action=%v",
				q.DstPort, res.Matched, res.PolicyName, res.Action)
		}
	}
	for _, q := range deny {
		res := Match(cfg, q)
		if res.Matched || !res.DefaultUsed || res.Action != config.PolicyDeny {
			t.Fatalf("deny twin port %d must fall to the default policy; got matched=%t default=%t action=%v",
				q.DstPort, res.Matched, res.DefaultUsed, res.Action)
		}
	}
}

// TestWireHostinboundDenyFixtureAdmitsOnlyNetconf_11056 proves the #10029
// fixture admits ONE management service on the WAN zone: with
// `system-services netconf` added, tcp/830 is token-admitted while SSH
// (22) and HTTPS (443) stay host-inbound DENIED — and the pre-fixture
// baseline denies all three, which is the exposure state the gate measures.
func TestWireHostinboundDenyFixtureAdmitsOnlyNetconf_11056(t *testing.T) {
	body, err := os.ReadFile(wire11056HostInbound)
	if err != nil {
		t.Fatalf("read %s: %v", wire11056HostInbound, err)
	}
	// The fixture is the set line inside the commit printf (this gate has no
	// FIXTURE_CMDS block).
	setLine := "set security zones security-zone wan host-inbound-traffic system-services netconf"
	if !strings.Contains(string(body), setLine) {
		t.Fatalf("%s no longer commits %q — the fixture leg has drifted", wire11056HostInbound, setLine)
	}
	for _, pin := range []string{
		`PROBE_PORT_A="${PROBE_PORT_A:-22}"`,
		`PROBE_PORT_B="${PROBE_PORT_B:-443}"`,
		`CONTROL_PORT="${CONTROL_PORT:-830}"`,
	} {
		if !strings.Contains(string(body), pin) {
			t.Fatalf("%s no longer pins %s — probe/control ports drifted from the tuple this test asserts", wire11056HostInbound, pin)
		}
	}

	hostQuery := func(port int) Query {
		return Query{
			FromZone: "wan", ToZone: JunosHostZone,
			SrcIP:    net.ParseIP("172.16.80.174"), // outside prober (xpf-mouse-target)
			DstIP:    net.ParseIP("172.16.80.8"),   // DUT WAN address the gate probes
			Protocol: "tcp", DstPort: port,
		}
	}

	// Baseline: the committed WAN stanza admits ping/gre only, so ALL three
	// management ports are host-inbound denied.
	base := compileWire11056(t, wire11056Baseline(t))
	for _, port := range []int{22, 443, 830} {
		res := Match(base, hostQuery(port))
		if res.HostInbound == nil || res.HostInbound.Status != dpuserspace.HostInboundDenied {
			t.Fatalf("baseline wan host-inbound must DENY tcp/%d (the exposure the gate measures); got %+v", port, res.HostInbound)
		}
	}

	tree := wire11056Baseline(t)
	applyWire11056Lines(t, tree, []string{setLine})
	cfg := compileWire11056(t, tree)

	res := Match(cfg, hostQuery(830))
	if res.HostInbound == nil || res.HostInbound.Status != dpuserspace.HostInboundTokenAdmit ||
		res.HostInbound.Token != "netconf" || res.HostInbound.Kind != "system-services" {
		t.Fatalf("netconf control tcp/830 must be admitted by the fixture's system-services netconf token; got %+v", res.HostInbound)
	}
	for _, port := range []int{22, 443} {
		res := Match(cfg, hostQuery(port))
		if res.HostInbound == nil || res.HostInbound.Status != dpuserspace.HostInboundDenied {
			t.Fatalf("probe port tcp/%d must stay host-inbound DENIED under the fixture; got %+v", port, res.HostInbound)
		}
	}
}
