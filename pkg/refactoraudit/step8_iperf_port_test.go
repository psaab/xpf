package refactoraudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// step8_iperf_port_test.go — #7610.
//
// `docs/engineering-style.md` step 8 tells every lane to apply
// `test/incus/cos-iperf-config.set` and then measure throughput on a specific
// port against a ≥ 23 Gbit/s bar. In that fixture THE PORT IS THE CLASS: the
// `bandwidth-output` filter maps each of 5200-5211 to a different
// forwarding-class, and several of those classes are shaped.
//
// The doc named 5203, which maps to `iperf-3g` → `scheduler-3g`,
// `transmit-rate 3.0g exact`. So the instruction was "shape this traffic to
// 3 Gb/s, then fail the change if it does not reach 23" — a lane following it
// literally reads a correctly working shaper as an 8x regression. The
// "no regression vs previous run" clause made it worse, not better: every
// previous run of the same wrong port also reported ~3 Gbit/s, so the reading
// looked corroborated.
//
// This gate binds the AGREEMENT between the two files rather than pinning
// either to a literal. Pinning the doc to "5211" would encode which side I
// trust; if someone renumbers the fixture, a literal-pinned test keeps passing
// while the doc goes wrong again. The invariant is "the port step 8 names must
// resolve, IN THE FIXTURE, to an unshaped class" — which stays true under a
// renumber.

var (
	step8PortRe = regexp.MustCompile(`iperf3 [^|]*-p (\d{4})`)
	// `... term N from destination-port PPPP`
	cosTermPortRe = regexp.MustCompile(`(?m)^set firewall family inet filter bandwidth-output term (\d+) from destination-port (\d{4})\s*$`)
	// `... term N then forwarding-class CLASS`
	cosTermClassRe = regexp.MustCompile(`(?m)^set firewall family inet filter bandwidth-output term (\d+) then forwarding-class (\S+)\s*$`)
	// `set class-of-service schedulers SCHED transmit-rate RATE`
	schedRateRe = regexp.MustCompile(`(?m)^set class-of-service schedulers (\S+) transmit-rate (\S+)\s*$`)
	// `set class-of-service scheduler-maps MAP forwarding-class FC scheduler SCHED`
	schedMapRe = regexp.MustCompile(`(?m)^set class-of-service scheduler-maps \S+ forwarding-class (\S+) scheduler (\S+)\s*$`)
	// `IPERF_TARGET4="A.B.C.D"` in the loss cluster env (#18741).
	envIperfTarget4Re = regexp.MustCompile(`(?m)^IPERF_TARGET4="?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"?\s*$`)
)

// step8EnvFile is where loss's v4 iperf target is defined; step 8's row must
// agree with it.
const step8EnvFile = "test/incus/loss-userspace-cluster.env"

// TestStep8ThroughputPortIsUnshaped asserts that the port
// docs/engineering-style.md's step-8 throughput row names resolves, in
// test/incus/cos-iperf-config.set, to a forwarding class with no explicit
// transmit-rate cap.
func TestStep8ThroughputPortIsUnshaped(t *testing.T) {
	root := repoRootForMarkerSweep(t)
	doc := readRepoFile(t, root, "docs/engineering-style.md")
	cos := readRepoFile(t, root, "test/incus/cos-iperf-config.set")
	env := readRepoFile(t, root, step8EnvFile)

	target, err := lossIperfTarget4(env)
	if err != nil {
		t.Fatalf("%s: %v", step8EnvFile, err)
	}
	row, err := step8ThroughputRow(doc, target)
	if err != nil {
		t.Fatal(err)
	}
	m := step8PortRe.FindStringSubmatch(row)
	if m == nil {
		t.Fatalf("could not find an `iperf3 … -p <port>` in step 8's throughput "+
			"row; the gate cannot check what it cannot parse:\n  %s", row)
	}
	port := m[1]

	class, sched, rate := cosClassForPort(t, cos, port)
	t.Logf("step 8 measures port %s → forwarding-class %q (scheduler %q, transmit-rate %q)",
		port, class, sched, rate)

	if rate != "" {
		t.Fatalf("step 8's throughput row measures port %s, which the CoS fixture "+
			"maps to forwarding-class %q → scheduler %q with `transmit-rate %s` — "+
			"a SHAPED class. The row's pass criterion is an unshaped-line-rate "+
			"number, so a healthy box reads as a large regression and the shaper "+
			"working correctly is what fails the gate (#7610). Point the row at an "+
			"unshaped class, or change its criterion to the shaped rate.",
			port, class, sched, rate)
	}
}

// TestStep8IperfPortGateDetectsAShapedPort is the sensitivity control.
//
// Without it, the gate passing means either "the doc names an unshaped port" or
// "the parse returned nothing and the comparison never ran" — the same green.
// It drives the real parsers over a synthetic doc row naming a port the
// synthetic fixture shapes, and requires the shaped rate to come back.
func TestStep8IperfPortGateDetectsAShapedPort(t *testing.T) {
	cos := strings.Join([]string{
		"set class-of-service schedulers sched-slow transmit-rate 3.0g",
		"set class-of-service schedulers sched-slow transmit-rate exact",
		"set class-of-service scheduler-maps m forwarding-class fc-slow scheduler sched-slow",
		"set class-of-service scheduler-maps m forwarding-class fc-open scheduler sched-open",
		"set firewall family inet filter bandwidth-output term 3 from destination-port 5203",
		"set firewall family inet filter bandwidth-output term 3 then forwarding-class fc-slow",
		"set firewall family inet filter bandwidth-output term 11 from destination-port 5211",
		"set firewall family inet filter bandwidth-output term 11 then forwarding-class fc-open",
	}, "\n") + "\n"

	if _, _, rate := cosClassForPort(t, cos, "5203"); rate != "3.0g" {
		t.Errorf("a SHAPED port resolved to transmit-rate %q, want \"3.0g\" — the "+
			"gate would pass over the exact defect it exists to catch", rate)
	}
	if _, _, rate := cosClassForPort(t, cos, "5211"); rate != "" {
		t.Errorf("an UNSHAPED port resolved to transmit-rate %q, want empty — the "+
			"gate would fire on a correct doc", rate)
	}

	// And the row extractor must pick the throughput row's port, not some other
	// `-p` elsewhere in a long document.
	doc := "| x | y | `iperf3 -P 16 -t 30 -p 5211` → `$IPERF_TARGET4` (loss 172.16.80.202) | ≥ 23 Gbit/s |\n"
	if m := step8PortRe.FindStringSubmatch(doc); m == nil || m[1] != "5211" {
		t.Errorf("port extractor returned %v, want 5211", m)
	}
}

// lossIperfTarget4 returns the single IPERF_TARGET4 address the loss env
// assigns. It errors when the env does not assign exactly one.
func lossIperfTarget4(env string) (string, error) {
	m := envIperfTarget4Re.FindAllStringSubmatch(env, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("want exactly one IPERF_TARGET4=\"<ipv4>\" assignment, found %d", len(m))
	}
	return m[0][1], nil
}

// step8ThroughputRow returns the step-8 table row that carries the iperf3
// throughput check. It is located by CONTENT rather than by line number, so an
// edit above it does not silently make the gate inspect the wrong row.
//
// The content is the documented target: the `$IPERF_TARGET4` token plus the
// address the loss env actually assigns (#18741). It is no longer a literal.
// The literal .200 broke when #18576 renumbered to .202, and a literal .202
// would break on the next renumber. It also could not see an env-only move:
// the doc would still say .202 while the harness iperfs elsewhere. Requiring
// both the token and the env's address keeps the row unique, follows a
// renumber of both files, and turns a doc/env mismatch red.
func step8ThroughputRow(doc, target string) (string, error) {
	var hits []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") &&
			strings.Contains(line, "iperf3") && strings.Contains(line, "$IPERF_TARGET4") &&
			strings.Contains(line, target) {
			hits = append(hits, line)
		}
	}
	if len(hits) != 1 {
		return "", fmt.Errorf("expected exactly ONE step-8 table row with an iperf3 check against "+
			"$IPERF_TARGET4 and the loss env's address %s (%s), found %d; the gate must not guess "+
			"which one it means, and a row naming another address disagrees with the env",
			target, step8EnvFile, len(hits))
	}
	return hits[0], nil
}

// The locator itself (AG): exactly one matching row is found; zero and two
// are refused; a row whose address disagrees with the env is not a match.
func TestStep8ThroughputRowLocator18741(t *testing.T) {
	const target = "172.16.80.202"
	row := "| Any change | deploy | `iperf3 -P 16 -t 30 -p 5211` → `$IPERF_TARGET4` (loss 172.16.80.202) | band |"
	for name, tc := range map[string]struct {
		doc  string
		want bool
	}{
		"one row":                    {"intro\n" + row + "\noutro\n", true},
		"zero rows":                  {"intro\n| x | `iperf3 -p 5211` → somewhere | y |\n", false},
		"two rows":                   {row + "\n" + row + "\n", false},
		"row disagrees with the env": {strings.ReplaceAll(row, "172.16.80.202", "172.16.80.200"), false},
		"literal address, no token":  {"| x | `iperf3 -p 5211` → 172.16.80.202 | y |\n", false},
		"not a table row":            {"`iperf3 -p 5211` → `$IPERF_TARGET4` (loss 172.16.80.202)\n", false},
	} {
		got, err := step8ThroughputRow(tc.doc, target)
		if tc.want && (err != nil || got != row) {
			t.Errorf("%s: step8ThroughputRow = %q, %v; want the row", name, got, err)
		}
		if !tc.want && err == nil {
			t.Errorf("%s: step8ThroughputRow accepted %q", name, got)
		}
	}
	if got, err := lossIperfTarget4("A=1\nIPERF_TARGET4=\"172.16.80.202\"\n"); err != nil || got != target {
		t.Errorf("lossIperfTarget4 = %q, %v; want %s", got, err, target)
	}
	for name, env := range map[string]string{
		"absent":  "A=1\n",
		"twice":   "IPERF_TARGET4=\"1.2.3.4\"\nIPERF_TARGET4=\"5.6.7.8\"\n",
		"comment": "# IPERF_TARGET4=\"1.2.3.4\"\n",
	} {
		if _, err := lossIperfTarget4(env); err == nil {
			t.Errorf("lossIperfTarget4 accepted an env with the target %s", name)
		}
	}
}

// cosClassForPort resolves a destination port through the CoS fixture to its
// forwarding class, that class's scheduler, and that scheduler's explicit
// transmit-rate ("" when the class is unshaped).
func cosClassForPort(t *testing.T, cos, port string) (class, sched, rate string) {
	t.Helper()
	term := ""
	for _, m := range cosTermPortRe.FindAllStringSubmatch(cos, -1) {
		if m[2] == port {
			term = m[1]
			break
		}
	}
	if term == "" {
		t.Fatalf("port %s is not mapped by any bandwidth-output term in the CoS "+
			"fixture; the doc names a port the fixture does not classify", port)
	}
	for _, m := range cosTermClassRe.FindAllStringSubmatch(cos, -1) {
		if m[1] == term {
			class = m[2]
			break
		}
	}
	if class == "" {
		t.Fatalf("bandwidth-output term %s matches port %s but assigns no "+
			"forwarding-class", term, port)
	}
	for _, m := range schedMapRe.FindAllStringSubmatch(cos, -1) {
		if m[1] == class {
			sched = m[2]
			break
		}
	}
	for _, m := range schedRateRe.FindAllStringSubmatch(cos, -1) {
		// `transmit-rate exact` is a modifier on the rate above it, not a rate.
		if m[1] == sched && m[2] != "exact" {
			rate = m[2]
			break
		}
	}
	return class, sched, rate
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}
