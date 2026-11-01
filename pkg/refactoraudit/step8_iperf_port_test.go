package refactoraudit

import (
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
)

// TestStep8ThroughputPortIsUnshaped asserts that the port
// docs/engineering-style.md's step-8 throughput row names resolves, in
// test/incus/cos-iperf-config.set, to a forwarding class with no explicit
// transmit-rate cap.
func TestStep8ThroughputPortIsUnshaped(t *testing.T) {
	root := repoRootForMarkerSweep(t)
	doc := readRepoFile(t, root, "docs/engineering-style.md")
	cos := readRepoFile(t, root, "test/incus/cos-iperf-config.set")

	row := step8ThroughputRow(t, doc)
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
	doc := "| x | y | `iperf3 -P 16 -t 30 -p 5211` → 172.16.80.202 | ≥ 23 Gbit/s |\n"
	if m := step8PortRe.FindStringSubmatch(doc); m == nil || m[1] != "5211" {
		t.Errorf("port extractor returned %v, want 5211", m)
	}
}

// step8ThroughputRow returns the step-8 table row that carries the iperf3
// throughput check. It is located by CONTENT (an iperf3 invocation against the
// documented target) rather than by line number, so an edit above it does not
// silently make the gate inspect the wrong row. The target is loss's
// IPERF_TARGET4: 172.16.80.202 since #18576 (b1b9c0ed1b), which moved off .200
// because an external box also answers ARP for it.
func step8ThroughputRow(t *testing.T, doc string) string {
	t.Helper()
	var hits []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") &&
			strings.Contains(line, "iperf3") && strings.Contains(line, "172.16.80.202") {
			hits = append(hits, line)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly ONE step-8 table row with an iperf3 check against "+
			"172.16.80.202, found %d; the gate must not guess which one it means",
			len(hits))
	}
	return hits[0]
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
