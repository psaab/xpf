package userspace

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"

	"golang.org/x/sys/unix"
)

// learned_route_cap_blackhole_9054_test.go guards the COMPOSITION of two
// separately-correct changes.
//
// #8355 capped the learned-route import and documented the degradation as
// "traffic still forwards through the kernel, just not on the fast path".
// #7480, landed separately, made a NoRoute frame get adjudicated against the
// #3110 unzoned egress sentinel — which no zone-pair or junos-global permit can
// match — so the verdict is the DEFAULT action and a Junos-default deny box
// DROPS it. Composed, the cap black-holes the entire dynamic FIB while the
// operator log says the opposite.
//
// The reason it survived two closed issues is worth naming, because it decides
// what these cells assert. #8355's own regression cells check the cap MESSAGE
// and the imported route COUNT, and both are still perfectly correct — a
// capped import does import zero routes. Neither can see what the helper then
// does with a frame for one of those destinations. So the cells below assert
// the DISPOSITION-BEARING fact instead: that the snapshot carries the cap state
// onto the wire, and that the helper reads it. The Rust half is in
// userspace-dp/src/afxdp/forwarding/tests_noroute_capped_import_9054.rs.

// capStateForTable drives the real builder against a synthetic kernel table of
// n routes and returns (routes imported, cap declared).
func capStateForTable(t *testing.T, n int) ([]RouteSnapshot, bool) {
	t.Helper()
	prev := learnedRouteImportFn
	t.Cleanup(func() { learnedRouteImportFn = prev })
	learnedRouteImportFn = func([]int) ([]routing.LearnedRoute, error) {
		snaps := bgpishRouteTable(n)
		out := make([]routing.LearnedRoute, 0, len(snaps))
		for _, s := range snaps {
			out = append(out, routing.LearnedRoute{
				TableID:     learnedRouteMainTableID,
				Family:      unix.AF_INET,
				Destination: s.Destination,
				NextHops:    s.NextHops,
				Protocol:    "bgp",
			})
		}
		return out, nil
	}
	routes, capped, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	return routes, capped
}

// TestTheCapStateReachesTheWire9054 is the cell #8355 could not have had.
func TestTheCapStateReachesTheWire9054(t *testing.T) {
	t.Run("over the cap the build DECLARES it", func(t *testing.T) {
		routes, capped := capStateForTable(t, maxLearnedRoutes()+1)
		if len(routes) != 0 {
			t.Fatalf("precondition: an over-cap table imported %d routes, want 0", len(routes))
		}
		if !capped {
			t.Fatal("the build declined the entire learned-route import and did not say so. " +
				"The helper then cannot distinguish 'this destination has no route' from " +
				"'the daemon withheld the route table', and on a default-deny box it drops " +
				"every learned destination (#7480) — a silent total blackhole of the dynamic FIB")
		}
	})

	t.Run("under the cap it does NOT", func(t *testing.T) {
		// THE CONTROL. Without it, "capped is true" is satisfied by hardcoding
		// true, which would leave the helper delegating NoRoute unconditionally
		// — i.e. reverting #7480's security fix under cover of an availability
		// fix.
		routes, capped := capStateForTable(t, 64)
		if len(routes) != 64 {
			t.Fatalf("precondition: an under-cap table imported %d routes, want 64", len(routes))
		}
		if capped {
			t.Fatal("a 64-route table declared the import capped. #7480's adjudication would " +
				"then be suspended on a box with a complete FIB, which is exactly the " +
				"attacker-steerable kernel delegation it exists to close")
		}
	})

	t.Run("an EMPTY table is not a capped table", func(t *testing.T) {
		// Both add zero routes, and only one of them means the FIB is
		// deliberately incomplete. Conflating them is how a "nothing was
		// imported" heuristic would get this wrong in the dangerous direction.
		routes, capped := capStateForTable(t, 0)
		if len(routes) != 0 {
			t.Fatalf("precondition: an empty table imported %d routes", len(routes))
		}
		if capped {
			t.Fatal("an EMPTY kernel table was reported as a capped import. A box with no " +
				"learned routes has a COMPLETE FIB, and suspending the NoRoute adjudication " +
				"there delegates attacker-chosen destinations to the kernel for no reason")
		}
	})

	t.Run("the flag is a function of THIS build, not sticky", func(t *testing.T) {
		// The route-only republish path (manager_overlay.go) does
		// `next := *m.lastSnapshot`, so it inherits every field it does not
		// reassign — and the #7437 rtnetlink listener drives that path on every
		// kernel route change, which is precisely when the table can cross the
		// cap in either direction.
		if _, capped := capStateForTable(t, maxLearnedRoutes()+1); !capped {
			t.Fatal("precondition: over-cap build did not report capped")
		}
		if _, capped := capStateForTable(t, 64); capped {
			t.Fatal("a build whose table fits still reported the import capped — the flag is " +
				"latching. A latched true keeps NoRoute delegated after the table shrank back")
		}
	})
}

// TestTheSnapshotCarriesTheCapFlag9054 walks the whole builder, not just the
// route sub-builder, because the field has to survive the struct literal.
func TestTheSnapshotCarriesTheCapFlag9054(t *testing.T) {
	prev := learnedRouteImportFn
	t.Cleanup(func() { learnedRouteImportFn = prev })
	install := func(n int) {
		learnedRouteImportFn = func([]int) ([]routing.LearnedRoute, error) {
			out := make([]routing.LearnedRoute, 0, n)
			for _, s := range bgpishRouteTable(n) {
				out = append(out, routing.LearnedRoute{
					TableID:     learnedRouteMainTableID,
					Family:      unix.AF_INET,
					Destination: s.Destination,
					NextHops:    s.NextHops,
					Protocol:    "bgp",
				})
			}
			return out, nil
		}
	}
	cfg := &config.Config{}

	install(maxLearnedRoutes() + 1)
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 1)
	if !snap.LearnedRouteImportCapped {
		t.Fatal("ConfigSnapshot.LearnedRouteImportCapped is false after an over-cap build; " +
			"the route sub-builder reported the cap but the snapshot dropped it")
	}

	// It must also survive the JSON encode — the helper reads the wire, not the
	// struct, and `omitempty` on a false bool means the key is absent, which is
	// the correct encoding of "not capped".
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"learned_route_import_capped":true`)) {
		t.Fatalf("the encoded snapshot does not carry learned_route_import_capped=true")
	}

	install(64)
	under := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 2, 1)
	if under.LearnedRouteImportCapped {
		t.Fatal("ConfigSnapshot.LearnedRouteImportCapped is true for an under-cap build")
	}
	body, err = json.Marshal(under)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("learned_route_import_capped")) {
		t.Fatal("an uncapped snapshot emits the key; omitempty should leave it absent")
	}
}

// TestTheCapDiagnosticIsTrue9054 asserts the OPERATOR-FACING sentence.
//
// This is not cosmetic and it is not a string test for its own sake: the log
// line is the first thing an operator reads when the cap fires, and until #9054
// it stated the exact opposite of what the box was doing. A diagnostic that
// points away from the cause is worse than no diagnostic.
func TestTheCapDiagnosticIsTrue9054(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if !learnedRouteCapExceeded(maxLearnedRoutes() + 1) {
		t.Fatal("precondition: learnedRouteCapExceeded did not fire")
	}
	got := buf.String()
	if got == "" {
		t.Fatal("the cap fired and logged nothing — this cell would then assert over an empty " +
			"string and pass for the wrong reason")
	}
	// The false claim, verbatim as it shipped.
	if strings.Contains(got, "so traffic still forwards through the kernel but not on the AF_XDP fast path") {
		t.Error("the cap log still tells the operator that traffic forwards through the kernel " +
			"unconditionally. Since #7480 a NoRoute frame is adjudicated against the unzoned " +
			"egress sentinel and DROPPED on a default-deny box")
	}
	for _, want := range []string{"learned_route_import_capped", "REFUSED"} {
		if !strings.Contains(got, want) {
			t.Errorf("the cap log does not mention %q; the operator cannot tell which mechanism "+
				"is keeping traffic flowing, nor what an out-of-date helper does instead", want)
		}
	}
}

// TestTheFalseKernelForwardingClaimIsGoneTreeWide9054 is the retraction census.
//
// The claim did not live in one place. It was in the cap's decision rationale,
// in its operator log line, in docs/multi-wan.md and in pkg/routing/README.md —
// and #8355's acceptance text asserted it too. A fix that corrects the code and
// leaves the documents is a retraction that reaches people but not the
// artifacts the claim reached, so the next reader is handed a confidently wrong
// prior with every local check agreeing.
func TestTheFalseKernelForwardingClaimIsGoneTreeWide9054(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	// The claim, in the two spellings it shipped in.
	claims := []*regexp.Regexp{
		regexp.MustCompile(`neither is an outage — the kernel still forwards`),
		regexp.MustCompile(`so traffic still forwards through the kernel but not on the AF_XDP fast path`),
	}
	subjects := []string{
		"pkg/dataplane/userspace/learned_route_cap_8355.go",
		"docs/multi-wan.md",
		"pkg/routing/README.md",
	}
	found := 0
	for _, rel := range subjects {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v — this census cannot report a clean board on a file it "+
				"could not open", rel, err)
		}
		for _, re := range claims {
			if re.Match(body) {
				found++
				t.Errorf("%s still asserts that a capped learned-route import leaves the kernel "+
					"forwarding. #7480 inverted that premise: on a Junos-default deny box the "+
					"frame is dropped. Pattern: %s", rel, re)
			}
		}
	}
	// POSITIVE CONTROL. A census whose patterns match nothing anywhere is
	// indistinguishable from a clean board, and both of these patterns were
	// present at master. Prove the reader and the patterns still work by
	// matching the SAME text where it is deliberately quoted as history.
	control := regexp.MustCompile(`still forwards through the kernel`)
	self, err := os.ReadFile("learned_route_cap_blackhole_9054_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !control.Match(self) {
		t.Fatal("the census control pattern matches nothing even in this file, so a zero above " +
			"says nothing about the tree")
	}
	if found != 0 {
		t.Logf("%d occurrences of the retracted claim remain", found)
	}
}

// TestCapFlagIsWiredEndToEnd9054 binds the WIRING across the language boundary.
//
// Every behavioural cell in this file stops at the Go struct, and every
// behavioural cell in tests_noroute_capped_import_9054.rs starts at the Rust
// ForwardingState. Neither can see the three links between them: the JSON key
// must match, the Rust snapshot field must be copied into ForwardingState, and
// the NoRoute arm must call the gated entry point. A silent mismatch in any of
// them leaves both suites green and the blackhole intact.
func TestCapFlagIsWiredEndToEnd9054(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	// 1. The wire key. `#[serde(default)]` makes a key mismatch SILENT: the
	// helper would decode false forever and keep black-holing.
	snapshotRS := read("userspace-dp/src/protocol/snapshot.rs")
	if !strings.Contains(snapshotRS, `#[serde(rename = "learned_route_import_capped", default)]`) {
		t.Error("userspace-dp/src/protocol/snapshot.rs does not declare the " +
			"learned_route_import_capped wire key; with serde(default) the mismatch is silent")
	}
	if !strings.Contains(snapshotRS, "pub learned_route_import_capped: bool,") {
		t.Error("the Rust snapshot struct has no learned_route_import_capped field")
	}

	// 2. The copy into the runtime state the packet path reads.
	if !strings.Contains(read("userspace-dp/src/afxdp/forwarding_build/mod.rs"),
		"state.learned_route_import_capped = snapshot.learned_route_import_capped;") {
		t.Error("forwarding_build does not copy learned_route_import_capped into ForwardingState; " +
			"the field would be decoded and then never read")
	}

	// 3. The arm calls the GATED adjudication.
	poll := read("userspace-dp/src/afxdp/poll_descriptor/mod.rs")
	if !strings.Contains(poll, "forwarding::noroute_policy_denial_gated(") {
		t.Error("the NoRoute arm does not call noroute_policy_denial_gated; the cap flag is " +
			"carried across the socket and then ignored at the one decision it exists for")
	}

	// 4. The Go producer sets it on BOTH publish paths. manager_overlay does
	// `next := *m.lastSnapshot`, so a path that forgets to reassign inherits a
	// stale value — and the #7437 route listener drives that path on every
	// kernel route change.
	if !strings.Contains(read("pkg/dataplane/userspace/manager_overlay.go"),
		"next.Routes, next.LearnedRouteImportCapped, err = buildRouteSnapshots(") {
		t.Error("the route-only republish path does not recompute LearnedRouteImportCapped; " +
			"it inherits the previous snapshot's value")
	}
	if !strings.Contains(read("pkg/dataplane/userspace/builder.go"),
		"LearnedRouteImportCapped: learnedRoutesCapped,") {
		t.Error("the full snapshot builder does not set LearnedRouteImportCapped")
	}

	// POSITIVE CONTROL: prove the reader reaches real source.
	if !strings.Contains(poll, "ForwardingDisposition::NoRoute =>") {
		t.Fatal("the census read poll_descriptor/mod.rs but did not find the NoRoute arm — it " +
			"is not reading the file it thinks it is")
	}
}

// TestProtocolVersionMovedWithTheWire9054 states the compatibility decision
// explicitly rather than leaving it to the shape-digest cell's error text.
func TestProtocolVersionMovedWithTheWire9054(t *testing.T) {
	if ProtocolVersion < 10 {
		t.Fatalf("ProtocolVersion = %d. learned_route_import_capped is additive, but the rule "+
			"recorded in protocol.go's v9 note has TWO questions: does an old reader still "+
			"enforce what it enforced before, AND is what it enforced before acceptable. Here "+
			"the answer to the second is no — an old helper ignores the field and keeps "+
			"black-holing the dynamic FIB, which IS the defect the field was added to fix — so "+
			"the bump is the only mechanism that refuses the pairing", ProtocolVersion)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "control.rs"))
	if err != nil {
		t.Fatalf("read control.rs: %v", err)
	}
	want := "pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = " +
		strings.TrimSpace(strings.Split(strings.Split(string(raw), "CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = ")[1], ";")[0]) + ";"
	if !strings.Contains(string(raw), want) {
		t.Fatalf("could not read the Rust protocol constant")
	}
	if !strings.Contains(string(raw), "= 10;") {
		t.Fatalf("the Rust CONFIG_SNAPSHOT_PROTOCOL_VERSION did not move with the Go one; a "+
			"one-sided bump makes EVERY pairing a mismatch, including matched deployments. Go "+
			"is at %d", ProtocolVersion)
	}
}
