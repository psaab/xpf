package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// coverageProbability is the occupancy model #8377 states, recomputed HERE so
// the assertions below are against the PROPERTY ("this many probes cover this
// many queues") rather than against a table of expected counts. A table can be
// satisfied by editing the expectation; this cannot.
//
//	E[uncovered] = n * ((n-1)/n)^k      P(all covered) ~= e^-E
func coverageProbability(queues, probes int) float64 {
	if queues <= 1 {
		return 1
	}
	n := float64(queues)
	e := n * math.Pow((n-1)/n, float64(probes))
	return math.Exp(-e)
}

// TestNAPIProbeCountCoversEveryQueue8377 is the cell the issue is about.
//
// THE POSITIVE CONTROL IS THE HALF THAT MATTERS. A coverage assertion that the
// old fixed 30 also satisfies would be measuring nothing, so the model is first
// required to REJECT 30 at the queue count #8377 names. If that sub-assertion
// ever stops failing, the model has stopped discriminating and every pass below
// is vacuous.
//
// MUTATION: return napiProbeFloor unconditionally (i.e. revert to the fixed 30)
// and the 8-, 12- and 16-queue rows red.
func TestNAPIProbeCountCoversEveryQueue8377(t *testing.T) {
	const target = 0.99

	// POSITIVE CONTROL: the historical constant must FAIL the property at 16
	// queues, or this test cannot tell the fix from the defect.
	if got := coverageProbability(16, napiProbeFloor); got >= target {
		t.Fatalf("the coverage model says the OLD fixed %d probes already cover 16 queues "+
			"with P=%.3f >= %.2f. The model no longer discriminates, so every assertion "+
			"below passes for the wrong reason", napiProbeFloor, got, target)
	}

	for _, queues := range []int{2, 4, 6, 8, 12, 16} {
		probes := napiProbeCount(queues)
		if got := coverageProbability(queues, probes); got < target {
			t.Errorf("napiProbeCount(%d) = %d gives P(all queues covered) = %.3f, want >= %.2f. "+
				"Queue selection is by RSS hash, so covering n queues is a coupon-collector "+
				"problem needing ~n*(ln n + ln(1/eps)) draws, not 2n (#8377)",
				queues, probes, got, target)
		}
	}
}

// TestNAPIProbeCountNeverSendsFewerThanBefore8377 is the no-regression half.
//
// The derived count is a FLOOR-ed rule, so no interface that was well covered
// by the historical constant sends fewer probes than it did. An unknown queue
// count (0 — /sys/class/net/<if>/queues unreadable) must also land exactly on
// the old constant, which is byte-identical to pre-#8377 behaviour there.
//
// MUTATION: drop the `if k < napiProbeFloor` clamp and the small-queue rows red.
func TestNAPIProbeCountNeverSendsFewerThanBefore8377(t *testing.T) {
	for queues := 0; queues <= 64; queues++ {
		if got := napiProbeCount(queues); got < napiProbeFloor {
			t.Errorf("napiProbeCount(%d) = %d, below the historical floor %d — an "+
				"interface that was covered before this change now sends fewer probes",
				queues, got, napiProbeFloor)
		}
	}
	for _, unknown := range []int{0, 1} {
		if got := napiProbeCount(unknown); got != napiProbeFloor {
			t.Errorf("napiProbeCount(%d) = %d, want exactly the historical %d: an unknown "+
				"or single-queue interface must behave exactly as it did before #8377",
				unknown, got, napiProbeFloor)
		}
	}
}

// TestNAPIProbeCountIsBoundedByTheBindableQueueCount8377 pins the clamp.
//
// Without it a 64-queue NIC would send ~500 UDP packets at every bringup, and
// the bound would be a magic maximum with no derivation. The clamp is
// BindingQueuesPerIface because that is the most queues an interface can have
// bound (#8374), and the RSS indirection table is reshaped to feed only bound
// queues (#7497) — so covering queues that can hold no binding buys nothing.
//
// The port span is asserted in the same cell because it is the same number: the
// UDP destination port is the only term of the mlx5 RSS hash that varies across
// probes, so count and span move together and an unbounded count would walk off
// the end of the port space.
//
// MUTATION: remove the clamp and both the plateau and the port-span assertions red.
func TestNAPIProbeCountIsBoundedByTheBindableQueueCount8377(t *testing.T) {
	max := napiProbeCount(int(dataplane.BindingQueuesPerIface))
	for _, queues := range []int{16, 17, 32, 64, 128, 4096} {
		if got := napiProbeCount(queues); got != max {
			t.Errorf("napiProbeCount(%d) = %d, want %d — the count must plateau at the "+
				"bindable queue ceiling (BindingQueuesPerIface=%d), not grow with the "+
				"hardware queue count", queues, got, max, dataplane.BindingQueuesPerIface)
		}
	}
	if napiProbeBasePort+max > 65535 {
		t.Errorf("probe ports run %d..%d, past the 16-bit port space — the port is the only "+
			"varying term of the RSS hash, so the span cannot be truncated",
			napiProbeBasePort, napiProbeBasePort+max-1)
	}
}

// TestNAPIBootstrapDerivesTheProbeCountFromTheInterface8377 binds the WIRING.
//
// Every assertion above is about napiProbeCount in isolation. None of them
// notices if bootstrapNAPIQueuesLocked keeps its hard-coded literal and simply
// never calls it — which is the shape that leaves a fix present and inert, and
// which this campaign has hit repeatedly. The call site cannot be driven
// directly (it needs netlink route/neighbour state), so the binding is made at
// the source level: the probe loop's bound must BE the derived count.
//
// MUTATION: put `for i := 0; i < 30; i++` back and this reds; replace the
// argument with a literal queue count and the second assertion reds.
func TestNAPIBootstrapDerivesTheProbeCountFromTheInterface8377(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "process_napi.go", nil, 0)
	if err != nil {
		t.Fatalf("parse process_napi.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if ok && d.Name.Name == "bootstrapNAPIQueuesLocked" {
			fn = d
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatal("bootstrapNAPIQueuesLocked not found in process_napi.go — the analyzer " +
			"can no longer see the call site it exists to bind, so it would pass vacuously")
	}

	var sawDerivedCount, sawQueueCountArg bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "napiProbeCount" {
			return true
		}
		sawDerivedCount = true
		// The argument must itself be the per-interface queue count. A literal,
		// or a constant, would make the count derived-in-name-only.
		for _, arg := range call.Args {
			inner, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			if fid, ok := inner.Fun.(*ast.Ident); ok && (fid.Name == "userspaceRXQueueCount" || fid.Name == "userspaceRXQueueCountFn") {
				sawQueueCountArg = true
			}
		}
		return true
	})

	if !sawDerivedCount {
		t.Error("bootstrapNAPIQueuesLocked does not call napiProbeCount — the probe count " +
			"is still pinned at the call site, so the derived rule is present and inert (#8377)")
	}
	if !sawQueueCountArg {
		t.Error("napiProbeCount is called without userspaceRXQueueCount(...) as its argument " +
			"— the count is not derived from THIS interface's queue count, which is the " +
			"whole of the fix")
	}
}
