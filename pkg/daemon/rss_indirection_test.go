// D3 RSS indirection tests (#785). Covers:
//   - weight-vector computation across edge cases (workers==1,
//     workers==queues, workers<queues, workers>queues).
//   - mlx5 vs non-mlx5 gating via fake sysfs.
//   - idempotent skip when the live table already matches.
//   - graceful skip when ethtool is missing.
//   - top-level kill-switch via the enabled argument (#797).
//   - twice-call idempotency on matching state (#797 Go LOW #3).
//
// No real NIC is required — ethtool, sysfs driver lookup, queue count,
// and netdev enumeration are all injected via the rssExecutor interface.
package daemon

import (
	"errors"
	"io/fs"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// fakeRSSExecutor records ethtool invocations and replays scripted output.
type fakeRSSExecutor struct {
	// Interfaces visible to the sysfs scan. Order preserved as returned.
	ifaces []string
	// Per-iface driver name. Missing key → non-PCI / unknown; treated
	// as empty string (skip).
	drivers map[string]string
	// Per-iface RX queue count.
	queues map[string]int
	// Per-iface sysfs enumeration error, overriding queues (#5250 A7-b2 F2).
	queueErrs map[string]error
	// Scripted ethtool -x <iface> output for idempotency probe.
	ethtoolX map[string][]byte
	// Scripted ethtool -c <iface> output for coalescence probe (#801).
	// Separate from ethtoolX so a test can script one without the
	// other and a production misuse (reading -x when probing
	// coalescence, for example) fails loudly.
	ethtoolC map[string][]byte
	// Recorded argvs, in call order. `{"-X", "eth0", "weight", "1", "1", "0", "0"}`, etc.
	calls [][]string
	// argvErr returns a scripted (output, error) for an argv-prefix
	// match. Used by tests that need to exercise the generic-error
	// branches in maybeRestoreDefault. Key matches via strings.HasPrefix
	// on a space-joined argv (longest matching prefix wins, for
	// determinism — see runEthtool). Checked BEFORE the per-iface
	// ethtoolX / ethtoolC path so a test can override default behavior
	// for a specific invocation.
	argvErr map[string]argvErrSpec
}

// argvErrSpec scripts a (combinedOutput, error) tuple for an argv match.
type argvErrSpec struct {
	out []byte
	err error
}

func (f *fakeRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	cp := make([]string, len(args))
	copy(cp, args)
	f.calls = append(f.calls, cp)
	// Argv-keyed scripted errors (Codex code-review LOW #2) take
	// precedence so tests can override default behavior for a
	// specific invocation.
	if f.argvErr != nil {
		// Longest-prefix-wins for determinism — Go map iteration
		// is randomized, so without this two overlapping prefix
		// keys (e.g. "-X eth0" and "-X eth0 default") would
		// produce flaky tests.
		joined := strings.Join(args, " ")
		var bestPrefix string
		var bestSpec argvErrSpec
		matched := false
		for prefix, spec := range f.argvErr {
			if strings.HasPrefix(joined, prefix) && len(prefix) >= len(bestPrefix) {
				bestPrefix = prefix
				bestSpec = spec
				matched = true
			}
		}
		if matched {
			return bestSpec.out, bestSpec.err
		}
	}
	if len(args) >= 2 && args[0] == "-x" {
		if out, ok := f.ethtoolX[args[1]]; ok {
			return out, nil
		}
		// Wrap exec.ErrNotFound so errors.Is detects it — mirrors the
		// real *exec.Error shape returned by os/exec.
		return nil, &exec.Error{Name: "ethtool", Err: exec.ErrNotFound}
	}
	if len(args) >= 2 && args[0] == "-c" {
		if out, ok := f.ethtoolC[args[1]]; ok {
			return out, nil
		}
		return nil, &exec.Error{Name: "ethtool", Err: exec.ErrNotFound}
	}
	return nil, nil
}

func (f *fakeRSSExecutor) readDriver(iface string) string {
	return f.drivers[iface]
}

func (f *fakeRSSExecutor) readQueueCount(iface string) (int, error) {
	if f.queueErrs != nil {
		if err, ok := f.queueErrs[iface]; ok {
			return 0, err
		}
	}
	return f.queues[iface], nil
}

func (f *fakeRSSExecutor) listInterfaces() []string {
	return f.ifaces
}

func TestComputeWeightVector_WorkersOne_Skips(t *testing.T) {
	// Single-worker deploys get default RSS: pinning to queue 0 would
	// serialize the worker on one IRQ line. Reviewer #L1.
	v, reason := computeWeightVector(1, 6)
	if v != nil {
		t.Fatalf("workers=1 must skip, got %v", v)
	}
	if reason == "" {
		t.Fatal("expected a non-empty skip reason")
	}
}

func TestComputeWeightVector_FourOfSix(t *testing.T) {
	v, reason := computeWeightVector(4, 6)
	want := []int{1, 1, 1, 1, 0, 0}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("want %v, got %v (reason=%q)", want, v, reason)
	}
}

func TestComputeWeightVector_WorkersEqualsQueues_Skips(t *testing.T) {
	// workers==queues: default table already delivers to every queue.
	// No reshaping is useful; plan §2.3 says skip.
	v, _ := computeWeightVector(4, 4)
	if v != nil {
		t.Fatalf("workers==queues must skip, got %v", v)
	}
}

func TestComputeWeightVector_WorkersExceedsQueues_Skips(t *testing.T) {
	// The edge case from the brief: workers=5, queues=4.
	//
	// Defence: we cannot honor "hash onto queues 0..4" when only 4 queues
	// exist. Writing weight [1 1 1 1] is indistinguishable from the
	// default table (which is what the kernel has already); writing
	// anything else (e.g. [1 1 1 1 1] of length queues=4 would be
	// malformed) is not valid ethtool input.
	//
	// We skip *and log a warning* via the reason string. The caller
	// that logs "rss indirection skipped" surfaces this; operationally
	// this means "your userspace-dp worker count exceeds the HW queue
	// count — workers 5..N will still bind because AF_XDP queue binding
	// is handled separately, but RSS can't steer traffic to them."
	v, reason := computeWeightVector(5, 4)
	if v != nil {
		t.Fatalf("workers>queues must skip, got %v", v)
	}
	if reason == "" {
		t.Fatal("expected skip reason for workers>queues")
	}
}

func TestComputeWeightVector_GeneralizesTo4of8(t *testing.T) {
	// Reviewer flagged hardcoding "1 1 1 1 0 0". Confirm it generalizes.
	v, _ := computeWeightVector(4, 8)
	want := []int{1, 1, 1, 1, 0, 0, 0, 0}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("want %v, got %v", want, v)
	}
}

func TestComputeWeightVector_ZeroInputs(t *testing.T) {
	if v, _ := computeWeightVector(0, 6); v != nil {
		t.Fatalf("workers=0 must skip, got %v", v)
	}
	if v, _ := computeWeightVector(4, 0); v != nil {
		t.Fatalf("queues=0 must skip, got %v", v)
	}
}

// mlx5 detected → ethtool -X weight is issued with the expected argv.
func TestApplyRSSIndirectionOne_MlxWritesWeightVector(t *testing.T) {
	// Default-looking ethtool -x output: all 6 queues active.
	defaultTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
    8:      0     1     2     3     4     5
   16:      0     1     2     3     4     5
RSS hash key:
Operation not supported
`)
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": defaultTable},
	}
	applyRSSIndirectionOne("eth0", 4, f)

	// Expect two ethtool calls: probe then write.
	if len(f.calls) != 2 {
		t.Fatalf("want 2 ethtool calls, got %d: %v", len(f.calls), f.calls)
	}
	wantProbe := []string{"-x", "eth0"}
	if !reflect.DeepEqual(f.calls[0], wantProbe) {
		t.Fatalf("probe mismatch: want %v got %v", wantProbe, f.calls[0])
	}
	wantWrite := []string{"-X", "eth0", "weight", "1", "1", "1", "1", "0", "0"}
	if !reflect.DeepEqual(f.calls[1], wantWrite) {
		t.Fatalf("write mismatch: want %v got %v", wantWrite, f.calls[1])
	}
}

// Already-constrained table → no write.
func TestApplyRSSIndirectionOne_MatchingTable_SkipsWrite(t *testing.T) {
	// Live table only uses queues 0..3 (weight 1 1 1 1 0 0 applied
	// previously). ethtool distributes rows across the active queues.
	matchingTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
   16:      0     1     2     3     0     1
`)
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": matchingTable},
	}
	applyRSSIndirectionOne("eth0", 4, f)

	if len(f.calls) != 1 {
		t.Fatalf("want 1 ethtool call (probe only), got %d: %v", len(f.calls), f.calls)
	}
	if f.calls[0][0] != "-x" {
		t.Fatalf("want probe-only, got %v", f.calls[0])
	}
}

// Go MEDIUM #2 + #3: Non-mlx5 driver must short-circuit at the top-level
// scan, with no ethtool invocation at all. The test now actually calls
// applyRSSIndirection with a fake that owns both the interface list and
// the driver map — the driver guard is exercised for real.
func TestApplyRSSIndirection_NonMlx_Skips(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0", "eth1"},
		drivers: map[string]string{"eth0": "virtio_net", "eth1": "iavf"},
		queues:  map[string]int{"eth0": 4, "eth1": 4},
	}
	applyRSSIndirection(true, 4, f.ifaces, f)
	if len(f.calls) != 0 {
		t.Fatalf("non-mlx5 interfaces must not trigger any ethtool call, got %v", f.calls)
	}
}

// Go HIGH #1 flavour: mixed interface set. Only the mlx5 interface
// receives ethtool writes; virtio/iavf siblings are untouched.
func TestApplyRSSIndirection_MixedDrivers_OnlyMlxTouched(t *testing.T) {
	defaultTable := []byte(`RX flow hash indirection table for mlx0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
    8:      0     1     2     3     4     5
`)
	f := &fakeRSSExecutor{
		ifaces: []string{"lo", "virt0", "mlx0", "iavf0"},
		drivers: map[string]string{
			"virt0": "virtio_net",
			"mlx0":  "mlx5_core",
			"iavf0": "iavf",
		},
		queues:   map[string]int{"mlx0": 6, "virt0": 4, "iavf0": 4},
		ethtoolX: map[string][]byte{"mlx0": defaultTable},
	}
	applyRSSIndirection(true, 4, f.ifaces, f)

	// All ethtool invocations must target mlx0 only.
	for _, c := range f.calls {
		if len(c) < 2 {
			t.Fatalf("malformed call: %v", c)
		}
		if c[1] != "mlx0" {
			t.Fatalf("ethtool invoked on non-mlx5 iface: %v", c)
		}
	}
	// And the write must have happened.
	sawWrite := false
	for _, c := range f.calls {
		if c[0] == "-X" {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatalf("expected a -X write on mlx0, got %v", f.calls)
	}
}

// ethtool binary missing on probe → function skips cleanly, no write.
func TestApplyRSSIndirectionOne_EthtoolMissing_SkipsGracefully(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 6},
		// No entry in ethtoolX → probe returns ErrNotFound.
	}
	applyRSSIndirectionOne("eth0", 4, f)
	// Exactly one call — the probe. No write because probe failed.
	if len(f.calls) != 1 || f.calls[0][0] != "-x" {
		t.Fatalf("want 1 probe-only call, got %v", f.calls)
	}
}

// #5124 fail-on-revert: workers→1 must NOT early-return at the top level.
// A prior workers<queues apply left a concentrated table; the single-worker
// reconcile must walk the allowlist, probe the live table, and restore the
// NIC default so RX is no longer hashed onto the old subset of queues. With
// the pre-#5124 `workers == 1 { return }` early return (or a guard that
// requires workers > 1), no ethtool call fires and this test goes RED.
func TestApplyRSSIndirection_SingleWorker_StaleTable_RestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:   []string{"eth0"},
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirection(true, 1, f.ifaces, f)

	if len(f.calls) != 2 {
		t.Fatalf("workers→1 with stale table: want 2 calls (probe + restore), got %d: %v",
			len(f.calls), f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"-x", "eth0"}) {
		t.Errorf("call 0: want `ethtool -x eth0` probe, got %v", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"-X", "eth0", "default"}) {
		t.Errorf("call 1: want `ethtool -X eth0 default` restore, got %v", f.calls[1])
	}
}

// #5124: workers→1 on a NIC whose live table is ALREADY the round-robin
// default must issue only the probe and NO restore write (idempotent — a
// fresh single-worker boot must not churn the NIC mid-traffic).
func TestApplyRSSIndirection_SingleWorker_DefaultTable_ProbeOnly(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:   []string{"eth0"},
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable6q)},
	}
	applyRSSIndirection(true, 1, f.ifaces, f)

	if len(f.calls) != 1 {
		t.Fatalf("workers=1 with default table: want 1 call (probe only), got %d: %v",
			len(f.calls), f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"-x", "eth0"}) {
		t.Errorf("call 0: want `ethtool -x eth0` probe, got %v", f.calls[0])
	}
	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-X" {
			t.Errorf("default table → must not invoke -X, got %v", c)
		}
	}
}

// #5124: single-queue NIC has no possible concentration to undo — the
// queues>1 guard must short-circuit BEFORE any ethtool probe.
func TestApplyRSSIndirection_SingleWorker_SingleQueue_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0"},
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 1},
	}
	applyRSSIndirection(true, 1, f.ifaces, f)
	if len(f.calls) != 0 {
		t.Fatalf("workers=1 on single-queue NIC must issue no ethtool calls, got %v", f.calls)
	}
}

// Workers == 0 skips at the top level.
func TestApplyRSSIndirection_ZeroWorkers_Skips(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0"},
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 4},
	}
	applyRSSIndirection(true, 0, f.ifaces, f)
	if len(f.calls) != 0 {
		t.Fatalf("workers=0 must issue no ethtool calls, got %v", f.calls)
	}
}

// MEDIUM (Codex) rollback: when enabled=false the apply path short-
// circuits, and on mlx5 interfaces the kernel's default RSS table is
// restored via `ethtool -X <iface> default`. Non-mlx5 interfaces are
// untouched.
func TestApplyRSSIndirection_DisabledRestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces: []string{"lo", "virt0", "mlx0", "mlx1"},
		drivers: map[string]string{
			"virt0": "virtio_net",
			"mlx0":  "mlx5_core",
			"mlx1":  "mlx5_core",
		},
		queues: map[string]int{"mlx0": 6, "mlx1": 6, "virt0": 4},
	}
	applyRSSIndirection(false, 4, f.ifaces, f)

	// Exactly one restore call per mlx5 interface; virt0/lo untouched.
	if len(f.calls) != 2 {
		t.Fatalf("want 2 restore calls (mlx0, mlx1), got %d: %v", len(f.calls), f.calls)
	}
	seen := map[string]bool{}
	for _, c := range f.calls {
		if len(c) != 3 || c[0] != "-X" || c[2] != "default" {
			t.Fatalf("expected `ethtool -X <iface> default`, got %v", c)
		}
		if d := f.drivers[c[1]]; d != "mlx5_core" {
			t.Fatalf("restore invoked on non-mlx5 iface %q (driver=%q)", c[1], d)
		}
		seen[c[1]] = true
	}
	if !seen["mlx0"] || !seen["mlx1"] {
		t.Fatalf("both mlx5 interfaces must be restored, saw %v", seen)
	}
}

// Go LOW #3: the idempotency claim must be demonstrated on repeated
// invocation. After the first call writes the weight vector, the second
// call sees a matching table and must not write again.
func TestApplyRSSIndirection_TwiceIsIdempotent(t *testing.T) {
	// We can't replay the kernel's actual post-write table from a pure
	// fake, but the semantics we need to pin are: "if the probe already
	// returns a matching layout, the second call issues exactly one more
	// ethtool call (the probe) and no write." Simulate that by pre-
	// populating ethtoolX with a matching table.
	matchingTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
`)
	f := &fakeRSSExecutor{
		ifaces:   []string{"eth0"},
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": matchingTable},
	}

	applyRSSIndirection(true, 4, f.ifaces, f)
	if len(f.calls) != 1 || f.calls[0][0] != "-x" {
		t.Fatalf("first call: want probe-only, got %v", f.calls)
	}
	applyRSSIndirection(true, 4, f.ifaces, f)
	if len(f.calls) != 2 {
		t.Fatalf("second call must be exactly +1 probe, got total %d: %v",
			len(f.calls), f.calls)
	}
	if f.calls[1][0] != "-x" {
		t.Fatalf("second call must be probe-only, got %v", f.calls[1])
	}
}

func TestIndirectionTableMatches_TrueWhenConstrained(t *testing.T) {
	// Table only uses queues 0..3; weights allow 4 active queues.
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
RSS hash key:
...
`)
	if !indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("expected match")
	}
}

func TestIndirectionTableMatches_FalseWhenQueueOutOfRange(t *testing.T) {
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
`)
	if indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("queue 4 and 5 appear: must not match")
	}
}

// TestIndirectionTableMatches_FalseWhenActiveQueueMissing_5328 is the
// #5328 (A7-b2-F10) RED-on-revert guard. 4 workers are configured (weights
// [1,1,1,1,0,0] → active=4, so queues 0..3 must all be used), but the live
// table only spreads onto queues 0..2 — queue 3 never appears. That is a
// stale/driver-reset table that starves worker 3, so it must be reported as a
// MISMATCH to force the ethtool -X weight reprogram, NOT accepted as converged.
//
// FAIL-ON-REVERT: drop the per-active-queue coverage check (return true once
// every entry is < active) and every entry here is 0..2 < 4, so the subset
// table falsely matches and this assertion goes RED.
func TestIndirectionTableMatches_FalseWhenActiveQueueMissing_5328(t *testing.T) {
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     0     1     2
    8:      0     1     2     0     1     2
RSS hash key:
...
`)
	if indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("table omits active queue 3: must not match (subset-coverage regression)")
	}
}

// TestIndirectionTableMatches_FalseWhenPinnedToQueueZero_5328 covers the
// extreme #5328 case the audit called out directly: a table using ONLY queue 0
// while 4 workers are configured. Under the pre-fix `q >= active` check every
// entry (0) passed, so the concentrated table was accepted and workers 1..3
// stayed idle.
func TestIndirectionTableMatches_FalseWhenPinnedToQueueZero_5328(t *testing.T) {
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     0     0     0     0     0
    8:      0     0     0     0     0     0
`)
	if indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("table pinned to queue 0: must not match with 4 active queues")
	}
}

// Codex H1: the allowlist must scope apply — mlx5 siblings not in the
// userspace-dp binding list must never see an ethtool call. An mlx5 PF
// unused by xpf must stay at its driver-default RSS regardless of its
// sysfs presence.
func TestApplyRSSIndirection_AllowlistScopesApply(t *testing.T) {
	defaultTable := []byte(`RX flow hash indirection table for mlx_bound with 6 RX ring(s):
    0:      0     1     2     3     4     5
`)
	f := &fakeRSSExecutor{
		ifaces: []string{"lo", "mlx_bound", "mlx_sibling"},
		drivers: map[string]string{
			"mlx_bound":   "mlx5_core",
			"mlx_sibling": "mlx5_core",
		},
		queues:   map[string]int{"mlx_bound": 6, "mlx_sibling": 6},
		ethtoolX: map[string][]byte{"mlx_bound": defaultTable},
	}
	// Allowlist contains only mlx_bound — mlx_sibling must be untouched
	// even though it is also mlx5_core.
	applyRSSIndirection(true, 4, []string{"mlx_bound"}, f)

	for _, c := range f.calls {
		if len(c) < 2 {
			t.Fatalf("malformed call: %v", c)
		}
		if c[1] != "mlx_bound" {
			t.Fatalf("allowlist violated: ethtool invoked on %v", c)
		}
	}
	if len(f.calls) == 0 {
		t.Fatal("expected ethtool calls on the allowlisted iface")
	}
}

// Codex H1: empty allowlist → zero ethtool calls. A userspace-dp config
// with no bound mlx5 interfaces (e.g. management-only deploy) must not
// touch any netdev, regardless of the sysfs scan.
func TestApplyRSSIndirection_EmptyAllowlist_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"mlx0"},
		drivers: map[string]string{"mlx0": "mlx5_core"},
		queues:  map[string]int{"mlx0": 6},
	}
	applyRSSIndirection(true, 4, nil, f)
	if len(f.calls) != 0 {
		t.Fatalf("empty allowlist must not issue ethtool calls, got %v", f.calls)
	}
}

// Codex H1 (restore path): the kill switch must also respect the
// allowlist so we never "restore default" on a sibling mlx5 PF the
// operator reserved for a non-xpf workload.
func TestApplyRSSIndirection_RestoreRespectsAllowlist(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces: []string{"mlx_bound", "mlx_sibling"},
		drivers: map[string]string{
			"mlx_bound":   "mlx5_core",
			"mlx_sibling": "mlx5_core",
		},
		queues: map[string]int{"mlx_bound": 6, "mlx_sibling": 6},
	}
	applyRSSIndirection(false, 4, []string{"mlx_bound"}, f)
	if len(f.calls) != 1 {
		t.Fatalf("want exactly one restore call, got %v", f.calls)
	}
	if f.calls[0][1] != "mlx_bound" {
		t.Fatalf("restore escaped allowlist: %v", f.calls[0])
	}
}

// Codex LOW (new): end-to-end coverage from reapplyRSSIndirectionWith
// (the commit-time reapply entry point) through to an ethtool `-X
// ... weight ...` call. Proves the wiring on the exact code path
// applyConfig() uses — not just the helper.
func TestReapplyRSSIndirection_EndToEndWritesWeights(t *testing.T) {
	defaultTable := []byte(`RX flow hash indirection table for ge-0-0-1 with 6 RX ring(s):
    0:      0     1     2     3     4     5
`)
	f := &fakeRSSExecutor{
		ifaces:   []string{"lo", "ge-0-0-1"},
		drivers:  map[string]string{"ge-0-0-1": "mlx5_core"},
		queues:   map[string]int{"ge-0-0-1": 6},
		ethtoolX: map[string][]byte{"ge-0-0-1": defaultTable},
	}
	reapplyRSSIndirectionWith(true, 4, []string{"ge-0-0-1"}, f)

	sawWrite := false
	for _, c := range f.calls {
		if len(c) >= 4 && c[0] == "-X" && c[1] == "ge-0-0-1" && c[2] == "weight" {
			// Expect `1 1 1 1 0 0` for workers=4, queues=6.
			want := []string{"-X", "ge-0-0-1", "weight", "1", "1", "1", "1", "0", "0"}
			if !reflect.DeepEqual(c, want) {
				t.Fatalf("weight argv mismatch: want %v, got %v", want, c)
			}
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatalf("reapplyRSSIndirectionWith did not reach ethtool -X weight: %v", f.calls)
	}
}

// ─── #805: workers≥queues stale-table refresh ────────────────────────

// staleTable6q4w: indirection layout left behind by an
// applyRSSIndirectionOne run with workers=4, queues=6 — the
// ethtool-style "uses only queues 0..3" output that
// indirectionTableMatches([1,1,1,1,0,0]) returns true on but
// indirectionTableIsDefault(_, 6) must return false on.
const staleTable6q4w = `RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
   16:      0     1     2     3     0     1
`

// defaultTable6q: kernel default round-robin layout for queueCount=6,
// captured live from loss:xpf-userspace-fw0/ge-0-0-2 via
// `ethtool -X iface default; ethtool -x iface`.
const defaultTable6q = `RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5     0     1
    8:      2     3     4     5     0     1     2     3
   16:      4     5     0     1     2     3     4     5
   24:      0     1     2     3     4     5     0     1
`

// defaultTable4q: round-robin layout for queueCount=4 (synthesized from
// the formula entry[i] == i mod queueCount, the same shape mlx5
// produces).
const defaultTable4q = `RX flow hash indirection table for eth0 with 4 RX ring(s):
    0:      0     1     2     3     0     1     2     3
    8:      0     1     2     3     0     1     2     3
`

// #805 test 1: workers==queues, live table is from the prior
// workers<queues apply (stale concentrated). maybeRestoreDefault must
// fire `ethtool -X iface default`.
func TestApplyRSSIndirectionOne_WorkersEqualsQueues_StaleTable_RestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 2 {
		t.Fatalf("expected 2 ethtool calls (probe + restore), got %d: %v",
			len(f.calls), f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"-x", "eth0"}) {
		t.Errorf("call 0: want probe, got %v", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"-X", "eth0", "default"}) {
		t.Errorf("call 1: want -X default, got %v", f.calls[1])
	}
}

// #805 test 2: workers > queues (e.g. operator over-allocated workers).
// Same restore-default behavior as workers==queues case.
func TestApplyRSSIndirectionOne_WorkersGreaterThanQueues_StaleTable_RestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 8, f)

	sawRestore := false
	for _, c := range f.calls {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "default" {
			sawRestore = true
		}
	}
	if !sawRestore {
		t.Fatalf("expected ethtool -X default invocation, got %v", f.calls)
	}
}

// #805 test 3: workers >= queues but live table IS default. No write.
func TestApplyRSSIndirectionOne_WorkersGreaterEqualQueues_DefaultTable_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable6q)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-X" {
			t.Errorf("default table → must not invoke -X, got %v", c)
		}
	}
}

// #5124 (was #805 test 4): workers == 1 with a stale concentrated table —
// must probe and restore the NIC default. Single-worker policy is default
// RSS across every queue; a concentrated table left by a prior
// workers<queues apply keeps RX hashed onto the old subset, so the reconcile
// must undo it. With the fix neutralized (guard requiring workers > 1) this
// goes RED — no ethtool call fires.
func TestApplyRSSIndirectionOne_WorkersIsOne_StaleTable_RestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 1, f)

	if len(f.calls) != 2 {
		t.Fatalf("workers=1 stale table: want 2 calls (probe + restore), got %d: %v",
			len(f.calls), f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"-x", "eth0"}) {
		t.Errorf("call 0: want probe, got %v", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"-X", "eth0", "default"}) {
		t.Errorf("call 1: want -X default, got %v", f.calls[1])
	}
}

// #5124: workers == 1 with a live table that is ALREADY default — probe
// only, no restore write (mirrors the workers>=queues default no-op path).
func TestApplyRSSIndirectionOne_WorkersIsOne_DefaultTable_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable6q)},
	}
	applyRSSIndirectionOne("eth0", 1, f)

	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-X" {
			t.Errorf("workers=1 default table → must not invoke -X, got %v", c)
		}
	}
}

// #5124: workers == 1 on a single-queue NIC — the queues>1 guard
// short-circuits before any probe (no concentration is possible).
func TestApplyRSSIndirectionOne_WorkersIsOne_SingleQueue_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 1},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 1, f)

	if len(f.calls) != 0 {
		t.Errorf("workers=1 single-queue NIC → zero ethtool calls, got %v", f.calls)
	}
}

// #805 test 5: workers == 0 with stale table — must NOT touch.
func TestApplyRSSIndirectionOne_WorkersIsZero_StaleTable_NotTouched(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 0, f)

	if len(f.calls) != 0 {
		t.Errorf("workers=0 must issue zero ethtool calls, got %v", f.calls)
	}
}

// #805 test 6: queueCount==0 (sysfs read failed). The
// workers>=queues>0 guard must short-circuit.
func TestApplyRSSIndirectionOne_QueueCountZero_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 0},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 0 {
		t.Errorf("queueCount=0 must issue zero ethtool calls, got %v", f.calls)
	}
}

// #805 test 7: ethtool -x probe returns ErrNotFound on the
// restore-default path. Must log warning, NOT attempt -X default.
func TestApplyRSSIndirectionOne_RestoreEthtoolXProbeMissing_LogAndSkip(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"eth0": mlx5Driver},
		queues:  map[string]int{"eth0": 6},
		// No ethtoolX entry → fakeRSSExecutor returns ErrNotFound on -x.
	}
	applyRSSIndirectionOne("eth0", 6, f)

	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-X" {
			t.Errorf("probe failure → must not invoke -X, got %v", c)
		}
	}
}

// #805 test 8: parser — true round-robin for the given queueCount.
func TestIndirectionTableIsDefault_RoundRobin_True(t *testing.T) {
	if !indirectionTableIsDefault([]byte(defaultTable6q), 6) {
		t.Error("captured ge-0-0-2 default table must parse as default")
	}
	if !indirectionTableIsDefault([]byte(defaultTable4q), 4) {
		t.Error("synthetic 4-queue default must parse as default")
	}
}

// #805 test 9: parser — concentrated [1,1,1,1,0,0]-style table is NOT
// default.
func TestIndirectionTableIsDefault_Concentrated_False(t *testing.T) {
	if indirectionTableIsDefault([]byte(staleTable6q4w), 6) {
		t.Error("stale concentrated table must NOT parse as default")
	}
}

// #805 test 10: parser — table that uses every queue at least once but
// in non-round-robin order is NOT default. Tightens R2 #3.
func TestIndirectionTableIsDefault_EveryQueueOnceButNonRoundRobin_False(t *testing.T) {
	custom := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      5     4     3     2     1     0     5     4
    8:      3     2     1     0     5     4     3     2
`)
	if indirectionTableIsDefault(custom, 6) {
		t.Error("non-round-robin table that uses every queue must NOT parse as default")
	}
}

// #805 test 11: parser — empty / unparseable / value-less inputs all
// return false. The R3 sawAnyEntry guard must reject "row index with
// no values".
func TestIndirectionTableIsDefault_EmptyOutput_False(t *testing.T) {
	if indirectionTableIsDefault([]byte(""), 6) {
		t.Error("empty output must NOT be default")
	}
	headerOnly := []byte("RX flow hash indirection table for eth0 with 6 RX ring(s):\nRSS hash key:\n  0a:1b:2c:3d:4e\n")
	if indirectionTableIsDefault(headerOnly, 6) {
		t.Error("header-only output (no row data) must NOT be default")
	}
	emptyRow := []byte("    0:\n")
	if indirectionTableIsDefault(emptyRow, 6) {
		t.Error("row index with no values must NOT be default (sawAnyEntry guard)")
	}
}

// #805 test 12: full end-to-end transition. Step 1: workers=4, queues=6
// with a default starting table → write concentrated. Step 2: same
// iface, workers=6, queues=6 with the now-stale concentrated table →
// restore default.
func TestApplyRSSIndirectionOne_BootSequence_4then6_RestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable6q)},
	}

	// Step 1: workers=4. computeWeightVector → [1,1,1,1,0,0]. Live
	// table is default (doesn't match [1,1,1,1,0,0]) so a write fires.
	applyRSSIndirectionOne("eth0", 4, f)
	step1Calls := len(f.calls)
	sawWeight := false
	for _, c := range f.calls {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "weight" {
			sawWeight = true
		}
	}
	if !sawWeight {
		t.Fatalf("step 1 (workers=4): expected -X weight write, got %v", f.calls)
	}

	// Simulate the kernel-side outcome: live table is now the stale
	// concentrated layout.
	f.ethtoolX["eth0"] = []byte(staleTable6q4w)

	// Step 2: workers=6. computeWeightVector returns nil; the new
	// maybeRestoreDefault path must detect the stale table and fire
	// `ethtool -X eth0 default`.
	applyRSSIndirectionOne("eth0", 6, f)
	sawRestore := false
	for _, c := range f.calls[step1Calls:] {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "default" {
			sawRestore = true
		}
	}
	if !sawRestore {
		t.Fatalf("step 2 (workers=6): expected -X default restore, got %v",
			f.calls[step1Calls:])
	}
}

// #5124: full 4→1→4 worker-count transition on a 6-queue mlx5 NIC.
//   - Step 1 (4→concentrated): workers=4 writes [1,1,1,1,0,0].
//   - Step 2 (workers→1): the reduction must probe the now-stale
//     concentrated table and restore the round-robin default so RX is no
//     longer hashed onto queues 0..3 only.
//   - Step 3 (1→4): workers back to 4 re-writes the concentrated table.
//
// The kernel-side table is simulated between steps. With the pre-#5124
// behavior, Step 2 issues no restore and the stale table survives into
// Step 3 — Step 2's assertion goes RED.
func TestApplyRSSIndirectionOne_Transition_4then1then4(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable6q)},
	}

	// Step 1: workers=4 on a default table → write concentrated weights.
	applyRSSIndirectionOne("eth0", 4, f)
	sawWeight := false
	for _, c := range f.calls {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "weight" {
			sawWeight = true
		}
	}
	if !sawWeight {
		t.Fatalf("step 1 (workers=4): expected -X weight write, got %v", f.calls)
	}
	// Kernel now holds the concentrated layout.
	f.ethtoolX["eth0"] = []byte(staleTable6q4w)
	step1End := len(f.calls)

	// Step 2: workers→1. Must probe + restore the NIC default.
	applyRSSIndirectionOne("eth0", 1, f)
	sawRestore := false
	for _, c := range f.calls[step1End:] {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "default" {
			sawRestore = true
		}
	}
	if !sawRestore {
		t.Fatalf("step 2 (workers→1): expected -X default restore of the stale table, got %v",
			f.calls[step1End:])
	}
	// Kernel now holds the round-robin default again.
	f.ethtoolX["eth0"] = []byte(defaultTable6q)
	step2End := len(f.calls)

	// Step 3: workers back to 4 → re-write concentrated weights.
	applyRSSIndirectionOne("eth0", 4, f)
	sawReWeight := false
	for _, c := range f.calls[step2End:] {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "weight" {
			sawReWeight = true
		}
	}
	if !sawReWeight {
		t.Fatalf("step 3 (1→4): expected -X weight re-write, got %v", f.calls[step2End:])
	}
}

// #805 test 13 (Codex LOW #2): generic -x probe error suppresses
// the -X default call. The probe itself fails with a non-ErrNotFound
// error; maybeRestoreDefault must log Warn and return without
// attempting -X default.
func TestApplyRSSIndirectionOne_RestoreEthtoolXProbeGenericError_LogAndSkip(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
		argvErr: map[string]argvErrSpec{
			"-x eth0": {out: []byte("ethtool: bad request"), err: errors.New("exit status 1")},
		},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	for _, c := range f.calls {
		if len(c) >= 1 && c[0] == "-X" {
			t.Errorf("generic probe failure → must not invoke -X, got %v", c)
		}
	}
}

// #805 test 14 (Codex LOW #2): generic -X default error is logged
// and swallowed (D3 is best-effort). Ensures the function returns
// normally without panicking or propagating.
func TestApplyRSSIndirectionOne_RestoreEthtoolXDefaultGenericError_LoggedAndSwallowed(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
		argvErr: map[string]argvErrSpec{
			"-X eth0 default": {out: []byte("ethtool: kernel rejected"), err: errors.New("exit status 1")},
		},
	}
	// Should not panic. Both the -x probe and the failed -X default
	// should be recorded; the function returns normally.
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 2 {
		t.Fatalf("want 2 calls (probe + failed -X default), got %d: %v",
			len(f.calls), f.calls)
	}
	if !reflect.DeepEqual(f.calls[0], []string{"-x", "eth0"}) {
		t.Errorf("call 0: want probe, got %v", f.calls[0])
	}
	if !reflect.DeepEqual(f.calls[1], []string{"-X", "eth0", "default"}) {
		t.Errorf("call 1: want -X default, got %v", f.calls[1])
	}
}

// #805 test 15 (Codex LOW #3): non-mlx5 driver on the new branch.
// applyRSSIndirectionOne's first check is the driver guard; it must
// short-circuit BEFORE the new restore-default logic.
func TestApplyRSSIndirectionOne_NonMlxDriver_WorkersEqualsQueues_NotTouched(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": "virtio_net"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 0 {
		t.Errorf("non-mlx5 driver on workers>=queues path → zero ethtool calls, got %v",
			f.calls)
	}
}

// #805 test 16 (Codex LOW #3): empty driver string (sysfs unreadable
// for that iface). Same expectation as non-mlx5: short-circuit.
func TestApplyRSSIndirectionOne_EmptyDriver_WorkersEqualsQueues_NotTouched(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{}, // readDriver returns ""
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 0 {
		t.Errorf("empty driver on workers>=queues path → zero ethtool calls, got %v",
			f.calls)
	}
}

// #805 test 17 (Copilot inline #1): queueCount==1 short-circuit.
// On a single-queue NIC there's no possible concentration to undo;
// the guard `queues > 1` ensures we don't probe in that case.
func TestApplyRSSIndirectionOne_QueueCountOne_NoOp(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 1},
		ethtoolX: map[string][]byte{"eth0": []byte("RX flow hash indirection table for eth0 with 1 RX ring(s):\n    0:      0     0     0     0\n")},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	if len(f.calls) != 0 {
		t.Errorf("queueCount=1 must short-circuit before maybeRestoreDefault, got %v", f.calls)
	}
}

// ─── #3954: hash-key line must not be misparsed as a table row ───────
//
// Real mlx5 `ethtool -x` output ends with an "RSS hash key:" section whose
// bytes are printed colon-separated hex ("09:5c:8e:..."). When the first
// key byte is a decimal-looking hex value (both nibbles 0-9: 0x00-0x09,
// 0x10-0x19, ..., 0x90-0x99 — 100 of 256 values, ~39% of random keys) the
// "09" prefix parses as a valid decimal via strconv.Atoi, so the idempotence
// probe used to misread the key line as an indirection-table row whose
// remaining hex bytes then failed to parse → a false "current != desired"
// verdict → a spurious `ethtool -X` rewrite mid-traffic.
//
// These fixtures are captured-shape mlx5 output (128-entry table, 40-byte
// Toeplitz key) with a first key byte of 0x09 to pin the fix.

// capturedConstrainedTableDecimalKey: a live-shape `ethtool -x` dump whose
// indirection table only uses queues 0..3 (the layout mlx5 writes for
// weight vector [1 1 1 1 0 0]) AND whose RSS hash key begins with a
// decimal-looking byte (09). indirectionTableMatches([1,1,1,1,0,0]) must
// return true on this — i.e. the desired config is already applied.
const capturedConstrainedTableDecimalKey = `RX flow hash indirection table for ge-0-0-2 with 6 RX ring(s):
    0:      0     1     2     3     0     1     2     3
    8:      0     1     2     3     0     1     2     3
   16:      0     1     2     3     0     1     2     3
   24:      0     1     2     3     0     1     2     3
   32:      0     1     2     3     0     1     2     3
   40:      0     1     2     3     0     1     2     3
   48:      0     1     2     3     0     1     2     3
   56:      0     1     2     3     0     1     2     3
   64:      0     1     2     3     0     1     2     3
   72:      0     1     2     3     0     1     2     3
   80:      0     1     2     3     0     1     2     3
   88:      0     1     2     3     0     1     2     3
   96:      0     1     2     3     0     1     2     3
  104:      0     1     2     3     0     1     2     3
  112:      0     1     2     3     0     1     2     3
  120:      0     1     2     3     0     1     2     3
RSS hash key:
09:5c:8e:3a:7f:c1:d2:0b:44:91:6a:2e:88:fd:03:57:be:19:e4:7c:35:a0:6d:f2:48:9b:11:cc:82:5f:30:a7:6e:d9:04:53:bf:1a:e5:7d
RSS hash function:
    toeplitz: on
    xor: off
    crc32: off
`

// capturedDefaultTableDecimalKey: a live-shape `ethtool -x` dump whose
// indirection table is the kernel round-robin default across all 6 queues
// (entry[i] == i mod 6) AND whose RSS hash key begins with a decimal-looking
// byte (09). indirectionTableIsDefault(_, 6) must return true on this.
const capturedDefaultTableDecimalKey = `RX flow hash indirection table for ge-0-0-2 with 6 RX ring(s):
    0:      0     1     2     3     4     5     0     1
    8:      2     3     4     5     0     1     2     3
   16:      4     5     0     1     2     3     4     5
   24:      0     1     2     3     4     5     0     1
RSS hash key:
09:5c:8e:3a:7f:c1:d2:0b:44:91:6a:2e:88:fd:03:57:be:19:e4:7c:35:a0:6d:f2:48:9b:11:cc:82:5f:30:a7:6e:d9:04:53:bf:1a:e5:7d
RSS hash function:
    toeplitz: on
    xor: off
    crc32: off
`

// #3954 test 1 (RED on revert): the desired constrained layout is already
// live and the RSS key's first byte is decimal-looking (09). The probe must
// report "already applied" — the key line must not be misread as a table
// row. On revert the misparse makes indirectionTableMatches return false.
func TestIndirectionTableMatches_DecimalFirstKeyByte_StillMatches(t *testing.T) {
	if !indirectionTableMatches([]byte(capturedConstrainedTableDecimalKey), []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("constrained table with a decimal-looking RSS key byte must still match desired [1 1 1 1 0 0] " +
			"(#3954: the RSS hash key line must not be parsed as a table row)")
	}
}

// #3954 test 2: the round-robin default layout with a decimal-looking RSS
// key byte must still parse as default. On revert the key line "09:5c:..."
// is misread as row 9 whose entry "5c:8e:..." fails to parse → false.
func TestIndirectionTableIsDefault_DecimalFirstKeyByte_StillDefault(t *testing.T) {
	if !indirectionTableIsDefault([]byte(capturedDefaultTableDecimalKey), 6) {
		t.Fatal("round-robin default table with a decimal-looking RSS key byte must still parse as default " +
			"(#3954)")
	}
}

// #3954 test 3 (RED on revert, end-to-end): drive the full
// applyRSSIndirectionOne probe path with the golden fixture that already
// matches the desired weight vector. The probe must SKIP the rewrite — the
// only ethtool call is the `-x` probe, no `-X weight`. On revert the
// hash-key misparse forces a spurious `ethtool -X` weight rewrite (2 calls).
func TestApplyRSSIndirectionOne_MatchingTableDecimalKey_SkipsWrite(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"ge-0-0-2": mlx5Driver},
		queues:   map[string]int{"ge-0-0-2": 6},
		ethtoolX: map[string][]byte{"ge-0-0-2": []byte(capturedConstrainedTableDecimalKey)},
	}
	// workers=4, queues=6 → desired weights [1 1 1 1 0 0], already live.
	applyRSSIndirectionOne("ge-0-0-2", 4, f)

	if len(f.calls) != 1 {
		t.Fatalf("want exactly 1 ethtool call (probe only), got %d: %v (#3954: spurious -X rewrite)",
			len(f.calls), f.calls)
	}
	if f.calls[0][0] != "-x" {
		t.Fatalf("the single call must be the -x probe, got %v", f.calls[0])
	}
	for _, c := range f.calls {
		if c[0] == "-X" {
			t.Fatalf("already-correct RSS config must not trigger `ethtool -X`, got %v", c)
		}
	}
}

// #3954 test 4: the negative path still fires. When the live table is the
// full round-robin default (queues 0..5) but only 4 workers are desired, the
// config genuinely differs → exactly one `ethtool -X weight` rewrite. Pins
// that the section-bounded parser did not over-suppress writes.
func TestApplyRSSIndirectionOne_DifferingTableDecimalKey_WritesOnce(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"ge-0-0-2": mlx5Driver},
		queues:   map[string]int{"ge-0-0-2": 6},
		ethtoolX: map[string][]byte{"ge-0-0-2": []byte(capturedDefaultTableDecimalKey)},
	}
	applyRSSIndirectionOne("ge-0-0-2", 4, f)

	writes := 0
	for _, c := range f.calls {
		if len(c) >= 3 && c[0] == "-X" && c[2] == "weight" {
			writes++
			want := []string{"-X", "ge-0-0-2", "weight", "1", "1", "1", "1", "0", "0"}
			if !reflect.DeepEqual(c, want) {
				t.Fatalf("weight argv mismatch: want %v, got %v", want, c)
			}
		}
	}
	if writes != 1 {
		t.Fatalf("genuinely-different config must issue exactly one -X weight, got %d: %v",
			writes, f.calls)
	}
}

// #3954 test 5 (unit, parser): the shared parser stops at the RSS hash key
// section so the decimal-first-byte key line contributes no rows, and the
// preceding table rows all parse. Guards the section bound directly.
func TestParseIndirectionTable_StopsAtHashKey(t *testing.T) {
	rows, ok := parseIndirectionTable([]byte(capturedConstrainedTableDecimalKey))
	if !ok {
		t.Fatal("parse must succeed (all in-section tokens are integers)")
	}
	if len(rows) != 16 {
		t.Fatalf("want 16 indirection rows (key/function sections excluded), got %d", len(rows))
	}
	for _, row := range rows {
		if len(row.entries) != 8 {
			t.Fatalf("row %d: want 8 entries, got %d", row.idx, len(row.entries))
		}
		for _, q := range row.entries {
			if q < 0 || q > 3 {
				t.Fatalf("row %d: constrained table must only use queues 0..3, saw %d", row.idx, q)
			}
		}
	}
}

// Sanity: the production isExecNotFound detects the stable sentinel that
// `exec.Command("missing").CombinedOutput()` wraps, without substring
// matching (Go MEDIUM #1).
func TestIsExecNotFound_DetectsSentinel(t *testing.T) {
	wrapped := &exec.Error{Name: "ethtool", Err: exec.ErrNotFound}
	if !isExecNotFound(wrapped) {
		t.Fatal("expected true for wrapped exec.ErrNotFound")
	}
	fsPathErr := &fs.PathError{Op: "exec", Path: "ethtool", Err: exec.ErrNotFound}
	if !isExecNotFound(fsPathErr) {
		t.Fatal("expected true for PathError wrapping exec.ErrNotFound")
	}
	other := errors.New("some other error")
	if isExecNotFound(other) {
		t.Fatal("must not match unrelated errors")
	}
	if isExecNotFound(nil) {
		t.Fatal("nil must not match")
	}
}
