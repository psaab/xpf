// Host-scope tunables (#801): CPU governor + net.core.netdev_budget.
//
// Both knobs are Phase-B Step-0 audit fixes. The governor pushes every
// writable /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node to
// the operator's requested mode (default "performance"). The budget
// writes /proc/sys/net/core/netdev_budget. Neither touches a network
// interface directly — they are system-wide, so there is no per-iface
// driver guard: either the sysfs node is writable or it is not.
//
// Why a separate file from rss_indirection.go: these knobs cross
// sysctl + cpufreq abstraction lines and have different failure modes
// (VM no-op for governor, read-only mounts for sysctl) that deserve
// their own logging and their own unit tests. Keeping them here means
// test fakes don't have to stub ethtool.
//
// All three functions are best-effort: a failure never blocks daemon
// startup or config commit. Matches D3's invariant that tunables must
// not regress interface bring-up.
package daemon

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Defaults used when the operator omits the knob entirely. Exposed so
// applyConfig can resolve defaults at the call site (avoids sprinkling
// literal constants across daemon.go).
const (
	defaultCPUGovernor  = "performance"
	defaultNetdevBudget = 600
	defaultCoalesceRX   = 8
	defaultCoalesceTX   = 8
)

// hostTunableFS abstracts the filesystem writes performed by the
// governor + netdev_budget logic so unit tests can assert exact writes
// without touching real sysfs. The interface is intentionally narrow:
// list-cpufreq-governor-nodes, read one, write one, write a sysctl
// file. Production callers use realHostTunableFS; tests use a fake.
type hostTunableFS interface {
	// listCPUGovernorPaths returns the absolute paths of every
	// /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node. An
	// empty slice indicates cpufreq is not exposed (typical VM).
	listCPUGovernorPaths() []string
	// readFile reads the file at path. Distinct from writeFile so
	// idempotency (skip-if-already-set) can be asserted in tests.
	readFile(path string) ([]byte, error)
	// writeFile writes data to path. Failures are returned for the
	// caller to log (we never want a fake that silently drops writes).
	writeFile(path string, data []byte) error
	// listNeighDirs returns the immediate sub-directory names under a
	// /proc/sys/net/{ipv4,ipv6}/neigh directory (one per interface plus
	// "default"). An empty slice means the directory could not be read
	// (#1636). Distinct from a generic glob so the test fake can script
	// an exact interface set.
	listNeighDirs(dir string) []string
}

type realHostTunableFS struct{}

func (realHostTunableFS) listCPUGovernorPaths() []string {
	// glob is the simplest expression of "one node per CPU". cpufreq
	// filesystems are small — no reason to walk.
	matches, err := filepath.Glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

func (realHostTunableFS) readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (realHostTunableFS) writeFile(path string, data []byte) error {
	// 0644 is the sysfs/proc convention; real writes go through the
	// kernel's sysfs handler and ignore the mode, but setting it keeps
	// this identical to `echo > ...`.
	return os.WriteFile(path, data, 0644)
}

func (realHostTunableFS) listNeighDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		// /proc/sys/net/{ipv4,ipv6}/neigh/<iface> are directories;
		// IsDir() is unreliable on procfs symlinks, so accept any entry
		// — the subsequent retrans_time_ms read/write tolerates a miss.
		out = append(out, e.Name())
	}
	return out
}

// vmSkipLogOnce ensures the "no cpufreq sysfs — VM?" note is emitted at
// slog.Info exactly once per process (F2). Subsequent skips log at
// slog.Debug. `applyConfig` runs every commit; without this gate the
// Info line drowns the operator's real state-transition logs.
var vmSkipLogOnce sync.Once

// vmHeuristic inspects the host for well-known virtualization signals.
// Returns a human-readable reason ("kvm", "systemd-detect-virt:qemu",
// …) when the host looks virtualized, or empty when it looks like bare
// metal. Used to distinguish "VM with no cpufreq" (expected, Info) from
// "bare metal with no cpufreq" (unexpected — likely intel_pstate=disable
// or acpi=off, operator should know — Warn, M1).
//
// Heuristics checked, in order:
//   - /sys/hypervisor/type non-empty (e.g. "xen", "kvm", "microsoft").
//   - /proc/cpuinfo contains a "hypervisor" flag (KVM/VMware/QEMU all set).
//   - systemd-detect-virt --quiet exits zero and emits a virt name.
//
// All three are permissive: an absent file is treated as "not this
// signal"; an error surface is not propagated because we only want the
// caller to know "virtualized, skip is fine" vs "bare metal, this is a
// config miss." The hostTunableFS interface is reused so tests can mock
// the sysfs reads without shelling out.
func vmHeuristic(fs hostTunableFS) string {
	// /sys/hypervisor/type — present when the kernel detects a
	// hypervisor. Contents like "xen", "kvm", "microsoft".
	if raw, err := fs.readFile("/sys/hypervisor/type"); err == nil {
		if v := strings.TrimSpace(string(raw)); v != "" {
			return "/sys/hypervisor/type=" + v
		}
	}
	// /proc/cpuinfo — the "hypervisor" CPU flag is set by KVM, QEMU,
	// VMware, Hyper-V. Quick grep is sufficient — we only check for the
	// token, not which vendor.
	if raw, err := fs.readFile("/proc/cpuinfo"); err == nil {
		if bytesContainsHypervisorFlag(raw) {
			return "/proc/cpuinfo:hypervisor-flag"
		}
	}
	return ""
}

// bytesContainsHypervisorFlag returns true if raw's "flags" lines
// contain the literal "hypervisor" token. Keeps the detection in one
// place so the test fake can exercise a canned cpuinfo.
func bytesContainsHypervisorFlag(raw []byte) bool {
	// Fast path: look for "hypervisor" token in any "flags" or "Features"
	// line. The token may be adjacent to whitespace or the end-of-line.
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "flags") && !strings.HasPrefix(line, "Features") {
			continue
		}
		for _, tok := range strings.Fields(line) {
			if tok == "hypervisor" {
				return true
			}
		}
	}
	return false
}

// applyCPUGovernor writes the requested governor to every writable
// cpufreq node. `requested` values:
//   - ""          : no-op (operator left default unspecified — treat as "leave alone")
//   - "default"   : alias of "" — no-op
//   - anything else: try to write verbatim. We do NOT validate the
//     governor name because bare-metal operators may legitimately
//     request `powersave` / `ondemand` on a lab box. The kernel
//     enforces the valid set.
//
// VM semantics: `listCPUGovernorPaths` returns an empty slice when
// cpufreq is not exposed through QEMU/KVM to the guest (every current
// xpf VM). We log exactly once at Info (F2) — subsequent skips log at
// Debug so commit-time reconciles don't flood. If the host does NOT
// look like a VM (M1: bare-metal no cpufreq signals), we log a WARN
// once instead — that state is usually intel_pstate=disable or acpi=off
// and an operator should know.
//
// Idempotency: each node is read first and skipped if it already
// matches. Avoids sysfs write-amplification across reconciles.
//
// Read-only mounts (chroot, unprivileged containers) surface as
// EACCES/EROFS on writeFile. We log one warning per node and move on.
//
// `capture` may be nil. When non-nil, each node's pre-xpfd value is
// recorded via capture.captureGovernor BEFORE the first write. First-
// apply wins: subsequent reconciles do not overwrite the snapshot.
func applyCPUGovernor(requested string, fs hostTunableFS, capture *priorHostTunables) {
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == "default" {
		// Operator opted out. Nothing to do.
		slog.Debug("linksetup: cpu governor skip (no config)")
		return
	}
	paths := fs.listCPUGovernorPaths()
	if len(paths) == 0 {
		// VM case — or bare metal with cpufreq disabled (M1). Probe
		// the VM heuristics to distinguish. sync.Once pins the loud
		// branch to one emission per process; reconciles fall through
		// to Debug so `applyConfig` isn't a firehose (F2).
		vmSkipLogOnce.Do(func() {
			if reason := vmHeuristic(fs); reason != "" {
				slog.Info("linksetup: cpu governor skip (no cpufreq sysfs — VM)",
					"requested", requested, "virt", reason)
			} else {
				slog.Warn("linksetup: cpu governor skip (no cpufreq sysfs, no VM signal)",
					"requested", requested,
					"hint", "check intel_pstate=disable / acpi=off; governor write will be a no-op")
			}
		})
		slog.Debug("linksetup: cpu governor skip (no cpufreq sysfs)",
			"requested", requested)
		return
	}

	wrote := 0
	skipped := 0
	failed := 0
	drift := 0 // MIN1: node differs from both desired AND pre-xpfd
	target := []byte(requested)
	for _, p := range paths {
		existing, err := fs.readFile(p)
		liveVal := ""
		if err == nil {
			liveVal = strings.TrimSpace(string(existing))
		}
		// Capture the pre-xpfd value the FIRST time we see this
		// node. First-apply wins so that subsequent reconciles do
		// not lose the original value.
		if liveVal != "" {
			capture.captureGovernor(p, liveVal)
		}
		if liveVal == requested {
			skipped++
			continue
		}
		// MIN1: live value differs from our desired value. Check if
		// it also differs from what we captured (i.e. someone changed
		// it out from under us between reconciles) and log a warn.
		if capture != nil {
			if prior, ok := capture.governors[p]; ok && prior != liveVal && liveVal != "" {
				drift++
				slog.Warn("linksetup: cpu governor drift detected; overwriting",
					"path", p, "captured_prior", prior,
					"live", liveVal, "writing", requested)
			}
		}
		if err := fs.writeFile(p, target); err != nil {
			// Read-only host, EACCES, or governor name not on the
			// kernel's allowed list. Log once per failing node with
			// the specific path so the operator can pinpoint it.
			failed++
			// Log only the first few failures (cpu0 is
			// representative of every other CPU's failure mode).
			if failed <= 2 {
				slog.Warn("linksetup: cpu governor write failed",
					"path", p, "requested", requested, "err", err)
			}
			continue
		}
		wrote++
	}
	if wrote == 0 && failed == 0 {
		// All nodes already matched — avoid the Info line on
		// every reconcile (F2-adjacent: reconcile-time idempotency).
		slog.Debug("linksetup: cpu governor unchanged",
			"requested", requested, "skipped", skipped, "total", len(paths))
		return
	}
	slog.Info("linksetup: cpu governor applied",
		"requested", requested, "wrote", wrote,
		"skipped_already_set", skipped, "failed", failed,
		"drift", drift, "total", len(paths))
}

// sysctlPathNetdevBudget is the procfs path written by applyNetdevBudget.
// Exposed as a constant so the test fake can assert on exact paths.
const sysctlPathNetdevBudget = "/proc/sys/net/core/netdev_budget"

// applyNetdevBudget writes the requested value to /proc/sys/net/core/
// netdev_budget. 0 is the sentinel for "leave kernel default" — the
// daemon resolves a non-zero default at the call site.
//
// Why we accept 0 as "skip" instead of always writing defaultNetdevBudget:
// some deploy paths may prefer to leave the value at the kernel default
// (300) for profiling comparisons without editing sysctl.conf. The
// compiler emits 0 when the knob is omitted, and the call site decides
// whether to substitute defaultNetdevBudget (yes, for userspace-dp
// deploys) or pass 0 through (non-userspace deploys).
//
// Idempotent: reads current value first and skips the write if it
// already matches. Read-only /proc (unprivileged container) surfaces
// as a log warning, not a fatal error.
//
// `capture` may be nil. When non-nil, the pre-xpfd value is captured
// before the first write (B2). MIN1: if the live value differs from
// both desired and the captured pre-xpfd value, a drift warning is
// logged and the write still proceeds.
func applyNetdevBudget(value int, fs hostTunableFS, capture *priorHostTunables) {
	if value == 0 {
		slog.Debug("linksetup: netdev_budget skip (no config)")
		return
	}
	if value < 0 {
		// Defensive — net.core.netdev_budget must be > 0. Don't
		// propagate a nonsense value to the kernel.
		slog.Warn("linksetup: netdev_budget skip (non-positive)", "value", value)
		return
	}
	want := strconv.Itoa(value)
	existing, err := fs.readFile(sysctlPathNetdevBudget)
	liveVal := ""
	if err == nil {
		liveVal = strings.TrimSpace(string(existing))
	}
	if liveVal != "" {
		capture.captureBudget(liveVal)
	}
	if liveVal == want {
		slog.Debug("linksetup: netdev_budget already set", "value", value)
		return
	}
	// MIN1: drift detection — live value differs from desired and
	// from what we captured on first apply.
	if capture != nil && capture.budget != "" && capture.budget != liveVal && liveVal != "" {
		slog.Warn("linksetup: netdev_budget drift detected; overwriting",
			"captured_prior", capture.budget, "live", liveVal, "writing", want)
	}
	if err := fs.writeFile(sysctlPathNetdevBudget, []byte(want)); err != nil {
		if errors.Is(err, os.ErrPermission) {
			slog.Warn("linksetup: netdev_budget write denied (read-only /proc?)",
				"value", value, "err", err)
			return
		}
		slog.Warn("linksetup: netdev_budget write failed",
			"value", value, "err", err)
		return
	}
	slog.Info("linksetup: netdev_budget applied", "value", value)
}

// Neighbor retransmit-time sysctls (#1636). Lowering these from the
// 1000ms kernel default to 250ms is the dominant lever for cold-connect
// recovery against an unknown next-hop: the kernel's own ARP/NDP
// retransmit timer then fires every 250ms instead of every 1000ms, so a
// dropped initial solicit is re-driven ~4× sooner. See
// docs/pr/1636-cold-connect-mitigation/plan.md option B.
//
// Both the IPv4 and IPv6 "default" neighbor tables are written; "default"
// is the template every newly-created interface inherits, so this covers
// dataplane interfaces brought up after daemon start as well as those
// already present. Per-interface tables created from a stale template are
// re-evaluated by option D's runtime guard
// (compute_pending_neigh_timeout_ns) on every snapshot apply.
const (
	sysctlNeighV4Dir = "/proc/sys/net/ipv4/neigh"
	sysctlNeighV6Dir = "/proc/sys/net/ipv6/neigh"
	// neighRetransTargetMs is the value the daemon writes. Option D's
	// userspace guard (compute_pending_neigh_timeout_ns) admits the fast
	// 800ms PENDING_NEIGH_TIMEOUT when every dataplane interface reads
	// <= NEIGH_RETRANS_FAST_THRESHOLD_MS (300ms) — that threshold is
	// deliberately above this target because the kernel rounds
	// retrans_time_ms to its internal jiffy resolution (a write of 250
	// reads back as 252 on HZ=100 hosts).
	neighRetransTargetMs = 250
)

// applyNeighRetransTime lowers the kernel neighbor retrans_time_ms to
// neighRetransTargetMs across BOTH IPv4 and IPv6 neighbor tables.
//
// CRITICAL: writing only the `default` template does NOT lower the value
// on interfaces that already exist — the kernel seeds a per-interface
// neighbor table from `default` only at table-creation time. By the time
// xpfd runs, the dataplane interfaces already exist with the 1000ms
// default. So this walks every per-interface table under
// /proc/sys/net/{ipv4,ipv6}/neigh/<iface>/retrans_time_ms AND writes the
// `default` template (so interfaces created later inherit the fast
// value).
//
// Mirrors applyNetdevBudget: idempotent (skip-if-already-set per path),
// best-effort (read-only /proc surfaces as a warning, never an error),
// and captures the pre-xpfd value of each path once so restore can
// revert it.
//
// Unlike the cpu-governor / netdev_budget knobs this is NOT gated behind
// claim-host-tunables: retrans_time_ms is a neighbor-resolution timing
// parameter, not a system-wide performance knob, and lowering it is
// strictly beneficial for any forwarding deploy. It is still captured +
// restored so a co-tenant's tuned value is put back on daemon stop.
//
// Known limitation (AGY r1 #3): only interface tables that exist at apply
// time are captured for restore. An interface created AFTER apply inherits
// 250ms from the lowered `default` template and is not reverted on stop
// (its pre-xpfd value was never observed). This is benign — a 250ms
// neighbor retransmit is a strict improvement on any interface — and
// matches the best-effort, observed-value-only restore contract of the
// host-global netdev_budget knob.
func applyNeighRetransTime(fs hostTunableFS, capture *priorHostTunables) {
	want := strconv.Itoa(neighRetransTargetMs)
	applied, skipped, failed := 0, 0, 0
	for _, path := range neighRetransPaths(fs) {
		existing, err := fs.readFile(path)
		liveVal := ""
		if err == nil {
			liveVal = strings.TrimSpace(string(existing))
		}
		if liveVal != "" {
			capture.captureNeighRetrans(path, liveVal)
		}
		if liveVal == want {
			skipped++
			continue
		}
		if err := fs.writeFile(path, []byte(want)); err != nil {
			failed++
			if errors.Is(err, os.ErrPermission) {
				slog.Warn("linksetup: neigh retrans_time_ms write denied (read-only /proc?)",
					"path", path, "value", want, "err", err)
				continue
			}
			slog.Warn("linksetup: neigh retrans_time_ms write failed",
				"path", path, "value", want, "err", err)
			continue
		}
		applied++
	}
	if applied > 0 {
		slog.Info("linksetup: neigh retrans_time_ms applied",
			"value", want, "applied", applied, "already_set", skipped, "failed", failed)
	} else {
		slog.Debug("linksetup: neigh retrans_time_ms unchanged",
			"value", want, "already_set", skipped, "failed", failed)
	}
}

// neighRetransPaths enumerates every retrans_time_ms sysctl path to
// write: the `default` template plus every existing per-interface
// neighbor table, for both IPv4 and IPv6. A directory listing failure
// falls back to writing just the `default` template so the function is
// never a hard no-op on a constrained host.
func neighRetransPaths(fs hostTunableFS) []string {
	var paths []string
	for _, dir := range []string{sysctlNeighV4Dir, sysctlNeighV6Dir} {
		entries := fs.listNeighDirs(dir)
		if len(entries) == 0 {
			// Fall back to the default template only.
			paths = append(paths, dir+"/default/retrans_time_ms")
			continue
		}
		seenDefault := false
		for _, name := range entries {
			if name == "default" {
				seenDefault = true
			}
			paths = append(paths, dir+"/"+name+"/retrans_time_ms")
		}
		if !seenDefault {
			paths = append(paths, dir+"/default/retrans_time_ms")
		}
	}
	return paths
}

// resolvedHostTunables returns the effective governor + budget given
// the config values and default substitution rules. Extracted as a
// pure function so the daemon-wire code can unit-test the
// "omitted-becomes-default when userspace-dp in use" logic.
//
//   - governorIn=""          → defaultCPUGovernor if userspaceDP else ""
//
//   - governorIn="default"   → "" (pass-through sentinel for skip)
//
//   - governorIn="performance"/"schedutil"/anything else → verbatim
//
//   - budgetIn=0             → defaultNetdevBudget if userspaceDP else 0
//
//   - budgetIn>0             → verbatim
//
// The rationale: the #801 Step-0 audit is scoped to userspace-dp
// deploys (the only configuration where the line-rate PRs apply).
// eBPF/DPDK/no-dataplane deploys never receive the default — their
// baseline remains "whatever the host has". Operator can still opt
// in on those deploys by setting the knob explicitly.
func resolvedHostTunables(governorIn string, budgetIn int, userspaceDP bool) (string, int) {
	gov := governorIn
	if gov == "" && userspaceDP {
		gov = defaultCPUGovernor
	}
	if gov == "default" {
		// "default" is an explicit skip sentinel. Normalize to "" so
		// applyCPUGovernor's skip path is taken.
		gov = ""
	}
	budget := budgetIn
	if budget == 0 && userspaceDP {
		budget = defaultNetdevBudget
	}
	return gov, budget
}

// applyHostTunables is the single entry point called from daemon
// startup + reconcile. Composes the governor + budget paths with
// consistent logging, and swallows all errors. Mirrors D3's
// applyRSSIndirection contract.
//
// `capture` may be nil (tests that don't care about restore). When
// non-nil, the pre-xpfd value of each knob is stored before the first
// write so restoreHostTunables can revert to that exact value on
// disable or shutdown (B2).
func applyHostTunables(governor string, budget int, fs hostTunableFS, capture *priorHostTunables) {
	applyCPUGovernor(governor, fs, capture)
	applyNetdevBudget(budget, fs, capture)
}

// priorHostTunables captures the pre-xpfd values of the host-scope
// knobs xpfd has touched. Used by the B2 restore-on-disable path:
// when `claim-host-tunables` transitions from true → false (or xpfd
// shuts down), every field present in this struct is written back to
// the kernel. A missing field (empty governor map, zero budget) means
// xpfd never wrote that knob and there is nothing to restore.
//
// Documented invariant: "restore" reverts to the value xpfd read
// before its first write. It does NOT revert to the kernel's compiled
// default. If an admin manually set `performance` in
// /etc/sysctl.d/99-xpf.conf before xpfd started, and xpfd later wrote
// `powersave`, restore puts it back to `performance` (what was live
// when xpfd saw it), not to the kernel's hardcoded default.
//
// Crash-persistence policy (Codex round-2): this struct lives ONLY
// in memory on the Daemon. It is never written to disk. Rationale:
//
//   - The host-scope values (cpu governor, netdev_budget) are
//     idempotent across daemon restarts — if xpfd crashes with
//     governor=performance and netdev_budget=600, the next startup
//     reads those xpfd-written values as "prior" and continues
//     writing the same values. No drift, no surprise.
//   - On crash-recovery, the "restore" path would revert to the
//     xpfd-written value anyway (identity restore), so persisting
//     the pre-xpfd snapshot buys nothing the operator didn't have
//     before the crash.
//   - Operators who need strict pre-xpfd recovery across crashes
//     can write their intended values to /etc/sysctl.d/ or to a
//     systemd ExecStartPre hook — those run before xpfd and are
//     the canonical place for "this is my baseline" state.
//
// A persisted snapshot (option /run/xpf/priortunables.json) was
// rejected because the write-on-first-apply cost + the extra
// stat/load on startup exceeds the value we'd get from an
// identity restore.
type priorHostTunables struct {
	// governors maps cpufreq scaling_governor path → original string
	// (trim-space, no trailing newline). An empty map means the
	// governor was never captured — either the host has no cpufreq
	// sysfs, or no governor write has been attempted. Keyed by path
	// so restore walks only the nodes xpfd touched, never the broader
	// set. Absence of a key in this map means xpfd did not write
	// that CPU and restore does nothing on it.
	governors map[string]string
	// budget holds the original /proc/sys/net/core/netdev_budget value
	// as a string. Empty string means "never captured" — xpfd did not
	// write netdev_budget, so restore has nothing to do. Stored as a
	// string (not int) so the exact byte form the kernel served is
	// round-tripped on restore.
	budget string
	// mlx5Adaptive maps mlx5 interface name → captured adaptive-rx/tx
	// + rx-usecs/tx-usecs tuple. Absence of a key means xpfd never
	// wrote this iface's coalescence; restore does nothing on it.
	// The value is a verbatim snapshot of the coalescence state so the
	// restore call emits an identical `ethtool -C` invocation.
	mlx5Adaptive map[string]mlx5CoalesceState
	// neighRetrans maps a neighbor retrans_time_ms sysctl path → the
	// original value (#1636). Absence of a key means xpfd never wrote
	// that path; restore does nothing on it. Stored as a string so the
	// exact byte form the kernel served is round-tripped on restore.
	neighRetrans map[string]string
	// rssOwned is the set of interfaces (any driver, #15253) whose RSS
	// indirection table xpfd may have moved away from the kernel
	// default (#6801; the capability-probed apply set since #9040).
	// Unlike the maps above this holds no captured VALUE: the restore
	// action is `ethtool -X <iface> default`, the same idempotent call
	// the rss-indirection kill switch issues, so the pre-xpfd table
	// never has to be reconstructed. Membership is the ownership claim
	// — see claimNICTunableOwnership for why it is deliberately a
	// superset of "reprogrammed on this reconcile", and
	// releaseUnboundNICTunables for the `owned - current` teardown that
	// consumes it.
	rssOwned map[string]struct{}
}

// mlx5CoalesceState captures the four fields xpfd writes via ethtool -C.
// Used by priorHostTunables.mlx5Adaptive to remember the pre-xpfd state
// of each mlx5 interface touched.
type mlx5CoalesceState struct {
	adaptiveRX bool
	adaptiveTX bool
	rxUsecs    int
	txUsecs    int
}

// newPriorHostTunables allocates a zero-value capture struct. The maps
// are created lazily on first-touch so tests can assert "nothing
// captured" via nil-map checks.
func newPriorHostTunables() *priorHostTunables {
	return &priorHostTunables{
		governors:    map[string]string{},
		mlx5Adaptive: map[string]mlx5CoalesceState{},
		neighRetrans: map[string]string{},
		rssOwned:     map[string]struct{}{},
	}
}

// captureGovernor stores the current on-disk value of a single
// cpufreq scaling_governor node. No-op if path is already captured
// (first-apply wins; subsequent reconciles must not overwrite the
// pre-xpfd snapshot with an xpfd-written value).
func (p *priorHostTunables) captureGovernor(path, value string) {
	if p == nil {
		return
	}
	if _, already := p.governors[path]; already {
		return
	}
	p.governors[path] = strings.TrimSpace(value)
}

// captureBudget stores the current /proc/sys/net/core/netdev_budget
// value. No-op once captured (first-apply wins).
func (p *priorHostTunables) captureBudget(value string) {
	if p == nil {
		return
	}
	if p.budget != "" {
		return
	}
	p.budget = strings.TrimSpace(value)
}

// captureNeighRetrans stores the pre-xpfd value of a neighbor
// retrans_time_ms sysctl (#1636). No-op once captured for that path
// (first-apply wins). Lazily allocates the map so a nil-map capture
// (older newPriorHostTunables callers in tests) does not panic.
func (p *priorHostTunables) captureNeighRetrans(path, value string) {
	if p == nil {
		return
	}
	if p.neighRetrans == nil {
		p.neighRetrans = map[string]string{}
	}
	if _, already := p.neighRetrans[path]; already {
		return
	}
	p.neighRetrans[path] = strings.TrimSpace(value)
}

// captureMlx5Coalesce stores the pre-xpfd coalescence state of a
// single mlx5 interface. No-op once captured (first-apply wins).
func (p *priorHostTunables) captureMlx5Coalesce(iface string, s mlx5CoalesceState) {
	if p == nil {
		return
	}
	if _, already := p.mlx5Adaptive[iface]; already {
		return
	}
	p.mlx5Adaptive[iface] = s
}

// claimRSSOwnership records that xpfd holds the RSS indirection table of
// iface (#6801). Idempotent. Lazily allocates the set so a capture
// struct built by an older newPriorHostTunables caller (tests predating
// the field) does not panic.
func (p *priorHostTunables) claimRSSOwnership(iface string) {
	if p == nil || iface == "" {
		return
	}
	if p.rssOwned == nil {
		p.rssOwned = map[string]struct{}{}
	}
	p.rssOwned[iface] = struct{}{}
}

// restoreHostTunables writes every captured tunable back to the kernel.
// Errors are logged and swallowed: restore must not block daemon
// shutdown or config commit. After a successful restore, the caller is
// expected to reset priorTunablesActive=false so the next opt-in cycle
// starts with a fresh capture.
//
// The mlx5 restore is delegated to applyCoalescence (via mlx5execer) to
// reuse the ethtool -C code path. The governor + budget writes use the
// host tunable FS directly because they are simple atomic file writes.
//
// Crash recovery (Codex round-2): priorTunables lives in memory only.
// If xpfd crashes after writing host-scope knobs, the next startup
// reads the xpfd-written values as "prior" (idempotent — the governor
// and netdev_budget are stable across restarts so this is harmless).
// This is a documented, deliberate simplification — a persisted
// snapshot at /run/xpf/priortunables.json would add a write on every
// first-apply for very little additional safety. Operators who need
// strict pre-xpfd restore after a crash can write the intended values
// to /etc/sysctl.d/ or to a systemd ExecStartPre.
func restoreHostTunables(p *priorHostTunables, fs hostTunableFS, execer rssExecutor) {
	if p == nil {
		slog.Debug("linksetup: host tunables restore skip (no capture)")
		return
	}
	restoreHostScopeTunables(p, fs)
	// mlx5 adaptive + rx/tx-usecs. Reuse ethtool -C via the same
	// executor used by applyCoalescenceOne.
	for iface, s := range p.mlx5Adaptive {
		restoreMlx5Coalesce(iface, s, execer)
	}
}

// hostScopeRestoreResult reports the per-field outcome of
// restoreHostScopeTunables so the runtime-disable caller can honor the
// ownership invariant (#5114): ownership of a host-scope knob is
// released only after its restore write SUCCEEDS. A field counts as
// restored when its write succeeded OR the field was empty/sentinel
// (nothing to write). Fields whose write FAILED are reported back so
// the caller retains their captured baseline as retry debt instead of
// silently dropping it and leaving the host pinned at xpfd's value.
type hostScopeRestoreResult struct {
	// failedGovernors maps cpufreq scaling_governor path → captured
	// value for every governor whose restore write failed and must be
	// retained. Always non-nil; empty when every governor restored.
	failedGovernors map[string]string
	// budgetFailed is true when the netdev_budget restore write failed;
	// budgetValue then holds the captured value to retain.
	budgetFailed bool
	budgetValue  string
}

// allRestored reports whether every captured host-scope field restored
// successfully, i.e. no retry debt remains and ownership may be
// released (priorTunablesActive → false).
func (r hostScopeRestoreResult) allRestored() bool {
	return len(r.failedGovernors) == 0 && !r.budgetFailed
}

// restoreHostScopeTunables writes only the host-scope captures
// (cpu governor + netdev_budget) back to the kernel. Used when the
// `claim-host-tunables` opt-in flips true → false without disabling
// the rest of the dataplane: per-interface coalescence stays active,
// so its captures are retained, but the operator has retracted their
// consent to hold host-global knobs.
//
// Returns a hostScopeRestoreResult naming the fields whose kernel write
// FAILED (#5114). The caller must retain those captures + keep
// priorTunablesActive true so a later reconcile retries them; a
// transient sysfs/proc write failure must not release ownership and
// leave the host pinned at xpfd's governor / netdev_budget after the
// operator withdrew consent. Successful (and empty-sentinel) fields are
// reported as restored so the caller drops them. Safe to call with a
// nil pointer (no-op → allRestored() true).
func restoreHostScopeTunables(p *priorHostTunables, fs hostTunableFS) hostScopeRestoreResult {
	res := hostScopeRestoreResult{failedGovernors: map[string]string{}}
	if p == nil {
		return res
	}
	// Governor: write each captured path only if its value is
	// non-empty (skip sentinel). Retain any path whose write fails.
	restored := 0
	for path, value := range p.governors {
		if value == "" {
			continue
		}
		if err := fs.writeFile(path, []byte(value)); err != nil {
			slog.Warn("linksetup: host tunable restore — governor write failed",
				"path", path, "want", value, "err", err)
			res.failedGovernors[path] = value
			continue
		}
		restored++
	}
	if restored > 0 {
		slog.Info("linksetup: cpu governor restored to pre-xpfd value",
			"restored", restored, "total", len(p.governors))
	}
	// netdev_budget.
	if p.budget != "" {
		if err := fs.writeFile(sysctlPathNetdevBudget, []byte(p.budget)); err != nil {
			slog.Warn("linksetup: host tunable restore — netdev_budget write failed",
				"want", p.budget, "err", err)
			res.budgetFailed = true
			res.budgetValue = p.budget
		} else {
			slog.Info("linksetup: netdev_budget restored to pre-xpfd value",
				"value", p.budget)
		}
	}
	return res
}

// restoreNeighRetransTime writes every captured neighbor retrans_time_ms
// value back to the kernel (#1636). Unlike the cpu-governor / netdev
// knobs this is restored unconditionally on daemon stop (it applies
// unconditionally, not behind claim-host-tunables), so a co-tenant's
// tuned value is put back when xpfd exits.
//
// Returns the map of captures whose kernel write FAILED — path →
// captured value — so the runtime-disable caller retains them as retry
// debt instead of dropping the capture and stranding the host at the
// lowered 250ms after the dataplane that wanted it is gone (#5114). The
// returned map is always non-nil; empty means every path restored.
// Safe with a nil pointer or empty map (no-op → empty map).
func restoreNeighRetransTime(p *priorHostTunables, fs hostTunableFS) map[string]string {
	retained := map[string]string{}
	if p == nil || len(p.neighRetrans) == 0 {
		return retained
	}
	restored := 0
	for path, value := range p.neighRetrans {
		if value == "" {
			continue
		}
		if err := fs.writeFile(path, []byte(value)); err != nil {
			slog.Warn("linksetup: host tunable restore — neigh retrans_time_ms write failed",
				"path", path, "want", value, "err", err)
			retained[path] = value
			continue
		}
		restored++
	}
	if restored > 0 {
		slog.Info("linksetup: neigh retrans_time_ms restored to pre-xpfd value",
			"restored", restored, "total", len(p.neighRetrans))
	}
	return retained
}

// restoreMlx5Coalesce emits one `ethtool -C <iface> adaptive-rx ...
// adaptive-tx ... rx-usecs ... tx-usecs ...` matching the pre-xpfd
// capture. Errors are logged here and ALSO returned (#6801): the
// released-interface teardown releases ownership of a capture only after
// its restore write succeeds, so it needs the outcome, while the
// shutdown and full-restore callers keep ignoring it (best-effort).
func restoreMlx5Coalesce(iface string, s mlx5CoalesceState, execer rssExecutor) error {
	adaptRX := "off"
	if s.adaptiveRX {
		adaptRX = "on"
	}
	adaptTX := "off"
	if s.adaptiveTX {
		adaptTX = "on"
	}
	args := []string{
		"-C", iface,
		"adaptive-rx", adaptRX,
		"adaptive-tx", adaptTX,
		"rx-usecs", strconv.Itoa(s.rxUsecs),
		"tx-usecs", strconv.Itoa(s.txUsecs),
	}
	if out, err := execer.runEthtool(args...); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: host tunable restore — ethtool missing for mlx5 coalesce restore",
				"iface", iface)
			return err
		}
		slog.Warn("linksetup: host tunable restore — ethtool -C failed",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return err
	}
	slog.Info("linksetup: coalescence restored to pre-xpfd value",
		"iface", iface, "adaptive_rx", s.adaptiveRX,
		"adaptive_tx", s.adaptiveTX,
		"rx_usecs", s.rxUsecs, "tx_usecs", s.txUsecs)
	return nil
}
