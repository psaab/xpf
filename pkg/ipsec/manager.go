// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"

	"github.com/psaab/xpf/pkg/termsafe"
)

// swanctlTimeout bounds every swanctl shell-out. reload() runs on the
// config-apply path under applyConfigLocked's applySem (daemon_apply.go
// d.ipsec.Apply), so a hung swanctl (wedged charon, stuck vici socket)
// would otherwise block every commit indefinitely. The operator-RPC
// sites (--terminate / --initiate / --list-sas) hang the gRPC/CLI show
// and request paths the same way. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const swanctlTimeout = 15 * time.Second

// runSwanctlSplit runs `swanctl <args...>` under swanctlTimeout and returns
// stdout and stderr SEPARATELY (#9068).
//
// It exists because one parser was fed by two different exec channels.
// `GetSAStatus` (ike.go) has always used a stdout-only buffer, with the comment
// "the parser needs stdout alone"; `liveConnNames` routed through
// CombinedOutput on the security-critical TEARDOWN path, and its in-place
// justification — "parseSAOutput ignores any unrecognized stderr lines
// CombinedOutput may fold in" — was asserted, never tested.
//
// The assertion is true for WHOLE stderr lines and false in the one direction
// that matters. An executed tolerance matrix on parseSAOutput: a whole stderr
// line before the IKE header preserves the name; a stderr line containing `": #"`
// yields a spurious extra name (harmless — it is not in removedSet); CRLF is
// tolerated; and a MID-LINE SPLICE into the IKE header LOSES the real name
// (`vpn-corp` becomes `vpn-cowarning`).
//
// A lost name is a fail-open, not a cosmetic error: terminateRemovedConns
// iterates `for name := range live`, so a removed connection ABSENT from `live`
// is neither terminated nor entered into pendingTerminate — and prevConnNames
// has already advanced past it, so the debt record that #6542 exists to keep is
// never created. A deleted VPN's SA keeps forwarding under an unloaded
// configuration with no retry.
//
// Whether swanctl can actually splice mid-line on a successful listing is NOT
// established (stdout to a pipe is block-buffered, stderr unbuffered, so it
// needs a large SA listing plus a concurrent stderr write). This removes the
// question rather than answering it: giving the parser the same stdout-only
// channel its sibling already uses costs less than the experiment and does not
// depend on its outcome.
func runSwanctlSplit(args ...string) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), swanctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "swanctl", args...)
	// Buffer-backed Stdout/Stderr are pipe-fed by the runtime, so the
	// post-SIGKILL drain window applies here too.
	cmd.WaitDelay = 5 * time.Second
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// runSwanctl runs `swanctl <args...>` under swanctlTimeout and returns
// CombinedOutput, preserving the historical error-message shape at the
// call sites.
//
// #9068: this stays the channel for the NON-PARSED calls (`--load-all`,
// `--terminate --ike`), whose only consumer is an error message — folding
// stderr in is what makes those diagnostics useful. Only the call whose output
// is PARSED moved to runSwanctlSplit.
func runSwanctl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), swanctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "swanctl", args...)
	// WaitDelay caps the post-SIGKILL pipe-drain window (a charon child
	// inheriting the pipe could otherwise hold CombinedOutput open).
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

const (
	// DefaultSwanctlDir is where swanctl reads conf.d snippets.
	DefaultSwanctlDir = "/etc/swanctl/conf.d"
	// BPFRXConfFile is the config file xpf manages.
	BPFRXConfFile = "xpf.conf"
)

// Manager handles strongSwan config generation and SA queries.
type Manager struct {
	configDir  string
	configPath string

	// mu guards prevConnNames across concurrent Apply callers (the ordered
	// commit path and the DHCP-rebind re-render both call Apply).
	mu sync.Mutex
	// prevConnNames is the set of swanctl connection names (sanitized VPN
	// names) written by the most recent Apply. Diffing it against the new
	// config's connection set yields the connections an operator DELETED, so
	// their live SAs can be torn down (#3941). nil until the first Apply.
	prevConnNames map[string]bool

	// pendingTerminate carries the TEARDOWN DEBT of connections whose
	// `swanctl --terminate` failed on a previous apply (#6542).
	//
	// prevConnNames advances to the newly-loaded set as soon as the reload
	// succeeds, so a name that departed the loaded set is gone from it
	// forever after that single apply. Before #6542 a failed terminate was
	// logged and dropped on the floor: the departed connection's live child
	// SA kept forwarding under stale selectors/credentials and no later
	// reconcile ever retried the teardown, because the only record of what
	// departed had already been overwritten. Carrying the failed subset here
	// re-derives it into the NEXT apply's removed set, so the teardown is
	// retried until it succeeds or the SA is observed gone.
	//
	// A debt entry is NEVER a licence to terminate a loaded connection:
	// promoteConnNames folds the debt into `removed` only for names absent
	// from the newly-loaded set, so an operator re-adding the VPN discharges
	// the debt instead of tearing the restored tunnel down.
	pendingTerminate map[string]bool

	// swanctl is the exec seam for shelling out to swanctl. Nil in
	// production and directly-constructed test Managers; sc() falls back to
	// the package-level runSwanctl. Tests that must observe/intercept the
	// swanctl invocations (e.g. the removed-connection terminate in #3941)
	// set this to a recording double.
	swanctl func(args ...string) ([]byte, error)

	// swanctlSplit is the stdout/stderr-separated exec seam (#9068), used by
	// the one call whose output is PARSED. Nil in production and in every
	// pre-#9068 test; scSplit then falls back to `swanctl` (treating its
	// output as stdout) or to runSwanctlSplit.
	swanctlSplit func(args ...string) (stdout, stderr []byte, err error)
}

// scSplit is the STDOUT-ONLY exec used by the parsed call (#9068).
//
// It falls back to the combined `swanctl` seam when only that one is set, and
// treats the double's output as STDOUT — which is what a double returns: canned
// listing text with no stderr to fold. That keeps every existing test double
// working unchanged while production stops mixing the two streams.
func (m *Manager) scSplit(args ...string) (stdout, stderr []byte, err error) {
	if m.swanctlSplit != nil {
		return m.swanctlSplit(args...)
	}
	if m.swanctl != nil {
		out, err := m.swanctl(args...)
		return out, nil, err
	}
	return runSwanctlSplit(args...)
}

// sc returns the swanctl exec function, defaulting to the package-level
// runSwanctl when the seam is unset. This keeps a zero-value / directly
// constructed Manager working while letting tests inject a double.
func (m *Manager) sc(args ...string) ([]byte, error) {
	if m.swanctl != nil {
		return m.swanctl(args...)
	}
	return runSwanctl(args...)
}

// New creates a new IPsec manager.
func New() *Manager {
	return NewWithConfigDir(DefaultSwanctlDir)
}

// NewWithConfigDir creates an IPsec manager that writes its swanctl
// snippet under dir instead of the default /etc/swanctl/conf.d. It lets
// callers (and tests that must not touch the real swanctl tree) redirect
// the generated config to an arbitrary directory; reload() still shells
// out to the system swanctl.
func NewWithConfigDir(dir string) *Manager {
	return &Manager{
		configDir:  dir,
		configPath: filepath.Join(dir, BPFRXConfFile),
	}
}

// Apply generates swanctl config and reloads strongSwan.
//
// swanctl --load-all only UNLOADS the config of a connection that is no
// longer present in the rendered config; it does NOT terminate that
// connection's already-established IKE/child SAs, so a dropped VPN keeps
// forwarding until rekey/lifetime expiry (#3941). Apply therefore diffs the
// previous LOADED connection set against the set renderConfig actually
// emitted and, after the reload has unloaded the departed connections,
// actively terminates their live SAs (terminateRemovedConns).
//
// The diff keys off the RENDERED set, not the raw VPN map keys (#5494). A VPN
// that is still present in the config but became UNRENDERABLE on the tolerant
// load / peer-sync path — an unresolvable gateway reference (#2074), a broken
// ike-policy chain (#2270), or a `protocol ah` proposal with no ESP render
// path (#4298) — is OMITTED from the render, so its connection is neither
// loaded nor validated by swanctl. Continuing to forward under that
// connection's now-unloaded (stale) selectors/credentials is a security
// fail-open, so such a VPN is treated as a removal and its child SA is torn
// down. This is the fail-closed invariant: after a SUCCESSFUL apply, every
// forwarding child SA must correspond to a connection that was actually
// rendered and loaded, or be actively terminated.
func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
	return m.ApplyNotifyLoaded(ipsecCfg, nil)
}

// ApplyNotifyLoaded is Apply, and additionally calls loaded (when non-nil) at the
// moment strongSwan has LOADED ipsecCfg: immediately after the newly loaded
// connection set is promoted, and BEFORE departed connections are torn down (#9511).
//
// It is never called when the render, write, reload or clear fails, because the
// previous generation stays loaded. It IS called when the apply then returns
// teardown debt (#6542), because that error is returned after a successful reload.
// Calling it before the teardown matters because that teardown lists and terminates
// SAs through swanctl and can take tens of seconds, and during that time the new
// generation is already what charon runs. loaded runs on the caller's goroutine with
// no Manager lock held.
func (m *Manager) ApplyNotifyLoaded(ipsecCfg *config.IPsecConfig, loaded func()) error {
	return m.ApplyWithHooks(ipsecCfg, ApplyHooks{Loaded: loaded})
}

// ApplyHooks are the callbacks ApplyWithHooks runs at the two points where the
// swanctl config on disk and the generation charon runs can diverge.
type ApplyHooks struct {
	// Written runs once the on-disk swanctl config has CHANGED (the new file is
	// written, or the file is removed for an empty config) and BEFORE the reload.
	// From that moment until a successful reload, charon runs a generation that
	// is not the file on disk, and its own next start or reload will load the file
	// (#9511 stopgap). It does not run when render or write fails, because the
	// previous file is still on disk.
	Written func()
	// Loaded runs once strongSwan has LOADED the config: right after the newly
	// loaded connection set is promoted, before departed connections are torn down.
	// It does not run on a failed reload. It does run when the apply then returns
	// teardown debt (#6542).
	Loaded func()
}

// ApplyWithHooks is Apply with the ApplyHooks callbacks. A successful apply runs
// Written, then Loaded. A write followed by a failed reload runs only Written. A
// render or write failure runs neither. Both run on the caller's goroutine with no
// Manager lock held.
func (m *Manager) ApplyWithHooks(ipsecCfg *config.IPsecConfig, hooks ApplyHooks) error {
	// loadedNames is the set of connections swanctl actually loaded on this
	// apply. For the render path it is renderConfig's exact emitted set; for
	// the empty-config clear path nothing is loaded, so it stays nil.
	var loadedNames map[string]bool
	var applyErr error
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		applyErr = m.clearConfig(hooks.Written)
	} else {
		loadedNames, applyErr = m.applyConfig(ipsecCfg, hooks.Written)
	}

	// #4898: state promotion and SA teardown are gated on reload SUCCESS. On a
	// failed reload strongSwan keeps the PREVIOUS config loaded and effective, so
	// prevConnNames must NOT advance and the removed connections' live SAs must
	// NOT be terminated — they may still be the effective policy. Leaving
	// prevConnNames unchanged lets the next successful Apply/Clear recompute the
	// diff and retry the teardown; advancing it here (the old ordering) would
	// forget which connections are still loaded and disrupt a still-effective
	// tunnel while reporting success. A render-side hard error (a non-skip
	// failure, e.g. an unknown auth method) surfaces here the same way and
	// tears nothing down.
	if applyErr != nil {
		return applyErr
	}

	// Reload succeeded: atomically advance prevConnNames to the set that was
	// actually loaded and tear down the live SAs of the connections that
	// departed the loaded set — whether the operator DELETED them or they fell
	// out of the render as unrenderable (#5494). Their config is now unloaded,
	// so a straggler SA cannot be re-initiated from a still-loaded connection
	// while we tear it down. Terminate is idempotent: a departed VPN with no
	// active SA is a clean no-op (no --terminate is issued because it never
	// shows up in --list-sas).
	//
	// #6542: a terminate that FAILS is not swallowed. promoteConnNames has
	// already advanced prevConnNames past the departed names, so a dropped
	// failure would lose the teardown debt permanently and leave the stale SA
	// forwarding while Apply reported success. The failed subset is recorded
	// as debt (retried on the next apply) AND surfaced as an Apply error, so
	// the commit result shows the degraded IPsec state — the same posture
	// #4433 established for a failed reload.
	removed := m.promoteConnNames(loadedNames)
	if hooks.Loaded != nil {
		hooks.Loaded()
	}
	failed := m.terminateRemovedConns(removed)
	return m.recordTerminateDebt(failed)
}

// Clear removes the xpf config and reloads strongSwan, terminating the live
// SAs of every previously-applied connection.
func (m *Manager) Clear() error {
	if err := m.clearConfig(nil); err != nil {
		// #4898: the reload failed — the old config is still the effective
		// loaded config. Preserve prevConnNames and skip termination so a later
		// Clear retries the teardown rather than reporting a false success.
		return err
	}
	removed := m.promoteConnNames(nil)
	failed := m.terminateRemovedConns(removed)
	return m.recordTerminateDebt(failed)
}

// applyConfig renders + atomically writes the swanctl snippet and reloads.
// On success it returns the exact set of connection names renderConfig
// emitted into the loaded config (#5494) — the authoritative "what is loaded"
// set Apply diffs against prevConnNames to decide which stale SAs to tear
// down. On any error (render hard error, write failure, reload failure) it
// returns a nil set so Apply's error path leaves prevConnNames untouched.
func (m *Manager) applyConfig(ipsecCfg *config.IPsecConfig, written func()) (map[string]bool, error) {
	cfg, rendered, err := m.renderConfig(ipsecCfg)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	// AtomicGeneratedConfig (#1894): regenerated on every apply — a
	// torn file must never reach the strongSwan parser, but fsync is
	// deliberately skipped on this hot apply path.
	if err := fsatomic.WriteFileAtomic(m.configPath, []byte(cfg), 0600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	slog.Info("swanctl config written", "path", m.configPath)

	// #9511 stopgap: the NEW file is on disk from here on. If the reload below
	// fails, charon keeps the old generation, but its own next start or reload
	// (strongswan.service ExecStartPost/ExecReload `swanctl --load-all`) loads
	// this file. Tell the caller before reloading, so it stops trusting its
	// record of the loaded generation.
	if written != nil {
		written()
	}
	if err := m.reload(); err != nil {
		slog.Warn("swanctl reload failed", "err", err)
		return nil, err
	}

	return rendered, nil
}

// clearConfig removes the xpf snippet and reloads strongSwan.
//
// #4898: the reload error is PROPAGATED, not swallowed. The empty-clear branch
// (Apply(nil)/Clear deleting the last VPN) previously did `_ = m.reload()` and
// returned nil, reporting success even when `swanctl --load-all` failed and
// charon kept the old connection loaded — a decommissioned/compromised peer
// would stay authorized and could re-initiate. This now mirrors applyConfig,
// which already propagates reload errors (the #4433 contract).
func (m *Manager) clearConfig(written func()) error {
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	// #9511 stopgap: the on-disk config no longer matches what charon runs; a
	// charon restart or reload now loads no xpf config at all.
	if written != nil {
		written()
	}
	return m.reload()
}

func (m *Manager) reload() error {
	output, err := m.sc("--load-all")
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %w: %s", err, string(output))
	}
	slog.Info("swanctl config reloaded")
	return nil
}

// promoteConnNames records newNames — the set of connections that were
// actually RENDERED+LOADED on this apply — as the current loaded connection
// set and returns the connections that were loaded before but are gone now.
// A prior connection is "gone" if the operator DELETED its VPN OR the VPN is
// still configured but dropped out of the render as unrenderable (#5494):
// either way strongSwan is no longer enforcing that connection, so a live
// child SA still forwarding under its stale selectors/credentials is a
// fail-open and must be torn down. The diff keys off the RENDERED set, not
// the raw VPN map keys, precisely so an unrenderable-but-still-configured VPN
// is caught — the security-over-availability posture this project chose for
// an IPsec appliance (an unrenderable VPN is already non-functional for
// rekey/new-SA, so keeping its stale SA buys no real availability).
//
// #4898: this is called ONLY after a successful reload, so prevConnNames always
// reflects the last config strongSwan actually loaded — never a config whose
// reload failed. The name/removed diff and the prevConnNames advance stay
// atomic under mu.
//
// #6542: the returned set is the union of the departed-this-apply names AND
// any outstanding teardown debt (pendingTerminate) — connections whose
// terminate failed on an earlier apply and whose stale SA may therefore still
// be forwarding. Both halves are filtered by the newly-loaded set, so a name
// that came back (operator re-added the VPN, or it became renderable again)
// is never torn down. The debt is cleared here and re-derived from THIS
// apply's teardown outcome by recordTerminateDebt.
func (m *Manager) promoteConnNames(newNames map[string]bool) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed []string
	seen := make(map[string]bool, len(m.prevConnNames))
	for name := range m.prevConnNames {
		if !newNames[name] {
			removed = append(removed, name)
			seen[name] = true
		}
	}
	for name := range m.pendingTerminate {
		if !newNames[name] && !seen[name] {
			removed = append(removed, name)
		}
	}
	m.prevConnNames = newNames
	m.pendingTerminate = nil
	return removed
}

// recordTerminateDebt records the connections whose teardown failed on this
// apply so the next reconcile retries them, and returns the error Apply/Clear
// reports to the caller. An empty failed set discharges cleanly (nil error).
//
// The debt is UNIONED into whatever pendingTerminate currently holds rather
// than replacing it: promoteConnNames releases mu before the terminates run,
// so a concurrent Apply (the ordered commit path and the DHCP-rebind
// re-render both call Apply) could otherwise clobber the other's debt. A
// stale union member is harmless — promoteConnNames filters the debt by the
// loaded set before any terminate is issued.
func (m *Manager) recordTerminateDebt(failed []string) error {
	if len(failed) == 0 {
		return nil
	}
	m.mu.Lock()
	if m.pendingTerminate == nil {
		m.pendingTerminate = make(map[string]bool, len(failed))
	}
	for _, name := range failed {
		m.pendingTerminate[name] = true
	}
	m.mu.Unlock()
	sort.Strings(failed)
	return fmt.Errorf("terminate stale IPsec SAs for removed connection(s) "+
		"%s: teardown retried on next commit", strings.Join(failed, ", "))
}

// terminateRemovedConns tears down the live IKE/child SAs of the deleted
// connections and returns the subset whose terminate FAILED. It queries live
// SAs and only terminates a removed connection that actually has an SA, so a
// deletion of a VPN that was never up issues no swanctl call (#3941).
//
// #6542: the failed subset is returned rather than only logged. A departed
// connection that is observed LIVE and whose terminate errors is still
// forwarding under an unloaded configuration — the exact fail-open this
// teardown exists to close — so it becomes teardown debt the caller retries.
// A removed connection that is NOT live is a clean no-op and owes nothing,
// which is what lets the debt discharge once the SA is actually gone instead
// of failing every subsequent commit forever.
func (m *Manager) terminateRemovedConns(removed []string) []string {
	if len(removed) == 0 {
		return nil
	}

	removedSet := make(map[string]bool, len(removed))
	for _, name := range removed {
		removedSet[name] = true
	}

	var failed []string

	live, err := m.liveConnNames()
	if err != nil {
		// Could not enumerate live SAs (charon down / vici error). Fall back
		// to an unconditional, idempotent terminate of each removed name so a
		// straggler SA is not left forwarding; swanctl no-ops when nothing
		// matches.
		//
		// #6542: a failure here is ambiguous — it may be a genuine teardown
		// failure or merely "no matching SA" for a connection that was never
		// up. It is still carried as debt: the NEXT apply enumerates live SAs
		// and discharges the debt silently if the name is not live, so an
		// ambiguous failure self-clears in one reconcile instead of latching.
		slog.Warn("could not list SAs before terminating removed IPsec "+
			"connections; terminating unconditionally", "err", err)
		for _, name := range removed {
			if !m.terminateIKE(name) {
				failed = append(failed, name)
			}
		}
		return failed
	}

	for name := range live {
		if removedSet[name] && !m.terminateIKE(name) {
			failed = append(failed, name)
		}
	}
	return failed
}

// terminateIKE issues `swanctl --terminate --ike <name>` for a single
// connection and reports whether it succeeded. The error is logged here and
// converted to a false return so the caller can carry the teardown debt
// (#6542); it is deliberately not wrapped and propagated, because a single
// failure must not abort the teardown of the OTHER removed connections.
func (m *Manager) terminateIKE(name string) bool {
	if out, err := m.sc("--terminate", "--ike", name); err != nil {
		slog.Warn("swanctl terminate for deleted IPsec VPN failed "+
			"(SA may already be down); teardown retried on next commit",
			"ike", name, "err", err, "output", string(out))
		return false
	}
	slog.Info("terminated live SAs for deleted IPsec VPN", "ike", name)
	return true
}

// liveConnNames returns the set of connection (IKE SA) names strongSwan
// currently reports via --list-sas. It routes through the swanctl exec seam
// (unlike GetSAStatus, which uses stdout only); parseSAOutput ignores any
// unrecognized stderr lines CombinedOutput may fold in.
func (m *Manager) liveConnNames() (map[string]bool, error) {
	// #9068: STDOUT ONLY. parseSAOutput must never see stderr — a mid-line
	// splice into an IKE header silently renames the connection, and a name
	// this function fails to report is one terminateRemovedConns cannot tear
	// down and cannot record as debt.
	out, errOut, err := m.scSplit("--list-sas")
	if err != nil {
		// stderr alone in the diagnostic, matching GetSAStatus: it is where the
		// failure is described, and stdout on a failed listing is noise.
		return nil, fmt.Errorf("swanctl --list-sas: %w: %s", err, termsafe.SanitizeForDisplay(string(errOut)))
	}
	names := make(map[string]bool)
	for _, sa := range parseSAOutput(string(out)) {
		conn := sa.ConnectionName
		if conn == "" {
			conn = sa.Name
		}
		if conn != "" {
			names[conn] = true
		}
	}
	return names, nil
}
