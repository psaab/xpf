// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
// iterates `for name := range live`, so an affected connection ABSENT from
// `live` is neither terminated nor entered into teardown debt — and the SA
// keeps forwarding under stale settings with no retry.
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

	// mu guards the last successfully loaded connection set across concurrent
	// Apply callers (the ordered commit path and DHCP-rebind re-render both call
	// Apply).
	mu sync.Mutex
	// prevConnNames and prevConnHashes describe the rendered connections from
	// the most recent successful Apply. Departed names and same-name security
	// content changes both require stale live SAs to be torn down.
	prevConnNames  map[string]bool
	prevConnHashes map[string]string

	// pendingTerminate carries teardown debt for connections no longer loaded.
	// pendingChanged carries debt for same-name content changes: unlike removal
	// debt, it must still be retried while that name remains loaded.
	pendingTerminate map[string]bool
	pendingChanged   map[string]bool

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

	// statePath persists loaded names, rendered fingerprints, and teardown debt
	// across xpfd restarts (#9687/#10878, conn_state_9687.go). Empty disables
	// persistence, which is what NewWithConfigDir and directly-constructed
	// Managers get; New sets DefaultConnStatePath.
	statePath string
	// stateSeeded records that the persisted state was folded in, which
	// happens once, at this Manager's first promotion.
	stateSeeded bool
	// inflight counts affected connections a promotion handed to
	// terminateRemovedConns that have not settled. They are persisted as debt.
	inflight map[string]int
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
	m := NewWithConfigDir(DefaultSwanctlDir)
	m.statePath = DefaultConnStatePath // #9687
	return m
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
// swanctl --load-all unloads a connection's config when it is removed but does
// not terminate its established IKE/child SAs (#3941). It also leaves SAs
// established when a connection survives under changed credentials, proposals,
// selectors, endpoints, identities, or lifetimes (#10878). Apply therefore
// compares the rendered security-effective content for each loaded connection
// and, after a successful reload, terminates live SAs for removed or changed
// connections. Cosmetic fields not emitted by the renderer do not cause teardown.
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
// forwarding child SA must correspond to the rendered security-effective
// connection, or be actively terminated.
func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
	return m.ApplyNotifyLoaded(ipsecCfg, nil)
}

// ApplyNotifyLoaded is Apply, and additionally calls loaded (when non-nil) at the
// moment strongSwan has LOADED ipsecCfg: immediately after the newly loaded
// connection set is promoted, and BEFORE removed or changed connections are
// torn down (#9511/#10878).
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
	// From that moment until the reload succeeds or recovery completes
	// (#10712/#14589), charon runs a generation that is not the file on
	// disk. A total failure restores the prior file; a partial load is
	// reconciled to the set charon actually loaded (see applyConfig), so
	// once the apply returns an error the disk again matches what charon
	// runs — but Written has already fired and stays
	// fired (conservative: the caller re-validates rather than trusting a record
	// that may briefly have described the wrong generation). It does not run when
	// render or write fails, because the previous file is still on disk.
	Written func()
	// Loaded runs once strongSwan has LOADED the config: right after the newly
	// loaded connection set is promoted, before removed or changed connections
	// are torn down and changed live SAs are reinitiated.
	// It does not run on a failed reload. It does run when the apply then returns
	// teardown debt (#6542).
	Loaded func()
}

// ApplyWithHooks is ApplyGeneration naming no generation (UnknownGeneration).
func (m *Manager) ApplyWithHooks(ipsecCfg *config.IPsecConfig, hooks ApplyHooks) error {
	return m.ApplyGeneration(ipsecCfg, UnknownGeneration, hooks)
}

// ApplyGeneration is Apply with the ApplyHooks callbacks, and the file it writes names
// generation inside charon through the inert marker pool (#9641, generation.go).
// generation is a config digest the caller can look up later (the daemon passes the
// configstore digest of the active config it applies); anything else is written as
// UnknownGeneration. Only a rendered config carries the marker: the empty-config clear
// path removes the file, so charon then lists no marker at all.
//
// A successful apply runs Written, then Loaded. A write followed by a total reload
// failure runs only Written, and the prior file is restored (#10712); a partial
// load runs only Written and is reconciled to charon's loaded set (#14589), so
// the disk again matches the generation charon still runs in both cases. A
// render or write failure runs neither.
// Both run on the caller's goroutine with no Manager lock held.
func (m *Manager) ApplyGeneration(ipsecCfg *config.IPsecConfig, generation string, hooks ApplyHooks) error {
	// loadedNames and loadedHashes describe the connections swanctl actually
	// loaded on this apply. For the render path they come from renderConfig;
	// for the empty-config clear path nothing is loaded, so both stay nil.
	var loadedNames map[string]bool
	var loadedHashes map[string]string
	var applyErr error
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		applyErr = m.clearConfig(hooks.Written)
	} else {
		loadedNames, loadedHashes, applyErr = m.applyConfig(ipsecCfg, generation, hooks.Written)
	}

	// #4898: state promotion and SA teardown are gated on reload SUCCESS. On a
	// total reload failure strongSwan keeps the PREVIOUS config loaded and
	// effective, so prevConnNames and prevConnHashes must NOT advance and stale
	// connections' live SAs must NOT be terminated — they may still be the
	// effective policy. Leaving this state unchanged lets the next successful
	// Apply/Clear recompute the diff and retry the teardown. The #14589
	// partial exception (recovered set promoted below) is the one case where
	// charon demonstrably no longer runs the previous set.
	if applyErr != nil {
		var pae *partialApplyError
		if errors.As(applyErr, &pae) {
			// #14589: a partial load was recovered so disk == charon.
			// Promote the recovered set (tearing down SAs that departed
			// it, e.g. the deleted b whose config charon unloaded),
			// do NOT fire Loaded (the candidate generation did not
			// load), and still return the partial error.
			var removed []string
			if pae.clear {
				removed, _ = m.promoteConnNames(map[string]bool{}, map[string]string{})
			} else {
				removed, _ = m.promoteConnNames(pae.names, pae.hashes)
			}
			_, failed := m.terminateRemovedConns(removed)
			termErr := m.recordTerminateDebt(removed, failed)
			return errors.Join(applyErr, termErr)
		}
		return applyErr
	}

	// Reload succeeded: advance the loaded connection content and tear down the
	// live SAs of connections that departed or changed security-effective
	// settings. A changed live connection is then re-initiated with its new
	// configuration, forcing the peer to authenticate again.
	removed, changed := m.promoteConnNames(loadedNames, loadedHashes)
	if hooks.Loaded != nil {
		hooks.Loaded()
	}
	terminated, failed := m.terminateRemovedConns(removed)
	terminateErr := m.recordTerminateDebt(removed, failed)
	initiateErr := m.reinitiateChangedConnections(ipsecCfg, changed, terminated)
	return errors.Join(terminateErr, initiateErr)
}

// Clear removes the xpf config and reloads strongSwan, terminating the live
// SAs of every previously-applied connection.
func (m *Manager) Clear() error {
	if err := m.clearConfig(nil); err != nil {
		var pae *partialApplyError
		if errors.As(err, &pae) && pae.clear {
			removed, _ := m.promoteConnNames(pae.names, pae.hashes)
			_, failed := m.terminateRemovedConns(removed)
			return errors.Join(err, m.recordTerminateDebt(removed, failed))
		}
		// #4898: the reload failed — the old config is still the effective
		// loaded config. Preserve the loaded names and hashes and skip termination
		// so a later Clear retries the teardown rather than reporting false success.
		return err
	}
	removed, _ := m.promoteConnNames(nil, nil)
	_, failed := m.terminateRemovedConns(removed)
	return m.recordTerminateDebt(removed, failed)
}

// applyConfig renders + atomically writes the swanctl snippet and reloads.
// On success it returns the exact set of connection names renderConfig
// emitted into the loaded config and their rendered-content hashes. Apply
// compares both against the last successfully loaded state to detect removed
// and same-name changed connections.
//
// #9641: the written file ends with the generation marker pool naming generation. It
// is appended to the render rather than rendered inside it, so every other consumer of
// renderConfig (the SA name index, ExpectedLoadedConns) sees exactly
// the connections and secrets it always did.
func (m *Manager) applyConfig(ipsecCfg *config.IPsecConfig, generation string, written func()) (map[string]bool, map[string]string, error) {
	cfg, rendered, err := m.renderConfig(ipsecCfg)
	if err != nil {
		return nil, nil, err
	}
	hashes, err := renderedConnectionHashes(cfg, rendered)
	if err != nil {
		return nil, nil, err
	}
	cfg += "\n" + renderGenerationMarker(generation)

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("create config dir: %w", err)
	}

	// #10712: snapshot the prior file BEFORE replacing it. reload() runs
	// `swanctl --load-all`, which reads this same live path, so the NEW file
	// must be on disk when the reload runs — but after a total reload failure
	// charon keeps the OLD generation while the NEW file would stay on disk, and
	// charon's own next start or reload (strongswan.service ExecStartPost/
	// ExecReload `swanctl --load-all`) would then load a config that was never
	// successfully loaded. The snapshot lets the failure paths below restore
	// the prior bytes (total failure, #10712) or reconcile to charon's loaded
	// subset (partial load, #14589), so disk again matches what charon runs.
	prior, priorErr := os.ReadFile(m.configPath)
	havePrior := true
	if priorErr != nil {
		if !os.IsNotExist(priorErr) {
			return nil, nil, fmt.Errorf("read prior config: %w", priorErr)
		}
		havePrior = false
	}

	// AtomicGeneratedConfig (#1894): regenerated on every apply — a
	// torn file must never reach the strongSwan parser, but fsync is
	// deliberately skipped on this hot apply path.
	if err := fsatomic.WriteFileAtomic(m.configPath, []byte(cfg), 0600); err != nil {
		return nil, nil, fmt.Errorf("write config: %w", err)
	}

	slog.Info("swanctl config written", "path", m.configPath)

	// #9511: the NEW file is on disk from here until the reload below succeeds
	// or the prior file is restored. Tell the caller before reloading, so it
	// stops trusting its record of the loaded generation. On a reload failure
	// the record stays cleared (conservative — attribution re-asks charon,
	// #9641) even though the restore below returns the disk to the generation
	// charon still runs.
	if written != nil {
		written()
	}
	if _, err := m.reloadResult(); err != nil {
		var perr *partialReloadError
		if errors.As(err, &perr) {
			loadedNames, loadedHashes, rerr := m.recoverPartialLoad14589(ipsecCfg, generation, rendered, hashes, prior, havePrior, perr)
			if rerr != nil {
				return nil, nil, rerr
			}
			// Recovered: charon, disk and the returned set agree. Still
			// report the partial so the commit fails and the operator
			// fixes the refused VPN; the recovered set travels on the
			// partialApplyError for ApplyGeneration to promote.
			return loadedNames, loadedHashes, &partialApplyError{err: err, names: loadedNames, hashes: loadedHashes}
		}
		slog.Warn("swanctl reload failed", "err", err)
		if restoreErr := m.restoreConfigAfterFailedReload(prior, havePrior); restoreErr != nil {
			return nil, nil, errors.Join(err, restoreErr)
		}
		return nil, nil, err
	}

	return rendered, hashes, nil
}

// partialApplyError is returned by applyConfig (and clearConfig, with a
// nil set meaning empty) when a partial load was recovered to a
// consistent state. ApplyGeneration promotes names/hashes (when
// non-nil) and still returns the underlying partial error.
type partialApplyError struct {
	err    error
	names  map[string]bool
	hashes map[string]string
	clear  bool
}

func (e *partialApplyError) Error() string { return e.err.Error() }
func (e *partialApplyError) Unwrap() error { return e.err }

// recoverPartialLoad14589 reconciles disk + charon after a partial
// --load-all (#14589). It asks charon what it actually loaded. If that
// set can be filed (subset of candidate or of prior), it writes that
// set's file and re-loads it (rollback re-load for a prior set, subset
// file for a candidate subset). If charon cannot be asked or the
// verification reload does not converge, it falls back to a true
// rollback: restore the prior file and re-load it. The returned set
// always describes what charon runs and what is on disk on success.
func (m *Manager) recoverPartialLoad14589(ipsecCfg *config.IPsecConfig, generation string, rendered map[string]bool, hashes map[string]string, prior []byte, havePrior bool, perr *partialReloadError) (map[string]bool, map[string]string, error) {
	slog.Warn("swanctl partial load; reconciling disk with charon", "err", perr)
	loaded, lerr := m.ListLoadedConns()
	if lerr != nil {
		// Cannot discover the subset: true rollback.
		if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
			return nil, nil, errors.Join(perr, rbErr)
		}
		names, hs := m.priorSet14589(prior, havePrior)
		return names, hs, nil
	}
	loadedSet := make(map[string]bool, len(loaded))
	for n := range loaded {
		loadedSet[n] = true
	}
	// Candidate subset (includes empty set when nothing loaded but
	// other loaders failed, and the full set cannot happen here).
	if isSubset14589(loadedSet, rendered) {
		if len(loadedSet) == len(rendered) {
			// Summary lied / raced to full: candidate file already correct.
			return rendered, hashes, nil
		}
		text, _, ferr := m.renderSubsetFile14589(ipsecCfg, generation, loadedSet)
		if ferr != nil {
			if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
				return nil, nil, errors.Join(perr, rbErr)
			}
			names, phs := m.priorSet14589(prior, havePrior)
			return names, phs, nil
		}
		if werr := fsatomic.WriteFileAtomic(m.configPath, []byte(text), 0600); werr != nil {
			return nil, nil, errors.Join(perr, fmt.Errorf("write reconciled config after partial load: %w", werr))
		}
		if _, rerr := m.reloadResult(); rerr != nil {
			// Verification reload failed (possibly another partial):
			// fall back to a true rollback rather than leaving the
			// subset file unverified.
			if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
				return nil, nil, errors.Join(perr, rerr, rbErr)
			}
			names, phs := m.priorSet14589(prior, havePrior)
			return names, phs, nil
		}
		// Confirm charon still reports the same set.
		if confirm, cerr := m.ListLoadedConns(); cerr == nil {
			cs := make(map[string]bool, len(confirm))
			for n := range confirm {
				cs[n] = true
			}
			if !sameBoolSet14589(cs, loadedSet) {
				if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
					return nil, nil, errors.Join(perr, rbErr)
				}
				names, phs := m.priorSet14589(prior, havePrior)
				return names, phs, nil
			}
		}
		subHashes := make(map[string]string, len(loadedSet))
		for n := range loadedSet {
			subHashes[n] = hashes[n]
		}
		return loadedSet, subHashes, nil
	}
	// Loaded set is not a candidate subset: it may be exactly the prior
	// set (secret/pool-only partial, connections untouched).
	priorNames, priorHashes := m.priorSet14589(prior, havePrior)
	if sameBoolSet14589(loadedSet, priorNames) {
		if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
			return nil, nil, errors.Join(perr, rbErr)
		}
		return priorNames, priorHashes, nil
	}
	// Hybrid/unknown set charon runs that neither file describes.
	// Safest consistent state reachable is a true rollback.
	if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
		return nil, nil, errors.Join(perr, rbErr)
	}
	return priorNames, priorHashes, nil
}

// rollbackReload14589 restores the prior file (or removes it) and
// re-loads it, so charon converges to the prior generation. A failed
// re-load is joined by the caller; disk still names the prior set,
// which is the best available consistent target and what the next
// charon restart will load.
func (m *Manager) rollbackReload14589(prior []byte, havePrior bool) error {
	if err := m.restoreConfigAfterFailedReload(prior, havePrior); err != nil {
		return err
	}
	if _, err := m.reloadResult(); err != nil {
		return fmt.Errorf("rollback reload after partial load: %w", err)
	}
	return nil
}

// priorSet14589 derives the connection names/hashes the prior file
// describes. Names are parsed from the file; hashes are recomputed by
// matching against the current Manager state when the name was
// previously loaded (the common case) — otherwise the hash is left
// absent so promoteConnNames adopts the baseline without forcing a
// teardown (the #10878 legacy-adoption rule). Rendering the prior
// config is impossible (only its bytes survive), so an absent hash is
// the honest value.
func (m *Manager) priorSet14589(prior []byte, havePrior bool) (map[string]bool, map[string]string) {
	names := map[string]bool{}
	hashes := map[string]string{}
	if !havePrior {
		return names, hashes
	}
	for _, n := range connNamesInConfigText14589(string(prior)) {
		names[n] = true
		if h, ok := m.prevHashFor14589(n); ok {
			hashes[n] = h
		}
	}
	return names, hashes
}

func (m *Manager) prevHashFor14589(name string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prevConnHashes == nil {
		return "", false
	}
	h, ok := m.prevConnHashes[name]
	return h, ok
}

// renderSubsetFile14589 re-renders only the loaded subset. PSKs of
// refused connections are dropped with their VPN entry, so a restart
// cannot resurrect their secret.
func (m *Manager) renderSubsetFile14589(ipsecCfg *config.IPsecConfig, generation string, keep map[string]bool) (string, map[string]string, error) {
	sub := filterIPsecCfg14589(ipsecCfg, keep)
	text, rendered, err := m.renderConfig(sub)
	if err != nil {
		return "", nil, err
	}
	if !sameBoolSet14589(rendered, keep) {
		// A kept name fell out of the subset render (should not happen
		// for a set charon just loaded); treat as unrecoverable here.
		return "", nil, fmt.Errorf("subset render %v does not match loaded set %v", rendered, keep)
	}
	hs, err := renderedConnectionHashes(text, rendered)
	if err != nil {
		return "", nil, err
	}
	text += "\n" + renderGenerationMarker(generation)
	return text, hs, nil
}

func filterIPsecCfg14589(src *config.IPsecConfig, keep map[string]bool) *config.IPsecConfig {
	if src == nil {
		return &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{}}
	}
	out := *src
	vpns := make(map[string]*config.IPsecVPN, len(keep))
	for name, vpn := range src.VPNs {
		// Rendered names are sanitized; keep matching on both the raw
		// and sanitized spellings.
		if keep[name] || keep[sanitizeSwanctlValue(name)] {
			vpns[name] = vpn
		}
	}
	out.VPNs = vpns
	return &out
}

func isSubset14589(set, super map[string]bool) bool {
	for n := range set {
		if !super[n] {
			return false
		}
	}
	return true
}

func sameBoolSet14589(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if !b[n] {
			return false
		}
	}
	return true
}

// connNamesInConfigText14589 lists top-level connection names in a
// rendered swanctl file's connections{} section.
func connNamesInConfigText14589(text string) []string {
	var out []string
	inConns := false
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "connections {" {
			inConns = true
			continue
		}
		if !inConns {
			continue
		}
		if trim == "}" && !strings.HasPrefix(line, " ") {
			break
		}
		if strings.HasSuffix(trim, "{") && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			out = append(out, strings.TrimSpace(strings.TrimSuffix(trim, "{")))
		}
		if trim == "}" && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			// connection close; keep scanning
			continue
		}
	}
	return out
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
	// #10712: snapshot the prior file BEFORE removing it, mirroring applyConfig:
	// if the reload below fails, charon still runs the OLD config, so the
	// removed file must be restored — otherwise charon's own next start or
	// reload would load NO xpf config while charon runs the old one.
	prior, priorErr := os.ReadFile(m.configPath)
	havePrior := true
	if priorErr != nil {
		if !os.IsNotExist(priorErr) {
			return fmt.Errorf("read prior config: %w", priorErr)
		}
		havePrior = false
	}
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	// #9511: the file is gone from here until the reload below succeeds or the
	// prior file is restored. Tell the caller before reloading, so it stops
	// trusting its record of the loaded generation (see applyConfig).
	if written != nil {
		written()
	}
	if _, err := m.reloadResult(); err != nil {
		var perr *partialReloadError
		if errors.As(err, &perr) {
			loaded, lerr := m.ListLoadedConns()
			if lerr == nil {
				loadedSet := make(map[string]bool, len(loaded))
				for n := range loaded {
					loadedSet[n] = true
				}
				if len(loadedSet) == 0 {
					return &partialApplyError{err: err, names: map[string]bool{}, hashes: map[string]string{}, clear: true}
				}
				if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
					return errors.Join(err, rbErr)
				}
				names, hs := m.priorSet14589(prior, havePrior)
				return &partialApplyError{err: err, names: names, hashes: hs, clear: true}
			}
			if rbErr := m.rollbackReload14589(prior, havePrior); rbErr != nil {
				return errors.Join(err, rbErr)
			}
			names, hs := m.priorSet14589(prior, havePrior)
			return &partialApplyError{err: err, names: names, hashes: hs, clear: true}
		}
		if restoreErr := m.restoreConfigAfterFailedReload(prior, havePrior); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	return nil
}

// restoreConfigAfterFailedReload returns the swanctl snippet to its pre-apply
// state (#10712): the prior bytes when a file existed, or no file when the
// apply would have created one. It restores the FILE only; callers on the
// #14589 partial path additionally re-load it (rollbackReload14589), because
// after a partial load charon no longer runs the prior generation and a
// file-only restore would resurrect it on the next restart. reload() reads
// the live path, so the divergence window between the write and the restore
// cannot be closed further here — but it is synchronous and short.
func (m *Manager) restoreConfigAfterFailedReload(prior []byte, havePrior bool) error {
	if !havePrior {
		if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove unloaded config after failed reload: %w", err)
		}
		slog.Info("swanctl reload failed; removed unloaded config", "path", m.configPath)
		return nil
	}
	if err := fsatomic.WriteFileAtomic(m.configPath, prior, 0600); err != nil {
		return fmt.Errorf("restore prior config after failed reload: %w", err)
	}
	slog.Info("swanctl reload failed; restored prior config", "path", m.configPath)
	return nil
}

// partialLoadSummary is the parsed "loaded N of M ..., F failed to load"
// verdict swanctl --load-all prints for one loader (connections, pools,
// authorities). loaded < total (equivalently failed > 0) means charon
// accepted only part of the candidate (#14589).
type partialLoadSummary struct {
	loaded, total, failed int
	kind                  string
}

var partialLoadRe14589 = regexp.MustCompile(`loaded (\d+) of (\d+) (connections|pools|authorities), (\d+) failed to load`)

// parsePartialLoad14589 returns the first partial summary in output.
func parsePartialLoad14589(output string) (partialLoadSummary, bool) {
	m := partialLoadRe14589.FindStringSubmatch(output)
	if m == nil {
		return partialLoadSummary{}, false
	}
	loaded, _ := strconv.Atoi(m[1])
	total, _ := strconv.Atoi(m[2])
	failed, _ := strconv.Atoi(m[4])
	if failed == 0 && loaded >= total {
		return partialLoadSummary{}, false
	}
	return partialLoadSummary{loaded: loaded, total: total, failed: failed, kind: m[3]}, true
}

// partialReloadError reports a partial --load-all: charon loaded a
// subset of the candidate. The subset is not named by the summary;
// callers discover it via ListLoadedConns (#14589).
type partialReloadError struct {
	summary partialLoadSummary
	output  string
	err     error
}

func (e *partialReloadError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("swanctl --load-all: partial load (%s): %v: %s", e.summary.kind, e.err, e.output)
	}
	return fmt.Sprintf("swanctl --load-all: partial load (%s): %s", e.summary.kind, e.output)
}

func (e *partialReloadError) Unwrap() error { return e.err }

// reload runs swanctl --load-all. A nil return means the candidate is
// what charon runs. A *partialReloadError means charon loaded only a
// subset (see #14589); any other error means charon kept the prior
// config (vici/exec/total failure). swanctl may exit 0 on a partial,
// so the output text, not just the exit code, is the verdict
// (docs/ipsec-swanctl-load-proof.md).
func (m *Manager) reload() error {
	_, err := m.reloadResult()
	return err
}

func (m *Manager) reloadResult() (partialLoadSummary, error) {
	output, err := m.sc("--load-all")
	outStr := string(output)
	if summary, partial := parsePartialLoad14589(outStr); partial {
		return summary, &partialReloadError{summary: summary, output: outStr, err: err}
	}
	if err != nil {
		return partialLoadSummary{}, fmt.Errorf("swanctl --load-all: %w: %s", err, outStr)
	}
	slog.Info("swanctl config reloaded")
	return partialLoadSummary{}, nil
}

// promoteConnNames records newNames — the set of connections that were
// actually RENDERED+LOADED on this apply — and their effective-content hashes.
// It returns names whose live SAs must be terminated because the connection
// departed, changed, or still has outstanding changed-connection teardown debt.
//
// A prior connection is gone if the operator DELETED its VPN OR it fell out of
// the render as unrenderable (#5494). A same-name connection is changed when
// its rendered security-effective content differs from the last successful
// apply. Both cases leave a live SA operating under stale configuration and
// must be torn down. Cosmetic fields not emitted by renderConfig do not affect
// the hash.
//
// #4898: this is called ONLY after a successful reload, or after a #14589
// partial load recovered to a set charon demonstrably runs, so the remembered
// names/hashes always describe the last config strongSwan actually loaded.
// The diff and state advance stay atomic under mu.
//
// #6542: removal debt is retried only while the name remains absent; adding a
// connection back discharges that debt. Changed-connection debt is retried
// even while the name remains loaded, because its live SA may still use stale
// credentials/selectors.
func (m *Manager) promoteConnNames(newNames map[string]bool, newHashes map[string]string) (removed, changed []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seedFromStateLocked() // #9687
	seen := make(map[string]bool, len(m.prevConnNames)+len(m.pendingTerminate)+len(m.pendingChanged))
	for name := range m.prevConnNames {
		if !newNames[name] {
			removed = append(removed, name)
			seen[name] = true
			continue
		}
		// Old state files have no content hashes. Adopt the current baseline
		// without forcing every existing tunnel down during the first upgrade
		// apply; later content changes are fully tracked.
		if oldHash, known := m.prevConnHashes[name]; known && oldHash != newHashes[name] {
			removed = append(removed, name)
			changed = append(changed, name)
			seen[name] = true
		}
	}
	for name := range m.pendingTerminate {
		if !newNames[name] && !seen[name] {
			removed = append(removed, name)
			seen[name] = true
		}
	}
	for name := range m.pendingChanged {
		if !seen[name] {
			removed = append(removed, name)
			if newNames[name] {
				changed = append(changed, name)
			}
			seen[name] = true
		}
	}
	m.prevConnNames = newNames
	m.prevConnHashes = newHashes
	m.pendingTerminate = nil
	m.pendingChanged = nil
	// #9687: any removal/change is debt from here until recordTerminateDebt settles it.
	for _, name := range removed {
		if m.inflight == nil {
			m.inflight = make(map[string]int, len(removed))
		}
		m.inflight[name]++
	}
	m.persistStateLocked()
	sort.Strings(removed)
	sort.Strings(changed)
	return removed, changed
}

// recordTerminateDebt records the connections whose teardown failed on this
// apply so the next reconcile retries them, and returns the error Apply/Clear
// reports to the caller. An empty failed set discharges cleanly (nil error).
//
// The debt is UNIONED into the pending sets rather than replacing them:
// promoteConnNames releases mu before the terminates run, so a concurrent Apply
// could otherwise clobber the other's debt. Removal debt is filtered by the
// loaded set; changed-connection debt is retained while loaded.
//
// #9687: it also settles removed, the set the matching promotion counted as
// in flight, and persists the result. That write happens on success too, so a
// completed teardown leaves no debt on disk.
func (m *Manager) recordTerminateDebt(removed, failed []string) error {
	m.mu.Lock()
	for _, name := range removed {
		if m.inflight[name] <= 1 {
			delete(m.inflight, name)
		} else {
			m.inflight[name]--
		}
	}
	for _, name := range failed {
		if m.prevConnNames[name] {
			if m.pendingChanged == nil {
				m.pendingChanged = make(map[string]bool)
			}
			m.pendingChanged[name] = true
		} else {
			if m.pendingTerminate == nil {
				m.pendingTerminate = make(map[string]bool)
			}
			m.pendingTerminate[name] = true
		}
	}
	m.persistStateLocked()
	m.mu.Unlock()
	if len(failed) == 0 {
		return nil
	}
	sort.Strings(failed)
	return fmt.Errorf("terminate stale IPsec SAs for removed or changed connection(s) "+
		"%s: teardown retried on next commit", strings.Join(failed, ", "))
}

// terminateRemovedConns tears down live IKE/child SAs for connections that
// departed or changed security-effective content. It returns names that had a
// live SA and were successfully terminated, followed by names whose terminate
// FAILED. It queries live SAs so an affected connection with no active SA is a
// clean no-op (#3941).
//
// #6542: a stale connection observed LIVE whose terminate errors is still
// forwarding under old configuration — the exact fail-open this teardown
// exists to close — so it becomes teardown debt the caller retries.
func (m *Manager) terminateRemovedConns(removed []string) (terminated, failed []string) {
	if len(removed) == 0 {
		return nil, nil
	}

	removedSet := make(map[string]bool, len(removed))
	for _, name := range removed {
		removedSet[name] = true
	}

	live, err := m.liveConnNames()
	if err != nil {
		// Could not enumerate live SAs (charon down / vici error). Fall back
		// to an unconditional, idempotent terminate of each affected name so a
		// stale SA is not left forwarding; swanctl no-ops when nothing matches.
		//
		// #6542: a failure here is ambiguous — it may be a genuine teardown
		// failure or merely "no matching SA" for a connection that was never
		// up. It is still carried as debt: the NEXT apply enumerates live SAs
		// and discharges the debt silently if the name is not live, so an
		// ambiguous failure self-clears in one reconcile instead of latching.
		slog.Warn("could not list SAs before terminating stale IPsec "+
			"connections; terminating unconditionally", "err", err)
		for _, name := range removed {
			if !m.terminateIKE(name) {
				failed = append(failed, name)
			}
		}
		return nil, failed
	}

	for name := range live {
		if removedSet[name] {
			if m.terminateIKE(name) {
				terminated = append(terminated, name)
			} else {
				failed = append(failed, name)
			}
		}
	}
	sort.Strings(terminated)
	return terminated, failed
}

// reinitiateChangedConnections brings back changed connections that had a
// live IKE SA before teardown. Removed connections and changed connections
// whose teardown failed are never initiated.
//
// Only a connection whose NEW rendered policy would itself initiate is
// reinitiated here (#14140). The renderer emits start_action = start only
// for establish-tunnels=immediately on a non-responder-only gateway, and
// trap (traffic-triggered, not eager) for on-traffic. A responder-only
// gateway (remote_addrs = %any, gw.ResponderOnly) has no fixed peer to
// dial — swanctl --initiate against it fails or is meaningless — and an
// on-traffic / responder-only-mode / unset-mode VPN deliberately does not
// eagerly establish. Eagerly initiating those after a content change
// contradicted the rendered policy: it turned a config change that
// touched a live responder/on-traffic SA into a spurious Apply failure
// (the initiate error propagates) and attempted an outbound IKE the
// operator never asked for. Skipping is not leaving the tunnel down by
// accident: the new config is loaded, the peer (responder-only) or the
// first matching packet (trap) re-establishes under the new settings,
// exactly as on a fresh load.
func (m *Manager) reinitiateChangedConnections(ipsecCfg *config.IPsecConfig, changed, terminated []string) error {
	if len(changed) == 0 || len(terminated) == 0 {
		return nil
	}
	changedSet := make(map[string]bool, len(changed))
	for _, name := range changed {
		changedSet[name] = true
	}
	terminatedSet := make(map[string]bool, len(terminated))
	for _, name := range terminated {
		terminatedSet[name] = true
	}
	var errs []error
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]
		connName := sanitizeSwanctlValue(name)
		if !changedSet[connName] || !terminatedSet[connName] {
			continue
		}
		if !vpnEagerlyInitiates(ipsecCfg, vpn) {
			continue
		}
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			if err := m.InitiateConnection(child.Name); err != nil {
				errs = append(errs, fmt.Errorf("reinitiate changed IPsec connection %s child %s: %w",
					connName, child.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// vpnEagerlyInitiates reports whether the rendered child policy for vpn
// eagerly initiates: exactly the start_action = start arm of the render
// in policy.go — establish-tunnels=immediately on a gateway that is not
// responder-only. It resolves the gateway through the same
// resolveRemoteAddr the renderer uses, so a legacy inline-endpoint VPN
// (gw == nil, usable literal/hostname gateway) counts as initiable, a
// dangling/unrenderable gateway (ok == false — such a VPN is not in the
// loaded set and cannot be a changed+terminated candidate anyway) does
// not, and a defined responder-only gateway does not. Every other mode —
// on-traffic (trap), responder-only, and unset — waits for the peer or
// for traffic, on reapply just as on first load (#14140).
func vpnEagerlyInitiates(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) bool {
	if vpn == nil || vpn.EstablishTunnels != "immediately" {
		return false
	}
	_, _, gw, ok := resolveRemoteAddr(ipsecCfg, vpn)
	if !ok {
		return false
	}
	return gw == nil || !gw.ResponderOnly
}

// terminateIKE issues `swanctl --terminate --ike <name>` for a single
// connection and reports whether it succeeded. The error is logged here and
// converted to a false return so the caller can carry the teardown debt
// (#6542); it is deliberately not wrapped and propagated, because a single
// failure must not abort the teardown of the OTHER affected connections.
func (m *Manager) terminateIKE(name string) bool {
	if out, err := m.sc("--terminate", "--ike", name); err != nil {
		slog.Warn("swanctl terminate for stale IPsec VPN failed "+
			"(SA may already be down); teardown retried on next commit",
			"ike", name, "err", err, "output", string(out))
		return false
	}
	slog.Info("terminated live SAs for stale IPsec connection", "ike", name)
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
