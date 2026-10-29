package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// redirectSysctlRoot is the procfs root used for sysctl posture; overridable
// in tests to exercise existing and newly created netdev entries.
var redirectSysctlRoot = "/proc/sys/net"

var noRedirectsActive atomic.Bool

// redirectFamilies enumerates the sysctl families/knobs the
// no-redirects posture touches, shared by the disable and restore
// walks so the two cannot drift.
var redirectFamilies = []struct {
	name  string
	knobs []string
}{
	{"ipv4", []string{"send_redirects", "accept_redirects"}},
	{"ipv6", []string{"accept_redirects"}},
}

// redirectKnobPaths enumerates every knob file currently present under
// the sysctl root for the redirect families.
func redirectKnobPaths() []string {
	var out []string
	for _, family := range redirectFamilies {
		confRoot := filepath.Join(redirectSysctlRoot, family.name, "conf")
		entries, err := os.ReadDir(confRoot)
		if err != nil {
			slog.Warn("failed to enumerate redirect sysctls", "path", confRoot, "err", err)
			continue
		}
		for _, entry := range entries {
			for _, knob := range family.knobs {
				out = append(out, filepath.Join(confRoot, entry.Name(), knob))
			}
		}
	}
	return out
}

func writeRedirectKnobs(value string) {
	for _, path := range redirectKnobPaths() {
		if _, err := fsatomic.WriteKernelKnob(path, value); err != nil {
			slog.Warn("failed to set ICMP redirects", "path", path, "value", value, "err", err)
		}
	}
}

// redirectKnobSnapshotFile is the durable copy of capturedRedirects
// (#17792). The capture is taken on the inactive->active transition,
// but the knobs stay asserted until the stanza is deleted — possibly
// after one or more daemon restarts — so the capture must outlive
// the process. The path is fixed on /var/lib/xpf (same state root as
// the transit ownership record) and deliberately NOT derived from
// redirectSysctlRoot: tests redirect the sysctl root into a temp tree
// while production must keep the snapshot on disk across restarts.
// A test seam so hermetic fixtures can redirect it into a temp tree.
var redirectKnobSnapshotFile = configstore.NoRedirectsCapturePath

// redirectKnobSnapshotVersion rejects snapshot files written by a
// different format generation: load fails soft (warn + recapture)
// rather than restoring values the current decoder cannot vouch for.
const redirectKnobSnapshotVersion = 1

type redirectKnobSnapshot struct {
	Version int               `json:"version"`
	Values  map[string]string `json:"values"` // key: path relative to redirectSysctlRoot
}

// capturedRedirects holds the per-path values observed on the
// inactive->active transition (#16779), restored verbatim on the
// active->inactive transition. Guarded by redirectCaptureMu.
var (
	redirectCaptureMu sync.Mutex
	capturedRedirects map[string]string
)

// redirectKnobRelPath renders an enumerated knob path relative to the
// sysctl root so snapshots do not embed the (test-redirectable) root.
func redirectKnobRelPath(path string) (string, bool) {
	rel, err := filepath.Rel(redirectSysctlRoot, path)
	if err != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// redirectKnobAbsPath validates that a snapshot key names one of the
// supported boolean redirect knobs under a sysctl interface directory.
func redirectKnobAbsPath(rel string) (string, bool) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel {
		return "", false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 4 || parts[1] != "conf" || parts[2] == "." || parts[2] == ".." {
		return "", false
	}
	for _, family := range redirectFamilies {
		if parts[0] != family.name {
			continue
		}
		for _, knob := range family.knobs {
			if parts[3] == knob {
				return filepath.Join(redirectSysctlRoot, rel), true
			}
		}
	}
	return "", false
}

// validRedirectKnobValue restricts snapshot values to the boolean
// sysctl domain the capture itself can observe.
func validRedirectKnobValue(v string) bool { return v == "0" || v == "1" }

// persistCapturedRedirectKnobs durably writes capturedRedirects under
// redirectCaptureMu. Best-effort: a failed write is logged and the
// in-memory capture still drives this process; the posture itself
// must not depend on the snapshot landing.
func persistCapturedRedirectKnobs() {
	snap := redirectKnobSnapshot{Version: redirectKnobSnapshotVersion, Values: make(map[string]string, len(capturedRedirects))}
	for path, v := range capturedRedirects {
		rel, ok := redirectKnobRelPath(path)
		if !ok || !validRedirectKnobValue(v) {
			slog.Warn("skipping invalid captured redirect knob", "path", path, "value", v)
			continue
		}
		snap.Values[rel] = v
	}
	if len(snap.Values) == 0 {
		return
	}
	data, err := json.Marshal(snap)
	if err != nil {
		slog.Warn("failed to encode captured redirect knobs", "err", err)
		return
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(redirectKnobSnapshotFile), 0o700); err != nil {
		slog.Warn("failed to create redirect knob snapshot directory", "path", redirectKnobSnapshotFile, "err", err)
		return
	}
	if err := fsatomic.WriteFileDurable(redirectKnobSnapshotFile, data, 0o600); err != nil {
		slog.Warn("failed to persist captured redirect knobs", "path", redirectKnobSnapshotFile, "err", err)
	}
}

// parseRedirectKnobSnapshot validates decoded snapshot bytes: version,
// non-empty values in the boolean domain, and keys that stay under
// the sysctl root. Any defect rejects the whole snapshot.
func parseRedirectKnobSnapshot(data []byte) (map[string]string, error) {
	var snap redirectKnobSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if snap.Version != redirectKnobSnapshotVersion {
		return nil, fmt.Errorf("unsupported version %d", snap.Version)
	}
	if len(snap.Values) == 0 {
		return nil, errors.New("empty values")
	}
	out := make(map[string]string, len(snap.Values))
	for rel, v := range snap.Values {
		abs, ok := redirectKnobAbsPath(rel)
		if !ok {
			return nil, fmt.Errorf("key %q escapes the sysctl root", rel)
		}
		if !validRedirectKnobValue(v) {
			return nil, fmt.Errorf("value %q for %q is not a boolean sysctl value", v, rel)
		}
		out[abs] = v
	}
	return out, nil
}

// loadPersistedRedirectKnobsLocked reads and validates the durable
// snapshot (#17792). The caller holds redirectCaptureMu. It reports
// (nil, false) when no usable snapshot exists; an unreadable or
// invalid snapshot warns and is treated as absent (fail soft: the
// caller recaptures the live knobs, matching pre-#17792 behaviour)
// — never as a successful capture.
func loadPersistedRedirectKnobsLocked() (map[string]string, bool) {
	data, err := os.ReadFile(redirectKnobSnapshotFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("failed to read persisted redirect knob capture; recapturing", "path", redirectKnobSnapshotFile, "err", err)
		}
		return nil, false
	}
	values, err := parseRedirectKnobSnapshot(data)
	if err != nil {
		slog.Warn("invalid persisted redirect knob capture; recapturing", "path", redirectKnobSnapshotFile, "err", err)
		return nil, false
	}
	return values, true
}

// clearPersistedRedirectKnobs removes the durable snapshot after a
// fully successful restore and fsyncs its parent so the removal itself
// is durable. A missing file or state directory is already clear.
func clearPersistedRedirectKnobs() error {
	if err := os.Remove(redirectKnobSnapshotFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove persisted redirect knob capture %s: %w", redirectKnobSnapshotFile, err)
	}
	if _, err := os.Stat(filepath.Dir(redirectKnobSnapshotFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect redirect knob snapshot directory: %w", err)
	}
	if err := fsatomic.SyncDir(filepath.Dir(redirectKnobSnapshotFile)); err != nil {
		return fmt.Errorf("sync redirect knob snapshot directory: %w", err)
	}
	return nil
}

// captureRedirectKnobs establishes a capture for an activating posture.
// It adopts a valid persisted capture before sampling live knobs, so a
// restart cannot replace the original values with the asserted zeroes.
func captureRedirectKnobs() {
	redirectCaptureMu.Lock()
	defer redirectCaptureMu.Unlock()
	ensureRedirectCaptureLocked()
}

// ensureRedirectCaptureLocked loads and validates a prior snapshot before
// capturing any newly enumerated paths. The caller holds redirectCaptureMu.
func ensureRedirectCaptureLocked() {
	needsPersist := false
	if capturedRedirects == nil {
		if persisted, ok := loadPersistedRedirectKnobsLocked(); ok {
			capturedRedirects = persisted
		} else {
			capturedRedirects = make(map[string]string)
			needsPersist = true
		}
	}
	for _, path := range redirectKnobPaths() {
		if _, ok := capturedRedirects[path]; ok {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(b))
		if !validRedirectKnobValue(value) {
			slog.Warn("ignoring invalid redirect knob value in capture", "path", path, "value", value)
			continue
		}
		capturedRedirects[path] = value
		needsPersist = true
	}
	if needsPersist {
		persistCapturedRedirectKnobs()
	}
}

// loadCapturedRedirectKnobsLocked loads the durable capture when this
// process has no in-memory copy. The caller holds redirectCaptureMu.
func loadCapturedRedirectKnobsLocked() {
	if capturedRedirects != nil {
		return
	}
	if persisted, ok := loadPersistedRedirectKnobsLocked(); ok {
		capturedRedirects = persisted
	}
}

// redirectCapturePending reports whether an inactive reconcile still has
// a capture to restore, including a file left by a previous process.
func redirectCapturePending() bool {
	redirectCaptureMu.Lock()
	defer redirectCaptureMu.Unlock()
	if capturedRedirects != nil {
		return true
	}
	_, err := os.Lstat(redirectKnobSnapshotFile)
	if err == nil {
		return true
	}
	return !errors.Is(err, os.ErrNotExist)
}

// isIPv4AcceptRedirects reports whether path is an ipv4
// accept_redirects knob (any interface, including dotted names).
func isIPv4AcceptRedirects(path string) bool {
	if filepath.Base(path) != "accept_redirects" {
		return false
	}
	confDir := filepath.Dir(filepath.Dir(path)) // .../ipv4/conf
	return filepath.Base(confDir) == "conf" && filepath.Base(filepath.Dir(confDir)) == "ipv4"
}

func ipv4ForwardingEnabled() bool {
	fwd, err := os.ReadFile(ipv4ForwardSysctlPath)
	return err == nil && strings.TrimSpace(string(fwd)) == "1"
}

// restoreValueForRedirectKnob computes the value to write on restore
// when no captured value exists for path (e.g. an interface created
// while the posture was active). For ipv4 accept_redirects the kernel
// router default is !ip_forward (inet_forward_change sets
// IPV4_DEVCONF_ALL(ACCEPT_REDIRECTS) = !forwarding); every other knob
// keeps the historical default of 1.
func restoreValueForRedirectKnob(path string) string {
	if isIPv4AcceptRedirects(path) && ipv4ForwardingEnabled() {
		return "0"
	}
	return "1"
}

// restoreRedirectKnobs writes back the captured per-path values. For
// ipv4 accept_redirects paths the restored value is additionally
// capped by the forwarding-dependent router default. Failed writes keep
// both the in-memory capture and the persisted snapshot for a later
// inactive reconcile; ownership is cleared only after every knob and
// the durable snapshot removal succeed.
func restoreRedirectKnobs() bool {
	redirectCaptureMu.Lock()
	defer redirectCaptureMu.Unlock()
	loadCapturedRedirectKnobsLocked()
	forwarding := ipv4ForwardingEnabled()
	success := true
	for _, path := range redirectKnobPaths() {
		value, ok := capturedRedirects[path]
		if !ok {
			value = restoreValueForRedirectKnob(path)
		} else if forwarding && isIPv4AcceptRedirects(path) && value == "1" {
			value = "0"
		}
		if _, err := fsatomic.WriteKernelKnob(path, value); err != nil {
			slog.Warn("failed to restore ICMP redirects", "path", path, "value", value, "err", err)
			success = false
		}
	}
	if !success {
		return false
	}
	if err := clearPersistedRedirectKnobs(); err != nil {
		slog.Warn("failed to clear restored redirect knob capture", "path", redirectKnobSnapshotFile, "err", err)
		return false
	}
	capturedRedirects = nil
	return true
}

func applyNoRedirectsPosture() {
	if !noRedirectsActive.Load() {
		return
	}
	writeRedirectKnobs("0")
}

// reconcileNoRedirects records the configured posture and drives the
// kernel knobs: assert 0 while active, and on the active->inactive
// transition restore the values captured on activation exactly once
// (#15710, #16779). The previous constant-1 restore was not a restore
// at all: with ip_forward=1 the kernel router default for
// ipv4/conf/all/accept_redirects is 0 (inet_forward_change sets it to
// !forwarding), so writing 1 enabled spoofed on-link redirects for
// the firewall's own traffic and clobbered foreign sysctl.d hardening.
// Deleting `system no-redirects` therefore restores the captured
// per-path values (ipv4 accept_redirects capped at !ip_forward)
// instead of a constant 1.
func reconcileNoRedirects(active bool) {
	wasActive := noRedirectsActive.Swap(active)
	switch {
	case active:
		if !wasActive {
			captureRedirectKnobs()
		}
		writeRedirectKnobs("0")
	case wasActive || redirectCapturePending():
		restoreRedirectKnobs()
	}
}
