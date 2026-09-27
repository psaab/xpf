package ipsec

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// DefaultConnStatePath is where the daemon's Manager persists the swanctl
// connection set and rendered-content hashes it last loaded, plus teardown debt (#9687).
const DefaultConnStatePath = "/var/lib/xpf/ipsec-conn-state.json"

// maxConnStateBytes bounds the state read, so a corrupt file cannot exhaust
// memory at start.
const maxConnStateBytes = 1 << 20

// connState is the on-disk form of loaded connection names/content hashes and
// outstanding teardown debt (#9687, #10878).
//
// strongSwan is a separate service, so its SAs survive xpfd restarts. Persisted
// fingerprints let a later Apply detect same-name security changes, while
// Pending and PendingChanged preserve failed removal and reauthentication
// teardowns across a restart.
type connState struct {
	Loaded         []string          `json:"loaded"`
	Pending        []string          `json:"pending_terminate"`
	Fingerprints   map[string]string `json:"fingerprints,omitempty"`
	PendingChanged []string          `json:"pending_changed,omitempty"`
}

// seedFromStateLocked folds the persisted state into this Manager, once, at
// its first promotion. mu must be held.
//
// A missing file is the first start after an upgrade, or a node that never
// applied IPsec: nothing is seeded, which is the behaviour before #9687. An
// unreadable or oversized file is ignored with a warning for the same reason.
// Nothing seeded here is a licence to terminate a loaded connection:
// promoteConnNames filters removal debt by the newly-loaded set.
func (m *Manager) seedFromStateLocked() {
	if m.stateSeeded || m.statePath == "" {
		return
	}
	m.stateSeeded = true
	st, err := loadConnState(m.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("ignoring unreadable IPsec connection state; connections removed before this start will not be torn down",
				"path", m.statePath, "err", err)
		}
		return
	}
	if len(st.Loaded) > 0 && m.prevConnNames == nil {
		m.prevConnNames = make(map[string]bool, len(st.Loaded))
		for _, name := range st.Loaded {
			m.prevConnNames[name] = true
		}
	}
	if len(st.Fingerprints) > 0 {
		m.prevConnHashes = make(map[string]string, len(st.Fingerprints))
		for name, fingerprint := range st.Fingerprints {
			m.prevConnHashes[name] = fingerprint
		}
	}
	for _, name := range st.Pending {
		if m.pendingTerminate == nil {
			m.pendingTerminate = make(map[string]bool, len(st.Pending))
		}
		m.pendingTerminate[name] = true
	}
	for _, name := range st.PendingChanged {
		if m.pendingChanged == nil {
			m.pendingChanged = make(map[string]bool, len(st.PendingChanged))
		}
		m.pendingChanged[name] = true
	}
}

// persistStateLocked writes loaded names/fingerprints and the debt, including
// in-flight removals and changes, to statePath with a durable write. mu must
// be held.
//
// A failure is logged, not returned. It costs only the restart case this file
// exists for, and failing an IPsec apply over it would trade a tunnel outage
// for that.
func (m *Manager) persistStateLocked() {
	if m.statePath == "" {
		return
	}
	pending := make(map[string]bool, len(m.pendingTerminate)+len(m.inflight))
	pendingChanged := make(map[string]bool, len(m.pendingChanged)+len(m.inflight))
	for name := range m.pendingTerminate {
		pending[name] = true
	}
	for name := range m.pendingChanged {
		pendingChanged[name] = true
	}
	for name := range m.inflight {
		if m.prevConnNames[name] {
			pendingChanged[name] = true
		} else {
			pending[name] = true
		}
	}
	data, err := json.Marshal(connState{
		Loaded:         sortedConnNames(m.prevConnNames),
		Pending:        sortedConnNames(pending),
		Fingerprints:   m.prevConnHashes,
		PendingChanged: sortedConnNames(pendingChanged),
	})
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(m.statePath), 0o755); err == nil {
			err = fsatomic.WriteFileDurable(m.statePath, data, 0o600)
		}
	}
	if err != nil {
		slog.Warn("could not persist IPsec connection state; a restart before the next apply would not tear down stale connections",
			"path", m.statePath, "err", err)
	}
}

func loadConnState(path string) (connState, error) {
	f, err := os.Open(path)
	if err != nil {
		return connState{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConnStateBytes+1))
	if err != nil {
		return connState{}, err
	}
	if len(data) > maxConnStateBytes {
		return connState{}, fmt.Errorf("state file is larger than %d bytes", maxConnStateBytes)
	}
	var st connState
	if err := json.Unmarshal(data, &st); err != nil {
		return connState{}, err
	}
	return st, nil
}

func sortedConnNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
