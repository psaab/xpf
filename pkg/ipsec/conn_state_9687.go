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
// connection set it last loaded and its outstanding teardown debt (#9687).
const DefaultConnStatePath = "/var/lib/xpf/ipsec-conn-state.json"

// maxConnStateBytes bounds the state read, so a corrupt file cannot exhaust
// memory at start.
const maxConnStateBytes = 1 << 20

// connState is the on-disk form of prevConnNames and the teardown debt
// (#9687).
//
// Both lived only in process memory, and xpfd builds a fresh Manager on every
// start. A restart between a failed terminate (#6542 debt), a failed reload
// that deferred a removal (#4898), or a teardown still running, and its retry
// left the restarted daemon with no record of the departed connection, so it
// never terminated that connection's child SA. strongSwan is a separate
// service, its SAs survive the restart, and they kept forwarding under a
// configuration nothing loads.
//
// Pending includes the removals a promotion handed to terminateRemovedConns
// that have not settled yet, so a stop in the middle of a teardown still
// leaves the record behind.
type connState struct {
	Loaded  []string `json:"loaded"`
	Pending []string `json:"pending_terminate"`
}

// seedFromStateLocked folds the persisted state into this Manager, once, at
// its first promotion. mu must be held.
//
// A missing file is the first start after an upgrade, or a node that never
// applied IPsec: nothing is seeded, which is the behaviour before #9687. An
// unreadable or oversized file is ignored with a warning for the same reason.
// Nothing seeded here is a licence to terminate a loaded connection:
// promoteConnNames still filters both sets by the newly-loaded one.
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
	for _, name := range st.Pending {
		if m.pendingTerminate == nil {
			m.pendingTerminate = make(map[string]bool, len(st.Pending))
		}
		m.pendingTerminate[name] = true
	}
}

// persistStateLocked writes prevConnNames and the debt, in-flight removals
// included, to statePath with a durable write. mu must be held.
//
// A failure is logged, not returned. It costs only the restart case this file
// exists for, and failing an IPsec apply over it would trade a tunnel outage
// for that.
func (m *Manager) persistStateLocked() {
	if m.statePath == "" {
		return
	}
	pending := make(map[string]bool, len(m.pendingTerminate)+len(m.inflight))
	for name := range m.pendingTerminate {
		pending[name] = true
	}
	for name := range m.inflight {
		pending[name] = true
	}
	data, err := json.Marshal(connState{Loaded: sortedConnNames(m.prevConnNames), Pending: sortedConnNames(pending)})
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(m.statePath), 0o755); err == nil {
			err = fsatomic.WriteFileDurable(m.statePath, data, 0o600)
		}
	}
	if err != nil {
		slog.Warn("could not persist IPsec connection state; a restart before the next apply would not tear down removed connections",
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
