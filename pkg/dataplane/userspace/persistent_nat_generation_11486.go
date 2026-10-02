package userspace

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/fsatomic"
)

const maxPersistentNatGenerationPeers11486 = 16

// PersistentNatLeaseBatch is one sender-owned idle-lease advertisement set.
// Generation is durable on the sender and advances before every authoritative
// clear; receivers retain a per-origin high-water mark indefinitely.
type PersistentNatLeaseBatch struct {
	OriginID   string
	Generation uint64
	Leases     []IdleLeaseWire
}

type persistentNatLeaseGenerationState struct {
	OriginID          string            `json:"origin_id"`
	Generation        uint64            `json:"generation"`
	RemoteGenerations map[string]uint64 `json:"remote_generations,omitempty"`
	PendingLocalClear bool              `json:"pending_local_clear,omitempty"`
	PendingRemote     map[string]bool   `json:"pending_remote,omitempty"`
}

var persistentNatLeaseGenerationPath11486 = "/var/lib/xpf/persistent-nat-lease-generation.json"

// PersistentNatLeaseGenerationStatePath returns the durable state file that
// must be included in factory-reset cleanup.
func PersistentNatLeaseGenerationStatePath() string {
	return persistentNatLeaseGenerationPath11486
}

func newPersistentNatLeaseOrigin11486() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("create persistent-NAT lease origin identity: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func validPersistentNatLeaseOrigin11486(origin string) bool {
	if len(origin) != 32 {
		return false
	}
	for _, char := range origin {
		if char < '0' || (char > '9' && char < 'a') || char > 'f' {
			return false
		}
	}
	return true
}

func (m *Manager) loadPersistentNatLeaseGenerationLocked() error {
	if m.persistentNatLeaseGenerationLoaded {
		return nil
	}
	path := m.persistentNatLeaseGenerationPath
	if path == "" {
		path = persistentNatLeaseGenerationPath11486
		m.persistentNatLeaseGenerationPath = path
	}
	data, err := os.ReadFile(path)
	if err == nil {
		var state persistentNatLeaseGenerationState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode persistent-NAT lease generation state: %w", err)
		}
		if !validPersistentNatLeaseOrigin11486(state.OriginID) {
			return errors.New("persistent-NAT lease generation state has invalid origin identity")
		}
		if len(state.RemoteGenerations) > maxPersistentNatGenerationPeers11486 ||
			len(state.PendingRemote) > maxPersistentNatGenerationPeers11486 {
			return errors.New("persistent-NAT lease generation state exceeds peer limit")
		}
		if state.RemoteGenerations == nil {
			state.RemoteGenerations = make(map[string]uint64)
		}
		if state.PendingRemote == nil {
			state.PendingRemote = make(map[string]bool)
		}
		for origin := range state.RemoteGenerations {
			if !validPersistentNatLeaseOrigin11486(origin) || origin == state.OriginID {
				return errors.New("persistent-NAT lease generation state has invalid remote origin")
			}
		}
		for origin := range state.PendingRemote {
			if !validPersistentNatLeaseOrigin11486(origin) || origin == state.OriginID {
				return errors.New("persistent-NAT lease generation state has invalid pending remote origin")
			}
			if _, ok := state.RemoteGenerations[origin]; !ok {
				return errors.New("persistent-NAT lease generation state has orphaned pending remote clear")
			}
		}
		m.persistentNatLeaseGeneration = state
		m.persistentNatLeaseGenerationLoaded = true
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persistent-NAT lease generation state: %w", err)
	}
	origin, err := newPersistentNatLeaseOrigin11486()
	if err != nil {
		return err
	}
	state := persistentNatLeaseGenerationState{
		OriginID:          origin,
		Generation:        1,
		RemoteGenerations: make(map[string]uint64),
		PendingLocalClear: true,
		PendingRemote:     make(map[string]bool),
	}
	if err := m.persistPersistentNatLeaseGenerationLocked(state); err != nil {
		return err
	}
	m.persistentNatLeaseGeneration = state
	m.persistentNatLeaseGenerationLoaded = true
	return nil
}

func (m *Manager) persistPersistentNatLeaseGenerationLocked(state persistentNatLeaseGenerationState) error {
	path := m.persistentNatLeaseGenerationPath
	if path == "" {
		path = persistentNatLeaseGenerationPath11486
		m.persistentNatLeaseGenerationPath = path
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode persistent-NAT lease generation state: %w", err)
	}
	if err := fsatomic.WriteFileDurable(path, data, 0600); err != nil {
		return fmt.Errorf("persist persistent-NAT lease generation state: %w", err)
	}
	return nil
}

func clonePersistentNatLeaseGenerationState11486(state persistentNatLeaseGenerationState) persistentNatLeaseGenerationState {
	clone := state
	clone.RemoteGenerations = make(map[string]uint64, len(state.RemoteGenerations))
	for origin, generation := range state.RemoteGenerations {
		clone.RemoteGenerations[origin] = generation
	}
	clone.PendingRemote = make(map[string]bool, len(state.PendingRemote))
	for origin, pending := range state.PendingRemote {
		clone.PendingRemote[origin] = pending
	}
	return clone
}

func (m *Manager) storePersistentNatLeaseGenerationLocked(state persistentNatLeaseGenerationState) error {
	if err := m.persistPersistentNatLeaseGenerationLocked(state); err != nil {
		return err
	}
	m.persistentNatLeaseGeneration = state
	return nil
}
