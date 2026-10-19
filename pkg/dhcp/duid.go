// duid.go holds DHCPv6 DUID identity management: generation,
// persistence, type rotation, and the clear/enumerate operations.
// Split verbatim from dhcp.go (#6430).
package dhcp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// DUIDInfo holds information about a DHCPv6 DUID for display.
type DUIDInfo struct {
	Interface string
	Type      string // "DUID-LL" or "DUID-LLT"
	HexBytes  string
	Display   string
}

// DUIDs returns information about all configured/persisted DHCPv6 DUIDs.
func (m *Manager) DUIDs() []DUIDInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []DUIDInfo
	for ifName := range m.duidTypes {
		duid := m.duids[ifName]
		if duid == nil {
			// Try loading from disk
			if d, err := m.loadDUID(ifName); err == nil {
				duid = d
			}
		}
		if duid != nil {
			result = append(result, DUIDInfo{
				Interface: ifName,
				Type:      duid.DUIDType().String(),
				HexBytes:  hex.EncodeToString(duid.ToBytes()),
				Display:   duid.String(),
			})
		}
	}
	return result
}

// ClearDUID removes the persisted DUID for an interface. The next DHCPv6
// request will generate a fresh DUID. ifaceName must be the lease key
// (config.DHCPLeaseIfName), not an operator spelling: operator surfaces
// resolve Junos/Linux/lease-key spellings through
// Config.ResolveDHCPClientIdentifierTargets first (#15756). An absent
// file is idempotent success — callers that must not silently succeed on
// an unknown name resolve (and refuse) before calling here.
func (m *Manager) ClearDUID(ifaceName string) error {
	// Validate BEFORE mutating in-memory state or touching the filesystem so a
	// crafted interface name is refused without side effects (#4857).
	path, err := m.duidPath(ifaceName)
	if err != nil {
		return err
	}

	m.mu.Lock()
	delete(m.duids, ifaceName)
	m.mu.Unlock()

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	slog.Info("DHCPv6: DUID cleared", "interface", ifaceName)
	return nil
}

// ClearAllDUIDs removes every DHCPv6 DUID this manager knows about — both the
// in-memory cache AND every DUID persisted on disk, including a DUID whose
// client has not called getDUID since the last restart (present on disk but
// absent from m.duids). Iterating only m.duids left such persisted DUIDs behind
// while the API reported "all cleared" (#4909). Delete errors are aggregated
// and returned so the caller never reports success while an I/O or permission
// error stranded a DUID file.
func (m *Manager) ClearAllDUIDs() error {
	// Union of in-memory cached interfaces and interfaces with a persisted DUID
	// file, so a DUID untouched since restart is still enumerated.
	names := make(map[string]struct{})
	m.mu.Lock()
	for k := range m.duids {
		names[k] = struct{}{}
	}
	m.mu.Unlock()

	const prefix = "dhcpv6-duid-"
	entries, err := os.ReadDir(m.stateDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("enumerate DUID state dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name, ok := strings.CutPrefix(e.Name(), prefix); ok {
			names[name] = struct{}{}
		}
	}

	var errs []error
	for ifName := range names {
		if err := m.ClearDUID(ifName); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// getDUID returns the DUID for an interface, loading from disk or generating
// a new one as needed. The result is cached in memory and persisted.
func (m *Manager) getDUID(ifaceName string) (dhcpv6.DUID, error) {
	m.mu.Lock()
	want := normalizeDUIDType(m.duidTypes[ifaceName])
	if d, ok := m.duids[ifaceName]; ok {
		// #5855: only reuse the cached DUID when its ACTUAL type matches the
		// requested mode. A `duid-ll`<->`duid-llt` config change restarts the
		// client but leaves the OLD-type DUID cached; returning it kept the old
		// identity indefinitely. On a mismatch, drop the stale cache and fall
		// through to load/regenerate the requested type.
		if actualDUIDType(d) == want {
			m.mu.Unlock()
			return d, nil
		}
		delete(m.duids, ifaceName)
	}
	m.mu.Unlock()

	// Try the persisted DUID — reuse it ONLY when its type matches the requested
	// mode (#5855). A persisted DUID of the RETIRED type is not reusable, but it
	// IS retained below as the fail-safe fallback if regenerating the requested
	// type cannot be persisted.
	persisted, loadErr := m.loadDUID(ifaceName)
	if loadErr == nil && actualDUIDType(persisted) == want {
		m.mu.Lock()
		m.duids[ifaceName] = persisted
		m.mu.Unlock()
		slog.Info("DHCPv6: loaded persisted DUID",
			"interface", ifaceName, "duid", persisted)
		return persisted, nil
	}
	if loadErr == nil {
		slog.Info("DHCPv6: persisted DUID type differs from configured mode; rotating",
			"interface", ifaceName, "persisted", actualDUIDType(persisted), "want", want)
	}

	// Generate a NEW DUID of the requested type.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup for DUID: %w", err)
	}

	var duid dhcpv6.DUID
	switch want {
	case "duid-llt":
		// Time-based — stable only via persistence
		epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		duid = &dhcpv6.DUIDLLT{
			HWType:        iana.HWTypeEthernet,
			Time:          uint32(time.Since(epoch).Seconds()),
			LinkLayerAddr: iface.HardwareAddr,
		}
	default: // "duid-ll"
		duid = &dhcpv6.DUIDLL{
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: iface.HardwareAddr,
		}
	}

	// Persist the NEW identity durably BEFORE it is cached or returned, so the
	// restarted client never sends an identity that is not on disk (a DUID-LLT
	// embeds a generation timestamp — an unpersisted one is ephemeral, #4909).
	if err := m.saveDUID(ifaceName, duid); err != nil {
		// #5855 rotation fail-safe: the new-type identity is NOT durable. If a
		// PREVIOUS identity is persisted (loadErr==nil, i.e. this is a type
		// rotation), RETAIN it — keep the running client coherent on the OLD
		// identity and expose NO unpersisted new DUID (a partially-rotated
		// DUID-LLT would be ephemeral and diverge from disk). getDUID then keeps
		// returning the old (persisted) type until a later reconcile persists the
		// new one; show/API reports that actual active type.
		if loadErr == nil {
			m.mu.Lock()
			m.duids[ifaceName] = persisted
			m.mu.Unlock()
			slog.Warn("DHCPv6: DUID type rotation persist failed; retaining the previous "+
				"persisted identity (no unpersisted identity exposed)",
				"interface", ifaceName, "want", want,
				"retained", actualDUIDType(persisted), "err", err)
			return persisted, nil
		}
		// Cold start — no prior identity to fall back to. A DUID-LLT that never
		// reaches disk is ephemeral, so surface the failure (#4909). A DUID-LL is
		// a pure function of the hardware address — byte-identical across restart
		// even if never persisted — so a persist failure there is benign.
		if want == "duid-llt" {
			return nil, fmt.Errorf("persist DUID-LLT for %s (unstable across restart if not persisted): %w",
				ifaceName, err)
		}
		slog.Warn("DHCPv6: failed to persist DUID",
			"interface", ifaceName, "err", err)
	}

	m.mu.Lock()
	m.duids[ifaceName] = duid
	m.mu.Unlock()

	slog.Info("DHCPv6: generated DUID",
		"interface", ifaceName, "duid", duid)
	return duid, nil
}

// validInterfaceName reports whether s is a plausible Linux network interface
// name that is safe to embed in a DUID state-file path. A real interface name
// is at most IFNAMSIZ-1 (15) bytes and contains NONE of: a path separator, a
// NUL, whitespace, or a "." / ".." path component. Rejecting these neutralizes
// a crafted `interface` value (e.g. "../../../../etc/passwd") arriving on the
// DHCPv6-DUID-clear RPC, which would otherwise traverse out of the DUID state
// directory when joined into the state-file path (#4857). VLAN sub-interfaces
// such as "reth0.50" contain a '.' but are NOT a "." / ".." component, so they
// remain valid.
func validInterfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	if s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/', '\\', 0, ' ', '\t', '\n', '\r':
			return false
		}
	}
	return true
}

// duidPath returns the on-disk DUID state-file path for an interface. It
// validates the interface name and verifies the joined path stays directly
// under stateDir so a traversal-y name can never reach a file outside the DUID
// state directory (#4857). All DUID file operations (load/save/clear) route
// through here, so the containment guard is applied uniformly.
func (m *Manager) duidPath(ifaceName string) (string, error) {
	if !validInterfaceName(ifaceName) {
		return "", fmt.Errorf("invalid interface name %q for DUID path", ifaceName)
	}
	p := filepath.Join(m.stateDir, "dhcpv6-duid-"+ifaceName)
	// Defense in depth: the resolved path must be a direct child of stateDir.
	if filepath.Dir(p) != filepath.Clean(m.stateDir) {
		return "", fmt.Errorf("refusing DUID path outside state dir for interface %q", ifaceName)
	}
	return p, nil
}

func (m *Manager) loadDUID(ifaceName string) (dhcpv6.DUID, error) {
	path, err := m.duidPath(ifaceName)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return dhcpv6.DUIDFromBytes(data)
}

// duidWriteFile persists DUID bytes durably. A package var so a test can inject
// a persist failure to exercise the #5855 rotation fail-safe (keep the previous
// identity, expose no unpersisted new DUID) — loadDUID reads through the real
// filesystem, so an injected write failure leaves a pre-seeded old DUID
// readable while the new-type write fails deterministically (regardless of the
// test's uid, unlike an unwritable-dir trick).
var duidWriteFile = func(path string, data []byte, perm os.FileMode) error {
	return fsatomic.WriteFileDurable(path, data, perm)
}

func (m *Manager) saveDUID(ifaceName string, duid dhcpv6.DUID) error {
	path, err := m.duidPath(ifaceName)
	if err != nil {
		return err
	}
	// Durable creation (#1894 code-r1): the state dir's own entry must
	// be made durable on first creation or the DUID file can be lost
	// with the whole directory after a power cut.
	if err := fsatomic.MkdirAllDurable(m.stateDir, 0755); err != nil {
		return err
	}
	// DurableState (#1894): the DUID is the client's stable DHCPv6
	// identity — losing it to a power cut changes the identity the
	// server knows us by across reboot (new leases, stale bindings).
	return duidWriteFile(path, duid.ToBytes(), 0644)
}

// actualDUIDType maps a resolved DUID to the configured type token
// ("duid-ll" / "duid-llt"), or "" for an unrecognized type. It is how getDUID
// detects a type ROTATION: a cached or persisted DUID whose REAL type differs
// from the requested duid-ll/duid-llt mode must be regenerated, not silently
// reused (#5855). loadDUID returns the concrete *DUIDLL / *DUIDLLT via
// dhcpv6.DUIDFromBytes, and generation builds the same concrete types, so a
// concrete-type switch is exhaustive for the modes xpf can configure.
func actualDUIDType(d dhcpv6.DUID) string {
	switch d.(type) {
	case *dhcpv6.DUIDLLT:
		return "duid-llt"
	case *dhcpv6.DUIDLL:
		return "duid-ll"
	default:
		return ""
	}
}

// normalizeDUIDType resolves the empty config token to the duid-ll default,
// matching fingerprintV6 and getDUID (#5855).
func normalizeDUIDType(t string) string {
	if t == "" {
		return "duid-ll"
	}
	return t
}
