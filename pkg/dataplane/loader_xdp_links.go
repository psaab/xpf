package dataplane

// The shim XDP attach/detach lifecycle, moved out of loader.go by the #7253
// modularity audit when #9725's link reporting pushed that file past the 1500
// LOC watch floor. A pure move: no behaviour changed with it.

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachXDP attaches the XDP main program to the given interface.
// If forceGeneric is true, uses generic (SKB) mode instead of native driver mode.
// When forceGeneric is false, tries native driver mode only (no automatic fallback).
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	// #2114 A3 carve-out: the attach family keeps its own pre-registry
	// loaded rejection on BOTH unarmed states; the typed ErrDataplaneNotArmed
	// never fires here.
	if !m.loaded.Load() {
		return fmt.Errorf("eBPF programs not loaded")
	}

	entryProg := m.XDPEntryProgram()
	prog, present, _ := m.lookupProgramLocked(entryProg)
	if !present {
		return fmt.Errorf("%s not found", entryProg)
	}

	if _, exists := m.xdpLinkFor(ifindex); exists {
		return fmt.Errorf("XDP already attached to ifindex %d", ifindex)
	}

	// #863: defer setting IFACE_FLAG_XDP_ATTACHED on iface_zone_map
	// entries for this ifindex until AFTER a successful attach. The
	// flag is the tc_main tunnel-egress bypass's positive proof; if
	// attach fails, the flag must NOT be set. A flag-set failure on
	// the success path is logged at WARN — the attach itself
	// succeeded so we don't unwind, but tc_main's bypass won't fire
	// for this surface until the next config push runs SetZone
	// (which re-claims the surface based on m.xdpLinks[ifindex] and
	// sets the bit accordingly).
	defer func() {
		if _, ok := m.xdpLinkFor(ifindex); ok {
			if err := m.setXDPAttachedFlag(ifindex, true); err != nil {
				slog.Warn("AttachXDP: failed to set IFACE_FLAG_XDP_ATTACHED — tunnel-egress bypass will deny until next SetZone",
					"ifindex", ifindex, "err", err)
			}
		}
	}()

	// Try to load a previously pinned link and update it atomically.
	//
	// #864: before reusing, verify the pinned link's attach mode matches
	// what the caller requested.  If a previous boot fell back to generic
	// (skb-mode) and pinned a generic-mode link, we would otherwise keep
	// running in generic forever — losing native-XDP performance even
	// after the driver/firmware issue that forced the fallback is resolved,
	// and leaving IFACE_FLAG_NATIVE_XDP stale in the BPF maps.
	pinFile := filepath.Join(linkPinPath, xdpLinkPinName(ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if xdpAttachModeMatches(ifindex, forceGeneric) {
			if err := existing.Update(prog); err == nil {
				m.setXDPLink(ifindex, existing)
				slog.Info("updated pinned XDP link", "ifindex", ifindex)
				return nil
			}
			// Update failed (e.g. program type mismatch) — detach + re-attach.
			existing.Close()
			os.Remove(pinFile)
		} else {
			// Attach mode mismatch — existing pin is generic but we want
			// driver (or vice versa).  Drop the pin and attach fresh so the
			// mode picks up correctly and IFACE_FLAG_NATIVE_XDP stays true.
			slog.Warn("pinned XDP link has wrong attach mode; re-attaching",
				"ifindex", ifindex, "forceGeneric", forceGeneric)
			existing.Close()
			os.Remove(pinFile)
		}
	}

	// Fresh attachment (first boot or pin was removed/incompatible).
	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	}
	if forceGeneric {
		opts.Flags = link.XDPGenericMode
	} else {
		opts.Flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		return fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	// Pin the link for future restarts.
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir", "err", err)
	} else if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to pin XDP link", "ifindex", ifindex, "err", err)
	}

	m.setXDPLink(ifindex, l)
	m.seedInterfaceCounter(ifindex)
	mode := "native"
	if forceGeneric {
		mode = "generic"
	}
	slog.Info("attached XDP program", "ifindex", ifindex, "mode", mode)
	return nil
}

// seedInterfaceCounter pre-populates the PERCPU_HASH interface_counters
// entry for ifindex. Called from control-plane interface registration
// (AttachXDP, AddTxPort) so the BPF hot path stays lookup-only and
// never allocates in softirq context (#759). Idempotent: UpdateNoExist
// races safely across repeated registrations.
func (m *Manager) seedInterfaceCounter(ifindex int) {
	ic, _, _ := m.lookupMapLocked("interface_counters")
	if ic == nil {
		return
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]InterfaceCounterValue, numCPUs)
	_ = ic.Update(uint32(ifindex), zero, ebpf.UpdateNoExist)
}

// SwapToUserspaceXDPShimEntryProgram atomically replaces the XDP entry
// program on all attached interfaces with the retained userspace XDP shim.
// Userspace mode keeps this shim attached for normal operation and degraded
// local/control handling.
func (m *Manager) SwapToUserspaceXDPShimEntryProgram() error {
	return m.swapXDPEntryProg(userspaceShimEntryProg)
}

func (m *Manager) swapXDPEntryProg(name string) error {
	// #2114 A3 class 1: the program registry read is a REQUIRED access —
	// the fresh state returns the typed gate error, an armed/retained miss
	// keeps master's "not found".
	prog, present, st := m.lookupProgramLocked(name)
	if st == registryFresh {
		return fmt.Errorf("%w: XDP program %s", ErrDataplaneNotArmed, name)
	}
	if !present {
		return fmt.Errorf("XDP program %q not found", name)
	}
	m.mu.Lock()
	currentEntry := m.xdpEntryProgramLocked()
	m.mu.Unlock()
	if currentEntry == name {
		return nil // already using this program
	}
	// #6740: take the swap targets as ONE snapshot under m.mu — both maps
	// together, so the VLAN skip is decided against the same instant the link
	// set was read — then run the BPF updates on that snapshot with the lock
	// RELEASED. Holding m.mu across l.Update() would put a BPF syscall inside
	// the same lock the 1 Hz status path needs, which is the thing this section
	// exists to avoid.
	//
	// Skipping VLAN sub-interfaces: the parent's XDP handles VLAN-tagged
	// traffic. Swapping the shim onto VLAN sub-interfaces breaks NDP because
	// generic XDP + XDP_PASS doesn't properly deliver to the kernel's IPv6 NDP
	// stack on VLAN devices.
	targets := m.xdpSwapTargets()
	var errs []error
	for _, t := range targets {
		if err := t.link.Update(prog); err != nil {
			errs = append(errs, fmt.Errorf("swap XDP on ifindex %d: %w", t.ifindex, err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	// #2114 A3: scoped section around the field write only — never
	// whole-method locking (the xdpLinks loop above is serialized by the
	// outer userspace-manager lock at the liveness-restore call site).
	m.mu.Lock()
	if swapXDPEntryProgHook != nil {
		swapXDPEntryProgHook()
	}
	m.xdpEntryProg = name
	m.mu.Unlock()
	slog.Info("swapped XDP entry program", "program", name, "interfaces", len(targets))
	return nil
}

// DetachXDP detaches the XDP program from the given interface and
// removes its pin file.
func (m *Manager) DetachXDP(ifindex int) error {
	l, exists := m.xdpLinkFor(ifindex)
	if !exists {
		return nil
	}
	// #863: clear IFACE_FLAG_XDP_ATTACHED claims FIRST, before
	// closing/unpinning the link. If clear fails, the link stays in
	// m.xdpLinks and a retry of DetachXDP picks up where this one
	// left off. Doing it the other way around (close then clear)
	// leaves stale claims with no retry path — the next DetachXDP
	// early-returns at !exists.
	if err := m.setXDPAttachedFlag(ifindex, false); err != nil {
		slog.Error("DetachXDP: failed to clear IFACE_FLAG_XDP_ATTACHED — tc_main bypass may stay enabled until next config push",
			"ifindex", ifindex, "err", err)
		return fmt.Errorf("detach XDP from ifindex %d: clear flag: %w", ifindex, err)
	}
	// #9725: report the count this detach LEAVES, before unpinning and closing,
	// so the gate closes while the program is still adjudicating. Reporting here
	// rather than after deleteXDPLink is also what makes the close-error path
	// safe: the map entry is removed either way, and the report already happened.
	m.notifyAttachedLinksFunc(func() int { return m.attachedXDPLinkCountExcluding(ifindex) })
	l.Unpin()
	closeErr := l.Close()
	// Claim cleanup succeeded; the link is conceptually gone whether
	// or not Close errored. Remove from m.xdpLinks so a retry doesn't
	// infinite-loop on a stuck-close link, but surface the close
	// error.
	m.deleteXDPLink(ifindex)
	// #9725 round 12: report AGAIN, now that the map no longer holds this link.
	// The report above is "the count without me", computed before the detach so
	// the gate closes while the program still adjudicates — but under concurrent
	// detaches EVERY such report is computed before the others' deletions land,
	// so none of them carries the final state. This one does: it is the true
	// count, and whichever detach finishes last reports it. It can only LOWER
	// the count, so it cannot reopen the gate.
	m.notifyAttachedLinksFunc(m.AttachedXDPLinkCount)
	if closeErr != nil {
		return fmt.Errorf("detach XDP from ifindex %d: %w", ifindex, closeErr)
	}
	slog.Info("detached XDP program", "ifindex", ifindex)
	return nil
}
