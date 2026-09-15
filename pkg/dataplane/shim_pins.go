package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
)

// Per-compile bpffs pin finality for the userspace shim.
//
// Three cleanups run in CompileUserspaceShim after CompileConfig accepts the
// config and before the attach they exist for (#7079): the legacy TC sweep,
// the legacy-only map-pin sweep, and the scoped XDP link-pin sweep (#9847).
// The XDP re-pin and unpinned-link check live here too — they share the pin
// layout and the "pinning is the precondition for hitless operation"
// invariant, and loader.go crossed the 1500 LOC [WATCH] floor carrying them.
//
// Split out of loader.go by #9847, the way #6740 split link_maps.go. The move
// is verbatim: same functions, same order (XDP block first, legacy block
// second), no behaviour change. The #7079 ordering guard matches the callee
// names at the CompileUserspaceShim call site, so it is unaffected by which
// file holds the definitions.

// linkPinPath is the bpffs directory holding the pinned XDP/TC bpf_links. A
// var rather than a const so #9847 tests can redirect the pin-finality paths
// (scoped removal, re-pin, Close degraded-report) at a temp dir; production
// never reassigns it.
var linkPinPath = "/sys/fs/bpf/xpf/links"

// removeUserspaceShimXDPLinkPins deletes every `xdp_*` link pin for an
// interface with NO live link in this process, so the attach is a FRESH
// attach rather than a pinned-link reuse — reuse (`existing.Update`)
// swaps the program without reinitializing the mlx5 XSK RQs, leaving the
// fill ring unconsumed, which breaks zero-copy.
//
// #9847: pins for interfaces WITH a registered link are KEPT. The old shape
// deleted every `xdp_*` pin on every compile, and the attach loop then
// short-circuited on "already attached" without re-pinning — so after a
// second compile, Close's handle closes detached XDP from every interface
// (a bpf_link survives only while a handle or a pin holds it). A registered
// link never takes the pinned-reuse path the sweep exists to prevent (it
// returns before LoadPinnedLink), so keeping its pin changes nothing about
// the fresh-attach rationale — it only preserves the hitless-restart ref.
//
// Relocated here from userspace.Manager.Compile by #7079: it must precede
// AttachXDP and must NOT precede CompileConfig. Best-effort — a pin already gone
// is the desired end state, as at the original site.
func (m *Manager) removeUserspaceShimXDPLinkPins() {
	keep := make(map[int]bool)
	for ifindex := range m.XDPLinks() {
		keep[ifindex] = true
	}
	removeUserspaceShimXDPLinkPinsExcept(linkPinPath, keep)
}

// removeUserspaceShimXDPLinkPinsExcept is the #9847 test seam: it deletes
// every `xdp_*` pin in dir except those naming an ifindex in keep. A pin
// whose suffix is not a decimal ifindex is removed — it cannot name a live
// link. A missing dir is a no-op (best-effort, as at the original site).
func removeUserspaceShimXDPLinkPinsExcept(dir string, keep map[int]bool) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "xdp_") {
			continue
		}
		if ifindex, err := strconv.Atoi(strings.TrimPrefix(name, "xdp_")); err == nil && keep[ifindex] {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// ensureXDPLinkPinned re-pins a registered XDP link whose pin file is
// missing (#9847). The attach loops short-circuit registered links with
// "already attached" and never reach the fresh-attach Pin, so without this
// a link whose initial Pin failed (AttachXDP logs and continues) — or
// whose pin was deleted out from under the process — stays unpinned, and
// Close's handle close detaches it.
//
// cilium caches the pin path on the link handle (RawLink.pinnedPath): Pin
// to the SAME path is a nil no-op (internal/sys/pinning_other.go), so a
// link whose pin file disappeared would "re-pin" successfully while the pin
// stays absent. Unpin first to forget the cached path (a no-op when nothing
// is pinned; its error is irrelevant — the stat below is the verdict), then
// Pin, then VERIFY the pin exists: a nil Pin with no file is a failure, not
// a success. Returns nil when the pin is present (already or re-pinned).
//
// A nil link is a test-seeded membership without a handle (SetLinkForTest
// records nil as-is); there is nothing to pin. Failures warn and are
// returned: the attach already succeeded, and Close reports a degraded
// shutdown when the pin is still missing.
func ensureXDPLinkPinned(ifindex int, l link.Link) error {
	if l == nil {
		return nil
	}
	pinFile := filepath.Join(linkPinPath, fmt.Sprintf("xdp_%d", ifindex))
	if _, err := os.Stat(pinFile); err == nil {
		return nil
	}
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir for XDP re-pin", "ifindex", ifindex, "err", err)
		return fmt.Errorf("create link pin dir for XDP re-pin: %w", err)
	}
	l.Unpin()
	if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to re-pin registered XDP link; hitless restart impossible for this interface",
			"ifindex", ifindex, "err", err)
		return fmt.Errorf("re-pin XDP link for ifindex %d: %w", ifindex, err)
	}
	if _, err := os.Stat(pinFile); err != nil {
		slog.Warn("XDP re-pin reported success but the pin is still missing; hitless restart impossible for this interface",
			"ifindex", ifindex, "pin", pinFile)
		return fmt.Errorf("re-pin XDP link for ifindex %d left no pin at %s", ifindex, pinFile)
	}
	slog.Info("re-pinned registered XDP link", "ifindex", ifindex)
	return nil
}

// unpinnedXDPLinks reports the registered XDP ifindexes with no pin file in
// dir, sorted (#9847). Any stat failure counts as missing — pinning is the
// precondition for hitless operation, and Close reports whatever it cannot
// prove as a degraded shutdown rather than a silent one.
func unpinnedXDPLinks(dir string, links map[int]link.Link) []int {
	var missing []int
	for ifindex := range links {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("xdp_%d", ifindex))); err != nil {
			missing = append(missing, ifindex)
		}
	}
	slices.Sort(missing)
	return missing
}

type pinnedTCLink interface {
	Unpin() error
	Close() error
}

var userspaceShimLegacyOnlyMapPins = []string{
	"xdp_progs",
	"tc_progs",
	"policer_states",
}

func cleanupUserspaceShimLegacyOnlyMapPins() error {
	return cleanupUserspaceShimLegacyOnlyMapPinsIn(bpfPinPath, userspaceShimLegacyOnlyMapPins)
}

func cleanupUserspaceShimLegacyOnlyMapPinsIn(pinDir string, names []string) error {
	var cleanupErrs []error
	for _, name := range names {
		pinFile := filepath.Join(pinDir, name)
		if err := os.Remove(pinFile); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			cleanupErrs = append(cleanupErrs,
				fmt.Errorf("remove legacy-only userspace shim map pin %s: %w", pinFile, err))
			continue
		}
		slog.Info("removed legacy-only BPF map pin before userspace shim attach", "pin", pinFile)
	}
	return errors.Join(cleanupErrs...)
}

func cleanupUserspaceShimLegacyTCLinks() error {
	return cleanupUserspaceShimLegacyTCLinksIn(linkPinPath, func(path string) (pinnedTCLink, error) {
		return link.LoadPinnedLink(path, nil)
	})
}

func cleanupUserspaceShimLegacyTCLinksIn(
	linkDir string,
	load func(string) (pinnedTCLink, error),
) error {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read userspace shim link pins: %w", err)
	}
	var cleanupErrs []error
	for _, entry := range entries {
		if !isLegacyTCPinName(entry.Name()) {
			continue
		}
		pinFile := filepath.Join(linkDir, entry.Name())
		pinned, err := load(pinFile)
		if err != nil {
			if rmErr := os.Remove(pinFile); rmErr != nil && !os.IsNotExist(rmErr) {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("remove unreadable legacy TC pin %s: load: %v; remove: %w", pinFile, err, rmErr))
				continue
			}
			slog.Warn("removed unreadable legacy TC link pin", "pin", pinFile, "err", err)
			continue
		}
		pinErrs := 0
		if err := pinned.Unpin(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("unpin %s: %w", pinFile, err))
			pinErrs++
		}
		if err := pinned.Close(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close %s: %w", pinFile, err))
			pinErrs++
		}
		if pinErrs == 0 {
			slog.Info("detached stale legacy TC link before userspace shim attach", "pin", pinFile)
		}
	}
	return errors.Join(cleanupErrs...)
}

func isLegacyTCPinName(name string) bool {
	if !strings.HasPrefix(name, "tc_") {
		return false
	}
	if len(name) == len("tc_") {
		return false
	}
	for _, r := range name[len("tc_"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
