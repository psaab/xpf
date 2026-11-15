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
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
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
//
// #19110: "remove" now means RECLAIM. Unlinking a pin only schedules the link's
// release in the kernel (bpffs inode destroy -> bpf_link_put -> schedule_work),
// and the release takes rtnl, so an attach issued straight after the unlink can
// overtake it. reclaimStaleXDPLinkPin detaches the link synchronously
// (BPF_LINK_DETACH) before unpinning it. The sweep also KEEPS the pins of this
// compile's pending interfaces: attachUserspaceShimXDP reclaims each of those
// immediately before that interface's own attach, so no interface waits out
// its neighbours' detaches.
func (m *Manager) removeUserspaceShimXDPLinkPins(pending []int) {
	keep := make(map[int]bool)
	for ifindex := range m.XDPLinks() {
		keep[ifindex] = true
	}
	for _, ifindex := range pending {
		keep[ifindex] = true
	}
	removeUserspaceShimXDPLinkPinsExcept(linkPinPath, keep)
}

// removeUserspaceShimXDPLinkPinsExcept is the #9847 test seam: it reclaims
// every `xdp_*` pin in dir except those naming an ifindex in keep. A pin whose
// suffix is not a decimal ifindex is reclaimed too: it cannot name an interface
// this process manages. A missing dir is a no-op (best-effort, as at the
// original site).
func removeUserspaceShimXDPLinkPinsExcept(dir string, keep map[int]bool) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "xdp_") {
			continue
		}
		ifindex, err := strconv.Atoi(strings.TrimPrefix(name, "xdp_"))
		if err == nil && keep[ifindex] {
			continue
		}
		reclaimStaleXDPLinkPin(filepath.Join(dir, name)).log(ifindex)
	}
}

// reclaimableXDPLink is what reclaiming a stale pin needs from the link it
// holds.
type reclaimableXDPLink interface {
	Detach() error
	Unpin() error
	Close() error
}

// loadPinnedXDPLinkFn opens a pinned link. It is a seam for the reclaim cells.
var loadPinnedXDPLinkFn = func(path string) (reclaimableXDPLink, error) {
	return link.LoadPinnedLink(path, nil)
}

// pinOnBPFFSFn reports whether path lives on a bpffs mount. Only a bpffs file
// can be a pin; bpf_inode_type (kernel/bpf/inode.c) answers EACCES for any
// other inode, which is how the #9847 fixtures' plain files load. It is a seam.
var pinOnBPFFSFn = func(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Type == unix.BPF_FS_MAGIC, nil
}

type xdpReclaimOutcome string

const (
	reclaimNoPin xdpReclaimOutcome = "no-pin"
	// reclaimDetached: the link was detached synchronously and its pin removed.
	reclaimDetached xdpReclaimOutcome = "detached"
	// reclaimNotALink: the file was not a link pin (a prog/map pin, or not on
	// bpffs), so it held no XDP link attachment. It was removed.
	reclaimNotALink xdpReclaimOutcome = "not-a-link"
	// reclaimDetachedPinStuck: detached, but the pin could not be removed. It now
	// names a dead link, and ensureXDPLinkPinned's identity check replaces it
	// once this process's link is attached.
	reclaimDetachedPinStuck xdpReclaimOutcome = "detached-pin-stuck"
	// reclaimDeferred: the link could not be detached (or could not be opened)
	// but the pin is gone. The kernel releases it later, as master always did,
	// and the attach's bounded wait absorbs that.
	reclaimDeferred xdpReclaimOutcome = "deferred-release"
	// reclaimStuck: neither detached nor unpinned, so a live pin may remain.
	// AttachXDP never reuses a pin (fresh-only), so the attach meets it as a
	// refusal and ends in ErrXDPOccupied naming this failure.
	reclaimStuck xdpReclaimOutcome = "stuck"
)

type xdpReclaimResult struct {
	path     string
	outcome  xdpReclaimOutcome
	detachMS int64
	err      error
}

// clean reports a reclaim that left nothing for the attach to wait on.
func (r xdpReclaimResult) clean() bool {
	return r.outcome == reclaimNoPin || r.outcome == reclaimDetached || r.outcome == reclaimNotALink
}

func (r xdpReclaimResult) String() string {
	if r.err == nil {
		return string(r.outcome)
	}
	return fmt.Sprintf("%s: %v", r.outcome, r.err)
}

func (r xdpReclaimResult) log(ifindex int) {
	switch {
	case r.outcome == reclaimNoPin:
	case r.err == nil:
		slog.Info("reclaimed stale XDP link pin", "ifindex", ifindex, "pin", r.path,
			"outcome", string(r.outcome), "detach_ms", r.detachMS, "issue", "#19110")
	default:
		slog.Warn("stale XDP link pin not fully reclaimed; the attach waits out the kernel's release",
			"ifindex", ifindex, "pin", r.path, "outcome", string(r.outcome), "err", r.err, "issue", "#19110")
	}
}

// reclaimStaleXDPLinkPin releases the link a previous process left pinned at
// path. It NEVER aborts the apply: every failure falls back to master's unlink
// (a deferred kernel release), and the attach that follows decides.
//
// The load failure is classified by its errno (cilium wraps BPF_OBJ_GET's errno
// with %w; its type mismatch carries none):
//   - ENOENT: nothing to do;
//   - no errno: cilium's "is not a Link", a prog/map pin, which holds no XDP
//     link attachment: remove it;
//   - EACCES on a non-bpffs file: not a pin at all: remove it;
//   - anything else (EPERM, EACCES on bpffs, ENOMEM, EMFILE, ...): UNKNOWN. It
//     may be a live link this process cannot open: unlink it as master did and
//     let the attach's wait absorb the deferred release.
//
// Once the link is open, Close runs on every path.
func reclaimStaleXDPLinkPin(path string) xdpReclaimResult {
	r := xdpReclaimResult{path: path}
	l, err := loadPinnedXDPLinkFn(path)
	if err != nil {
		var errno unix.Errno
		switch {
		case errors.Is(err, os.ErrNotExist):
			r.outcome = reclaimNoPin
			return r
		case !errors.As(err, &errno):
			r.outcome = reclaimNotALink
			r.err = removeStalePin(path)
			return r
		case errno == unix.EACCES:
			if onBPF, serr := pinOnBPFFSFn(path); serr == nil && !onBPF {
				r.outcome = reclaimNotALink
				r.err = removeStalePin(path)
				return r
			}
		}
		if rmErr := removeStalePin(path); rmErr != nil {
			r.outcome = reclaimStuck
			r.err = errors.Join(fmt.Errorf("open pinned link: %w", err), rmErr)
			return r
		}
		r.outcome = reclaimDeferred
		r.err = fmt.Errorf("open pinned link: %w", err)
		return r
	}
	defer func() {
		if cerr := l.Close(); cerr != nil {
			slog.Debug("close reclaimed XDP link handle", "pin", path, "err", cerr)
		}
	}()
	start := time.Now()
	detErr := l.Detach()
	r.detachMS = time.Since(start).Milliseconds()
	unpinErr := l.Unpin()
	if unpinErr != nil {
		// cilium's Unpin removes the file; try the plain unlink once more
		// before calling the pin stuck.
		if rmErr := removeStalePin(path); rmErr == nil {
			unpinErr = nil
		} else {
			unpinErr = errors.Join(unpinErr, rmErr)
		}
	}
	switch {
	case detErr == nil && unpinErr == nil:
		r.outcome = reclaimDetached
	case detErr == nil:
		r.outcome = reclaimDetachedPinStuck
		r.err = fmt.Errorf("unpin: %w", unpinErr)
	case unpinErr == nil:
		r.outcome = reclaimDeferred
		r.err = fmt.Errorf("detach: %w", detErr)
	default:
		r.outcome = reclaimStuck
		r.err = errors.Join(fmt.Errorf("detach: %w", detErr), fmt.Errorf("unpin: %w", unpinErr))
	}
	return r
}

func removeStalePin(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// pinnedXDPLinkIsOursFn reports whether the pin at path names the very link
// this process holds (the same kernel link ID). It is a seam for the #9847 and
// #19110 cells, whose fakes carry no kernel identity.
var pinnedXDPLinkIsOursFn = func(path string, ours link.Link) (bool, error) {
	pinned, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return false, err
	}
	defer pinned.Close()
	pi, err := pinned.Info()
	if err != nil {
		return false, fmt.Errorf("pinned link info: %w", err)
	}
	oi, err := ours.Info()
	if err != nil {
		return false, fmt.Errorf("registered link info: %w", err)
	}
	return pi.ID == oi.ID, nil
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
		// #19110: presence is not proof. A reclaim that detached a dead
		// process's link but could not unlink its pin leaves a pin naming a
		// DEAD link at this path, and the sweep's keep set preserves it for a
		// registered ifindex. Keep the pin only if it names this very link;
		// otherwise replace it, or say the shutdown cannot be hitless.
		ours, verr := pinnedXDPLinkIsOursFn(pinFile, l)
		if verr == nil && ours {
			return nil
		}
		slog.Warn("XDP link pin does not name this process's registered link; replacing it",
			"ifindex", ifindex, "pin", pinFile, "verify_err", verr, "issue", "#19110")
		if err := removeStalePin(pinFile); err != nil {
			slog.Warn("could not remove a stale XDP link pin; hitless restart impossible for this interface",
				"ifindex", ifindex, "pin", pinFile, "err", err)
			return fmt.Errorf("replace stale XDP pin for ifindex %d: %w", ifindex, err)
		}
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
