package routing

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
)

// linkLookupDeleter is the lookup-and-delete slice of the netlink
// surface releaseOwnedLink needs. linkOps (tunnel.go) and vrfOps
// (vrf.go) both satisfy it.
type linkLookupDeleter interface {
	LinkByName(name string) (netlink.Link, error)
	LinkDel(netlink.Link) error
}

// errForeignOccupant is returned (wrapped) by releaseOwnedLink when
// the link wearing an owned name fails the caller's isOurs identity
// check: the link is foreign, not the owned device, and is never
// deleted. Detect it with errors.Is.
var errForeignOccupant = errors.New("foreign link occupies owned name")

// errLinkDelFailed marks (wrapped) the LinkDel-failure outcome of
// releaseOwnedLink, so a caller can distinguish a genuine delete
// failure (fail the commit closed, #5355) from a transient lookup
// failure (defer to the next reconcile) without string matching.
// Detect it with errors.Is.
var errLinkDelFailed = errors.New("LinkDel failed")

// alwaysOurs is the isOurs value for managers whose removal path has
// historically deleted whatever wears the tracked name (bond, xfrm,
// tunnel): the foreign-occupant policy of those managers is unchanged
// (#17020). VRF passes a real type check and refuses the foreign link
// instead (see reconcileVRFs).
func alwaysOurs(netlink.Link) bool { return true }

// releaseOwnedLink performs the owned-netdev release skeleton shared
// by every manager in this package (#17020, R4-Q42-01): look the link
// up by name, classify the lookup error, and delete — releasing
// ownership ONLY on a genuine not-found or a successful LinkDel.
//
//   - Genuine not-found (isLinkNotFound): released=true, err=nil. The
//     device is proven gone; the caller drops its tracking entry and
//     reports success.
//   - Any other lookup error (transient — EBUSY, ENOBUFS, EINTR,
//     transport): released=false, err wrapped with the caller's
//     kind/name context. The kernel state is unknown; the caller MUST
//     retain ownership so the next reconcile retries (#4901/#5495/
//     #7529/#8073 — this branch is the one each manager previously
//     hand-wrote and one copy at a time got wrong).
//   - Lookup succeeds but isOurs(link) is false: released=false, err
//     wrapping errForeignOccupant. The foreign link is never deleted.
//     Ownership RETENTION is the caller's decision (VRF releases: the
//     name is no longer ours to manage — see reconcileVRFs).
//   - LinkDel fails: released=false, err wrapped. The device is still
//     in the kernel; the caller retains ownership for retry (#4901).
//   - LinkDel succeeds: released=true, err=nil.
//
// released=true is therefore the ONLY outcome under which a caller
// may drop its per-name tracking entry on the strength of the device
// being gone.
func releaseOwnedLink(ops linkLookupDeleter, kind, name string, isOurs func(netlink.Link) bool) (released bool, err error) {
	link, err := ops.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return true, nil // genuinely gone
		}
		slog.Warn("owned-link delete: link lookup failed, retaining ownership for retry",
			"kind", kind, "name", name, "err", err)
		return false, fmt.Errorf("lookup %s %s for delete: %w", kind, name, err)
	}
	if isOurs != nil && !isOurs(link) {
		slog.Warn("owned-link delete: refusing to delete foreign link occupying owned name",
			"kind", kind, "name", name, "type", link.Type())
		return false, fmt.Errorf("%s %s: %w: existing link is %s", kind, name, errForeignOccupant, link.Type())
	}
	if err := ops.LinkDel(link); err != nil {
		slog.Warn("owned-link delete: LinkDel failed, retaining ownership for retry",
			"kind", kind, "name", name, "err", err)
		return false, fmt.Errorf("delete %s %s: %w: %w", kind, name, errLinkDelFailed, err)
	}
	slog.Info("owned link removed", "kind", kind, "name", name)
	return true, nil
}
