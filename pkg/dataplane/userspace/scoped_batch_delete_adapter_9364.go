package userspace

import (
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9364 — the second half of the compile-time belt: the type the userspace
// backend PUBLISHES must satisfy the scoped-batch-delete capability.
//
// See `pkg/dataplane/scoped_batch_delete_published_9364.go` for why the belt is
// split across two packages (the capability interface is unexported in
// `pkg/dataplane`, and naming these types there would be an import cycle) and why
// an optional capability needs a belt at all: a miss does not error, it silently
// restores the bare delete #9364 exists to remove.
//
// `*LegacyDataPlaneAdapter` is the one that matters. `Manager.Sessions()` builds
// the store as
// `dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m))`, so the
// adapter — not the Manager that owns the implementation — is the value the
// store's type assertion is handed. #9482 is what happens when that distinction
// is missed: #9344 added a method to the Manager, not the adapter, and the HA
// cold-prime bulk sync silently never ran.
//
// `*Manager` is asserted too, for the same reason #9482's belt asserts both:
// `pkg/dataplane/userspace` declares exactly two types as
// `dataplane.RuntimeDataPlane` (`manager.go` and `legacy_dataplane.go`), so both
// are publishable, and asserting only the one wired today leaves the identical
// hole in its sibling.
var (
	_ scopedBatchDeleter = (*LegacyDataPlaneAdapter)(nil)
	_ scopedBatchDeleter = (*Manager)(nil)
)

// scopedBatchDeleter mirrors `pkg/dataplane`'s unexported
// `sessionDomainBatchDeleter`. It is a local restatement because the original
// cannot be named from here; `pkg/dataplane`'s half of the belt is what keeps the
// two from drifting apart.
type scopedBatchDeleter interface {
	BatchDeleteSessionsScoped([]dataplane.ScopedSessionKey) (int, error)
	BatchDeleteSessionsScopedV6([]dataplane.ScopedSessionKeyV6) (int, error)
}
