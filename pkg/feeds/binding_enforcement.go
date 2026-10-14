package feeds

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// BindingEnforcement says what the dataplane enforces for a binding, as the
// operator-facing `Enforced:` sentence of the `show security
// dynamic-address` surfaces. It mirrors Manager.SnapshotForBindings (#5645,
// #9689) — the local CLI and the gRPC ShowText renderer both call it (#12903)
// so the two shows cannot drift from each other or from the snapshot
// semantics: current or stale prefixes; an empty or partial set under
// `fail-mode drop`; or unresolved, in which case policies referencing the
// name are rejected and the previous-good policy set stays enforced.
func BindingEnforcement(b *config.AddressBinding, runtimeFeeds map[string]FeedInfo) string {
	if runtimeFeeds == nil {
		return "unknown (no runtime feed status)"
	}
	ready, dropped, stale := 0, 0, 0
	var publicationDebt []string
	for _, feedName := range b.FeedNames {
		fi, ok := runtimeFeeds[feedName]
		switch {
		case ok && fi.PublicationDebt:
			publicationDebt = append(publicationDebt, feedName)
			if fi.Prefixes > 0 {
				ready++
			} else if fi.HoldDropped {
				dropped++
			}
		case ok && fi.Prefixes > 0:
			ready++
			if !fi.StaleSince.IsZero() {
				stale++
			}
		case ok && fi.HoldDropped:
			dropped++
		default:
			return "unresolved: a feed has no snapshot yet, so policies referencing this name are rejected and the previous-good policy set stays enforced"
		}
	}
	if len(publicationDebt) > 0 {
		return fmt.Sprintf("indeterminate: feed publication debt for %s; dataplane may still enforce the previous-good snapshot",
			strings.Join(publicationDebt, ", "))
	}
	if dropped > 0 {
		if b.FailMode == "drop" {
			return fmt.Sprintf("%d feed(s) dropped by hold-interval, publishing the other %d feed(s)' prefixes (fail-mode drop)", dropped, ready)
		}
		return "unresolved: a feed was dropped by its hold-interval under fail-mode retain, so policies referencing this name are rejected and the previous-good policy set stays enforced"
	}
	if stale > 0 {
		return fmt.Sprintf("last-good prefixes, %d feed(s) stale", stale)
	}
	return "current prefixes"
}
