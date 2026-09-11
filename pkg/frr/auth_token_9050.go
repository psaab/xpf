package frr

import (
	"log/slog"
	"strings"
)

// #9050: the render belt must not defer auth-secret token safety to a gate the
// lenient path downgrades.
//
// THE SEAM. frrTokenUnsafeIndex (pkg/config) rejects ' ', '\t', bytes < 0x20 and
// 0x7f in a routing auth secret at commit. sanitizeFRRValue rejects only
// < 0x20 / 0x7f -- and maps them TO ' '. Its own doc says the whitespace case is
// handled because "frrTokenUnsafeIndex also rejects at commit", and
// compiler_uniformgates_log_feed_routing.go downgrades exactly that gate to a
// warning on the tolerant path (lenientFRRAuthValues). So on Store.Load, HA
// Store.SyncApply, or a confirm-rollback recompile, a persisted secret with a
// space renders as:
//
//	 neighbor 10.0.2.1 password my secret pass
//
// Worse for a TAB: sanitizeFRRValue converts it INTO a splitter, so the belt
// manufactures the very shape it is supposed to prevent. And the strict
// validator's stated rationale -- "the render path strips control chars and the
// offending line stays inert / single-line" -- is false for a literal space and
// false in the worse direction for a tab.
//
// A new commit cannot introduce this: configstore.CheckText and Store.Commit
// both hard-reject. The value has to be already persisted -- a pre-#2889 config,
// a rollback slot older than the gate, or a peer running an older build.
//
// WHY OMIT RATHER THAN EMIT. What FRR does with a split line was not measured
// and is not asserted, but both possibilities are bad and they differ in blast
// radius: either it truncates to the first token (a weakened but still
// "configured" secret, silently) or vtysh refuses the line, which by this
// repository's own precedent for a bad router-id FAILS THE WHOLE frr-reload.
// The second takes down every routing protocol on the box, not just this
// adjacency.
//
// Omitting the single auth line confines the damage to one adjacency, which
// then fails to authenticate -- loudly, in FRR's own logs, at the layer that
// owns the decision. Between "one neighbor cannot come up" and "no routing
// config applies at all", the first is the one to choose for a value that
// should never have been persisted.
//
// NOT quoting it: whether vtysh accepts a quoted operand at each of these ten
// sites (#9496 added the two IS-IS per-interface sites #9050 had missed)
// sites is unmeasured, and guessing wrong reproduces the reload failure this
// avoids.

// frrAuthTokenUnsafe reports whether s cannot be emitted as a single vtysh
// token. It mirrors config.frrTokenUnsafeIndex's character set deliberately: a
// render belt that admits a character the commit gate rejects is a seam, and
// this file exists because there was one.
func frrAuthTokenUnsafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// authTokenOrOmit returns the value to interpolate and whether the caller may
// emit the line at all.
//
// The warning names the protocol and the length and NEVER the value: this is an
// auth secret, and the log is not 0640.
func authTokenOrOmit(kind, s string) (string, bool) {
	if !frrAuthTokenUnsafe(s) {
		return sanitizeFRRValue(s), true
	}
	slog.Warn("frr: OMITTING a routing authentication line whose secret is not a "+
		"single vtysh token (#9050) — the adjacency will not authenticate; "+
		"re-set the key without whitespace",
		"protocol", kind,
		"secret_len", len(s),
		"has_space", strings.ContainsAny(s, " \t"))
	return "", false
}
