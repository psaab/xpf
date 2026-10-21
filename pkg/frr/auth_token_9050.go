package frr

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
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
// #14977 (D33-05) extends this one step: at every activation site the
// caller now also withholds the enclosing capability (OSPF interface
// block, RIP enrollment, IS-IS stanza/interface, BGP neighbor) when a
// CONFIGURED auth value cannot render — because "fails to
// authenticate" only holds when the peer requires auth; a peer that
// does not forms an unauthenticated adjacency with the password-less
// activation this file's contract used to leave behind. The belt
// itself (omit the LINE) is unchanged; the fail-closed escalation
// lives at the callers in protocols_render.go.
//
// #15990 extends the same belt to Junos `$9$` credentials on the
// tolerant path, without decoding twice. Compilation owns the one
// decode and records provenance on the compiled Secret: decoded values
// are plaintext even when they begin `$9$`; a retained tolerant blob
// is marked undecodable and omitted. Only a directly constructed,
// unprocessed renderer input takes the belt's decode fallback.

// frrAuthTokenUnsafe reports whether s cannot be emitted as a single vtysh
// token. It mirrors config.frrTokenUnsafeIndex's character set deliberately: a
// render belt that admits a character the commit gate rejects is a seam, and
// this file exists because there was one.
func frrAuthTokenUnsafe(s string) bool {
	for i := range s {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// resolvedAuthSecret applies the single-decode provenance contract to
// a compiled routing credential:
//
//   - Junos9Decoded: reveal the compile plaintext verbatim, even when
//     that plaintext begins `$9$`; it has already consumed its decode.
//   - Junos9Undecodable: tolerant compilation retained a failed blob;
//     no credential is available.
//   - Junos9Unprocessed: a directly constructed renderer input has no
//     compile provenance. Only non-`$9$` plaintext is safe to consume;
//     a leading `$9$` is unresolved authored material. A valid direct
//     blob is decoded for this render, while a malformed/decoded-empty
//     blob supplies no credential. This fallback never writes back, so
//     it cannot mark a direct value as compiled plaintext.
func resolvedAuthSecret(s *config.Secret) (string, bool) {
	if s == nil {
		return "", false
	}
	raw := s.Reveal()
	switch s.Provenance() {
	case config.Junos9Decoded:
		if raw == "" {
			return "", false
		}
		return raw, true
	case config.Junos9Undecodable:
		return "", false
	default:
		decoded, err := config.DecodeJunos9Secret(raw)
		if err != nil || decoded == "" {
			return "", false
		}
		return decoded, true
	}
}

// authTokenOrOmit returns the value to interpolate and whether the caller may
// emit the line at all.
//
// The warning names the protocol and the length and NEVER the value: this is an
// auth secret, and the log is not 0640.
func authTokenOrOmit(kind string, s *config.Secret) (string, bool) {
	resolved, ok := resolvedAuthSecret(s)
	if !ok {
		secretLen := 0
		if s != nil {
			secretLen = len(*s)
		}
		slog.Warn("frr: OMITTING a routing authentication line whose Junos $9$ secret cannot be decoded to a non-empty credential (#15990) — the adjacency will not authenticate; re-set the key",
			"protocol", kind,
			"secret_len", secretLen)
		return "", false
	}
	if !frrAuthTokenUnsafe(resolved) {
		return sanitizeFRRValue(resolved), true
	}
	slog.Warn("frr: OMITTING a routing authentication line whose secret is not a "+
		"single vtysh token (#9050) — the adjacency will not authenticate; "+
		"re-set the key without whitespace",
		"protocol", kind,
		"secret_len", len(resolved),
		"has_space", strings.ContainsAny(resolved, " \t"))
	return "", false
}
