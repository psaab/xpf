package frr

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// #9493: render-side belts for operands the commit gate now validates. The
// commit gate (pkg/config schema validators) runs on commit and commit-check
// only, so a value persisted or peer-synced before it existed still reaches
// this renderer. These keep such a value from putting a line FRR rejects into
// the managed section, where one rejected line fails the whole reload.

// frrClampInt bounds an integer operand to FRR's accepted maximum. Clamping,
// not omission, is deliberate: an over-large OSPF cost or multihop TTL clamped
// to the ceiling keeps the operator's intent (a very high cost, a far peer),
// while omitting it would fall back to FRR's default and pull traffic onto the
// link or drop the session.
func frrClampInt(operand string, v, max int) int {
	if v <= max {
		return v
	}
	slog.Warn("frr: clamping an out-of-range integer operand (#9493)",
		"operand", operand, "value", v, "max", max)
	return max
}

// frrOperandOrOmit reports whether a string operand is a single FRR token, and
// warns naming the operand when it is not. The caller omits the line.
func frrOperandOrOmit(operand, v string) bool {
	if config.FRRSingleToken(v) {
		return true
	}
	slog.Warn("frr: omitting a line whose operand is not a single vtysh token (#9493)",
		"operand", operand, "value", sanitizeFRRValue(v))
	return false
}

// frrName returns an FRR object name (route-map, prefix-list, community-list,
// as-path access-list) as ONE token.
//
// A name FRR can carry is returned unchanged, so every existing render is
// byte-identical. #16867: a single-token name over FRR's 128-byte YANG
// `list-name` bound (FRRNameMaxLen) is NOT carried unchanged — FRR rejects
// the leaf yet leaves a half-built match-condition node that aborts the
// routing daemons on the next `show running-config` — so it takes the
// alias below too, with its fragment truncated to keep the alias within
// the bound. A name the commit gate now refuses, persisted or peer-synced
// before the gate existed, carries whitespace, and FRR splits it into extra
// arguments. Skipping such a line is not safe here, because omitting a
// `neighbor ... route-map ... out` REMOVES the outbound filter. So it is rendered
// under a deterministic alias instead: the sanitizeFRRIdent fragment plus a hash
// of the full name. The hash is what keeps `a b` and `a_b` apart. Every
// definition AND reference site calls this on the same final string, so they
// always agree. The alias carries config.FRRNameEscapeMarker, which the
// commit gate reserves (ValidateFRRObjectName rejects it), so no committed
// operator name can be spelled identically to another name's alias;
// frrNameAliasCollision fails the apply closed when a tolerant-path
// config still carries such a pair.
func frrName(name string) string {
	if config.FRRSingleToken(name) && len(name) <= config.FRRNameMaxLen {
		return name
	}
	// #16867: an OVERLONG single-token name takes the same alias. The
	// fragment is bounded so fragment + "-xpfesc-" + 8 hex stays within
	// FRRNameMaxLen; the hash of the FULL name keeps two long names that
	// share the truncated fragment apart, and definition and reference
	// sites agree because both call frrName on the same final string.
	frag := sanitizeFRRIdent(name)
	suffix := config.FRRNameEscapeMarker
	if max := config.FRRNameMaxLen - len(suffix) - 8; len(frag) > max {
		frag = frag[:max]
	}
	sum := sha256.Sum256([]byte(name))
	return frag + suffix + hex.EncodeToString(sum[:4])
}
