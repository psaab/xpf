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
// byte-identical. A name the commit gate now refuses, persisted or peer-synced
// before the gate existed, carries whitespace, and FRR splits it into extra
// arguments. Skipping such a line is not safe here, because omitting a
// `neighbor ... route-map ... out` REMOVES the outbound filter. So it is rendered
// under a deterministic alias instead: the sanitizeFRRIdent fragment plus a hash
// of the full name. The hash is what keeps `a b` and `a_b` apart. Every
// definition AND reference site calls this on the same final string, so they
// always agree.
func frrName(name string) string {
	if config.FRRSingleToken(name) {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return sanitizeFRRIdent(name) + "-xpfesc-" + hex.EncodeToString(sum[:4])
}
