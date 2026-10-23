package ipsec

import (
	"encoding/base64"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// This file isolates the Junos $9$ pre-shared-key decryption surface so the
// decryption logic can be audited and unit-tested independently of swanctl
// config generation and XFRM netlink bindings (#1989). Do not add unrelated
// config-rendering helpers here.
//
// #15051 moved the `$9$` decoder itself into pkg/config
// (config.DecodeJunos9Secret) so the same decoder applies at compile to
// every Junos-reversible routing secret leaf as well as IKE PSKs.
// normalizePSK remains the IKE call shape: decode a
// `$9$` value, pass anything else through verbatim, error on malformed
// — including a `$9$` value that decodes to zero bytes (#15990), so a
// decoded-empty PSK can never reach `secret = ""`.

func normalizePSK(secret string) (string, error) {
	return config.DecodeJunos9Secret(secret)
}

// validHexPSKRender reports whether s can render as a swanctl hex
// secret (`secret = 0x<s>`) (#15027): non-empty, even length, hex
// digits only. It mirrors pkg/config's compile-time check so a
// directly constructed or peer-synced config that bypassed the
// strict commit gate is still fenced at render. encoding/hex is
// already imported by policy.go's package; this file stays free of
// rendering helpers beyond the PSK predicates per its header — the
// check is a PSK-validity predicate, not a rendering helper.
func validHexPSKRender(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// asciiValueCollidesWithSwanctlEncoding reports whether an ASCII PSK
// value would be re-decoded by swanctl's secret loader instead of
// reaching charon as its literal bytes (#15991 fold). The loader
// (strongSwan 6.1.0 `load_creds.c` load_secret, the same code on
// master) receives the settings value with quotes already stripped
// by the settings lexer, then:
//
//	if (strcasepfx(value, "0x"))      data = chunk_from_hex(value+2)
//	else if (strcasepfx(value, "0s")) data = chunk_from_base64(value+2)
//	else                              data = chunk_from_str(value)
//
// Quoting is purely lexical — `"0x61626364"` and `0x61626364` load
// identically. Verified live against charon 6.1.0 (two-daemon lab,
// docs/log/15991.md): quoted `"0x61626364"` authenticates against a
// peer holding the hex-decoded bytes `abcd`, not against a peer
// holding the literal string. The check is case-insensitive on the
// first two bytes only, matching strcasepfx.
func asciiValueCollidesWithSwanctlEncoding(v string) bool {
	if len(v) < 2 || v[0] != '0' {
		return false
	}
	return v[1] == 'x' || v[1] == 'X' || v[1] == 's' || v[1] == 'S'
}

// swanctlSecretToken is the loader-facing token for one PSK element:
// a hex-authored value keeps its `0x<hex>` token (#15027); an ASCII
// value that collides with the loader's `0x`/`0s` decoding is
// base64-armored as `0s<base64 of the literal bytes>` so charon
// recovers exactly the authored string; any other ASCII value is
// itself. Base64 output contains no comma, quote, backslash or
// control byte, so armoring also removes those bytes from the token
// (the surrounding render still sanitizes/escapes the joined value).
func swanctlSecretToken(pv pskValue) string {
	if pv.hex {
		return "0x" + pv.value
	}
	if asciiValueCollidesWithSwanctlEncoding(pv.value) {
		return "0s" + base64.StdEncoding.EncodeToString([]byte(pv.value))
	}
	return pv.value
}

// swanctlSecretRendered is the value charon must receive for a
// connection's PSK set, before the renderer's sanitize/escape pass:
// a lone ASCII value renders its token directly; a grouped set
// (#15024) is the comma-joined member tokens that the existing
// render wraps in one quoted string. Per-element armoring is what
// keeps a colliding ASCII member (and a hex member beside it)
// loadable from that single string — the pre-fold renderer emitted
// the ASCII bytes bare, so a grouped `"0x61626364,other"` loaded
// with its first element hex-re-decoded (or, for a non-hex tail,
// failed chunk_from_hex on the whole joined value).
func swanctlSecretRendered(values []pskValue) string {
	if len(values) == 1 {
		return swanctlSecretToken(values[0])
	}
	parts := make([]string, len(values))
	for i, pv := range values {
		parts[i] = swanctlSecretToken(pv)
	}
	return strings.Join(parts, ",")
}
