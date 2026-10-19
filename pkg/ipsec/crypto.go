package ipsec

import (
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
// `$9$` value, pass anything else through verbatim, error on malformed.

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
