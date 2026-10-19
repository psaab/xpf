package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// #15051 (A20-01): Junos `$9$` routing authentication keys were not
// decoded; the obfuscated blob committed strict-clean and was installed
// verbatim as the live key, so authenticated adjacencies to a real peer
// (whose key is the plaintext) never formed.
//
// The `$9$` decoder previously lived only in pkg/ipsec and was applied
// only to IKE pre-shared keys (normalizePSK, #157). This file is the
// shared copy in pkg/config: decodeJunos9AtCompile applies it to every
// Junos-reversible routing secret leaf the fix direction names — BGP
// AuthPassword, OSPF AuthKey + OSPF MD5 keys, IS-IS global/interface
// AuthKey, RIP AuthKey — in the global protocols block and every
// routing instance, before any downstream validator or renderer reads
// the value.
//
// VRRP and LDP name no decodable site at this base: VRRP
// authentication is refused at strict commit and dropped on tolerant
// load by #4288/#5834 (RFC 5798 removed VRRP authentication) before
// compilation, so no `$9$` VRRP key can be installed; LDP carries no
// authentication-key leaf in the typed config at all. If either gains
// an enforced auth leaf it must be added to the walk below.
//
// Strict commit REFUSES a malformed `$9$` value. The tolerant
// load/peer-sync paths keep the original blob and warn (#1960): a
// persisted config an older binary accepted must still boot, and the
// render belts (pkg/frr authTokenOrOmit / #14977 fail-closed sites)
// then see the undecodable blob. Decoding happens in place on the
// compiled *Config, so every renderer downstream of compile receives
// plaintext without knowing `$9$` exists, and the AST the operator
// authored is never rewritten — `show configuration` still displays
// the `$9$` form Junos displays.
//
// Portions of the $9$ decoder are adapted from the MIT-licensed
// github.com/nadddy/jcrypt project:
// MIT License — Copyright (c) 2020 nadddy. Permission is hereby
// granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without
// limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject
// to the following conditions: the above copyright notice and this
// permission notice shall be included in all copies or substantial
// portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
// WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const junos9Magic = "$9$"

var errInvalidJunos9Secret = errors.New("invalid Junos $9$ secret")

var junos9NumAlpha = []byte{}
var junos9ExtraNum = make([]int, 256)
var junos9AlphaNum = make([]int, 256)
var junos9Encoding = [][]int{{1, 4, 32}, {1, 16, 32}, {1, 8, 32}, {1, 64}, {1, 32}, {1, 4, 16, 128}, {1, 32, 64}}

func init() {
	family := [][]byte{
		[]byte("QzF3n6/9CAtpu0O"),
		[]byte("B1IREhcSyrleKvMW8LXx"),
		[]byte("7N-dVbwsY2g4oaJZGUDj"),
		[]byte("iHkq.mPf5T"),
	}
	offset := 0
	for i, bs := range family {
		junos9NumAlpha = append(junos9NumAlpha, bs...)
		for j, b := range bs {
			junos9AlphaNum[b] = offset + j
			junos9ExtraNum[b] = 3 - i
		}
		offset += len(bs)
	}
}

// DecodeJunos9Secret decodes a Junos `$9$`-obfuscated secret to its
// plaintext. A value without the `$9$` prefix is returned unchanged.
// A malformed `$9$` value returns errInvalidJunos9Secret.
func DecodeJunos9Secret(secret string) (string, error) {
	if !strings.HasPrefix(secret, junos9Magic) {
		return secret, nil
	}
	return decodeJunos9(secret)
}

func decodeJunos9(secret string) (string, error) {
	if !strings.HasPrefix(secret, junos9Magic) {
		return "", errInvalidJunos9Secret
	}
	rest := []byte(secret[len(junos9Magic):])
	if len(rest) == 0 {
		return "", errInvalidJunos9Secret
	}
	first := rest[:1]
	rest = rest[1:]
	skip := junos9ExtraNum[first[0]]
	if skip > len(rest) {
		return "", errInvalidJunos9Secret
	}
	rest = rest[skip:]
	prev := first[0]
	out := make([]byte, 0, len(rest))
	for len(rest) > 0 {
		decode := junos9Encoding[len(out)%len(junos9Encoding)]
		if len(rest) < len(decode) {
			return "", errInvalidJunos9Secret
		}
		nibble := rest[:len(decode)]
		rest = rest[len(decode):]
		gaps := make([]byte, 0, len(nibble))
		for _, nb := range nibble {
			gap, err := junos9Gap(prev, nb)
			if err != nil {
				return "", err
			}
			prev = nb
			gaps = append(gaps, gap)
		}
		out = append(out, junos9GapDecode(gaps, decode))
	}
	return string(out), nil
}

func junos9Gap(prev, next byte) (byte, error) {
	if int(prev) >= len(junos9AlphaNum) || int(next) >= len(junos9AlphaNum) {
		return 0, errInvalidJunos9Secret
	}
	if !bytes.Contains(junos9NumAlpha, []byte{prev}) || !bytes.Contains(junos9NumAlpha, []byte{next}) {
		return 0, errInvalidJunos9Secret
	}
	gap := (junos9AlphaNum[next]-junos9AlphaNum[prev])%len(junos9NumAlpha) - 1
	if gap < 0 {
		gap += len(junos9NumAlpha)
	}
	return byte(gap), nil
}

func junos9GapDecode(gaps []byte, decode []int) byte {
	num := 0
	for i := range gaps {
		num += int(gaps[i]) * decode[i]
	}
	return byte(num % 256)
}

// decodeJunos9AtCompile decodes every Junos-reversible routing
// secret leaf in cfg in place. On the strict path a malformed `$9$`
// value is a compile error naming the leaf (never the value — it is a
// secret). On the tolerant path the malformed leaf keeps its original
// blob and a warning naming the leaf is returned instead, so a
// persisted config still boots (#1960).
func decodeJunos9AtCompile(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	decode := func(scope, field string, s *Secret) error {
		if s == nil || *s == "" {
			return nil
		}
		raw := s.Reveal()
		if !strings.HasPrefix(raw, junos9Magic) {
			return nil
		}
		decoded, err := decodeJunos9(raw)
		if err != nil {
			msg := fmt.Sprintf("%s%s is a malformed Junos $9$ secret that "+
				"cannot be decoded — re-enter the key in plaintext or as a "+
				"valid $9$ value (#15051)", scope, field)
			if lenient {
				warnings = append(warnings, msg+" (downgraded to warning on tolerant path)")
				return nil
			}
			return errors.New(msg)
		}
		*s = Secret(decoded)
		return nil
	}
	// OSPF keeps a legacy single-key view (AuthKey/AuthKeyID) beside
	// AuthMD5Keys; decoding the list entry must also update the legacy
	// view so the two never diverge (the FRR renderer reads both).
	decodeOSPF := func(scope, areaID string, iface *OSPFInterface) error {
		base := fmt.Sprintf("protocols ospf area %s interface %s", areaID, iface.Name)
		for i := range iface.AuthMD5Keys {
			mfld := fmt.Sprintf("%s authentication md5 %d key", base, iface.AuthMD5Keys[i].ID)
			before := iface.AuthMD5Keys[i].Key.Reveal()
			if err := decode(scope, mfld, &iface.AuthMD5Keys[i].Key); err != nil {
				return err
			}
			if iface.AuthMD5Keys[i].ID == iface.AuthKeyID &&
				iface.AuthKey.Reveal() == before {
				iface.AuthKey = iface.AuthMD5Keys[i].Key
			}
		}
		if iface.AuthKeyID == 0 || len(iface.AuthMD5Keys) == 0 {
			return decode(scope, base+" authentication-key", &iface.AuthKey)
		}
		for i := range iface.AuthMD5Keys {
			if iface.AuthMD5Keys[i].ID == iface.AuthKeyID {
				return nil // legacy view already synced above
			}
		}
		return decode(scope, base+" authentication-key", &iface.AuthKey)
	}
	decodeProtocols := func(scope string, ospf *OSPFConfig, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface == nil {
						continue
					}
					if err := decodeOSPF(scope, area.ID, iface); err != nil {
						return err
					}
				}
			}
		}
		if bgp != nil {
			for _, n := range bgp.Neighbors {
				if n == nil {
					continue
				}
				fld := fmt.Sprintf("protocols bgp neighbor %s authentication-key", n.Address)
				if n.GroupName != "" {
					fld = fmt.Sprintf("protocols bgp group %s neighbor %s authentication-key", n.GroupName, n.Address)
				}
				if err := decode(scope, fld, &n.AuthPassword); err != nil {
					return err
				}
			}
		}
		if rip != nil {
			if err := decode(scope, "protocols rip authentication-key", &rip.AuthKey); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := decode(scope, "protocols isis authentication-key", &isis.AuthKey); err != nil {
				return err
			}
			for _, iface := range isis.Interfaces {
				if iface == nil {
					continue
				}
				fld := fmt.Sprintf("protocols isis interface %s authentication-key", iface.Name)
				if err := decode(scope, fld, &iface.AuthKey); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := decodeProtocols("", cfg.Protocols.OSPF, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return warnings, err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := decodeProtocols(scope, ri.OSPF, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}
