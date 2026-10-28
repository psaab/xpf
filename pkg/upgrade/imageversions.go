package upgrade

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// ImageVersions are the compile-time protocol/version constants a baked image's
// xpfd embeds, used by the #1930 INC-3 LANE-2 mixed-base image-replace gate to
// decide — BEFORE swapping the second HA node — whether the new image can run
// alongside the still-running peer's OLD image without dropping sessions.
//
// Two sources produce the same key=value set:
//   - `xpfd protocol-versions` run against the staged binary unpacked from the
//     new image (canonical; the binary IS the protocol).
//   - the bake `.manifest` (the bake recorded the same fields), for a pure file
//     read where running the staged binary is inconvenient (cross-arch).
type ImageVersions struct {
	XPFVersion string
	// HAProtocol is the HA/session-transfer protocol version this image SPEAKS.
	HAProtocol uint16
	// HAProtocolMinCompat is the OLDEST HA protocol version this image can still
	// interoperate with (back-compat floor). An image speaking N that can still
	// talk to N-1 sets MinCompat=N-1.
	HAProtocolMinCompat uint16
	// SessionSyncProtocol is the userspace session-sync frame/control protocol.
	SessionSyncProtocol int
	// ConfigDBEnvelope is the config-DB envelope grammar version.
	ConfigDBEnvelope int
	// ConfigDBMinReader is the minimum envelope-format version a reader must
	// support to load a DB this image writes.
	ConfigDBMinReader int

	// present tracks which fields were actually parsed (missing keys are a
	// fail-closed signal for the gate, not silent zero values).
	present map[string]bool
}

// parseImageVersions reads the `key=value` (protocol-versions) or `key: value`
// (manifest) lines into an ImageVersions. Unknown keys are ignored; the gate
// checks Has() for the fields it requires and fails closed if any is absent.
func parseImageVersions(text string) (*ImageVersions, error) {
	iv := &ImageVersions{present: map[string]bool{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k, v string
		if i := strings.IndexAny(line, "=:"); i >= 0 {
			k = strings.TrimSpace(line[:i])
			v = strings.TrimSpace(line[i+1:])
		} else {
			continue
		}
		// The manifest re-keys with underscores; accept both separators.
		k = strings.ReplaceAll(k, "_", "-")
		switch k {
		case "xpf-version":
			iv.XPFVersion = v
			iv.present[k] = true
		case "ha-protocol-version":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.HAProtocol = uint16(n)
				iv.present[k] = true
			}
		case "ha-protocol-min-compat":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.HAProtocolMinCompat = uint16(n)
				iv.present[k] = true
			}
		case "session-sync-protocol-version":
			// Parse as unsigned 16-bit, matching the on-wire constant
			// (cluster.SessionSyncWireVersion is a uint16) AND the Python gate's
			// _u16() — a signed strconv.Atoi here would accept a negative value
			// that the Python gate rejects (fail-closed), and a peer reporting
			// e.g. -1 against a new image also at -1 would falsely pass the
			// exact-match check (Go/Python parity bypass; r4 Codex HIGH).
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.SessionSyncProtocol = int(n)
				iv.present[k] = true
			}
		case "configdb-envelope-version":
			// Unsigned for the same Go/Python parity reason (kept symmetric with
			// session-sync even though config-DB versions are informational for
			// the HA gate today).
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.ConfigDBEnvelope = int(n)
				iv.present[k] = true
			}
		case "configdb-min-reader-version":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.ConfigDBMinReader = int(n)
				iv.present[k] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan protocol versions: %w", err)
	}
	return iv, nil
}

// has reports whether the named key was parsed.
func (iv *ImageVersions) has(key string) bool { return iv.present[key] }

// requiredKeys are the fields the mixed-base gate must see to make a decision.
// Config-DB versions are informational for the HA gate (the replaced node
// re-bootstraps its DB from text), so they are NOT required here.
var requiredKeys = []string{
	"ha-protocol-version",
	"ha-protocol-min-compat",
	"session-sync-protocol-version",
}

// UnknownWirePolicy decides what an unknown (0) peer session-sync wire
// version means. It is the ONLY behavioural difference between the two
// live lanes; everything else in the rule is shared.
type UnknownWirePolicy int

const (
	// RefuseUnknownWire fails closed on peer wire 0: the LANE-2
	// image-replace gate (scripts/deploy/xpf-deploy.py:_gate_mixed_base)
	// cannot prove a pre-advertisement peer's frames will decode.
	RefuseUnknownWire UnknownWirePolicy = iota
	// PermitUnknownWire permits peer wire 0 (a pre-#7990 peer that does not
	// advertise): refusing would block every LANE-1 roll from such a
	// release. Deliberate since #14991 (docs/log/14991.md).
	PermitUnknownWire
)

// ProtocolCompatVerdict is the outcome of GateProtocolCompat.
type ProtocolCompatVerdict struct {
	// Compatible is true only when the target's HA + session-sync
	// protocols are back-compatible with the still-running peer, so the
	// mixed-base cluster keeps syncing sessions across the failover.
	Compatible bool
	// Reason is a human-readable explanation (always set when Err is nil).
	Reason string
	// Err is non-nil when the check itself cannot run (no target, or the
	// target cannot prove its own constants) — never a judgement about
	// the peer. A caller that must fail closed treats Err as a refusal.
	Err error
}

// GateProtocolCompat is the single Go rule deciding whether `target` (the
// binary/image that will run after the cut) can preserve sessions while the
// peer still runs the old build advertising `peerHA` / `peerWire`. It is
// fail-closed: any missing field or out-of-window protocol returns
// Compatible=false.
//
// Back-compat rule: sessions survive iff the peer's HA protocol lies within
// the target's [HAProtocolMinCompat, HAProtocol] window AND the session-sync
// wire matches EXACTLY (the userspace frame format is not versioned for
// skew — a mismatch means the target cannot decode the peer's synced
// sessions). Peer HA 0 (not advertising) always refuses. Peer wire 0 is
// governed by `unknownWire` (see UnknownWirePolicy).
//
// This is the documented source of truth for the rule. Executors:
//   - LANE-1 (in-place rolling): targetWireVerdict in rolling.go, an
//     adapter passing PermitUnknownWire.
//   - LANE-2 (image-replace): scripts/deploy/xpf-deploy.py
//     _gate_mixed_base, the Python executor passing RefuseUnknownWire.
//
// The Go and Python bodies are pinned against each other by
// scripts/deploy/mixed_base_gate_fixture.json (#17091), consumed by both
// TestMixedBaseGateFixture17091 (Go) and MixedBaseFixture17091Tests
// (Python). Edit the fixture and BOTH executors together.
func GateProtocolCompat(target *ImageVersions, peerHA, peerWire uint16, unknownWire UnknownWirePolicy) ProtocolCompatVerdict {
	if target == nil {
		return ProtocolCompatVerdict{Err: fmt.Errorf("target binary protocol versions unavailable — the staged-target compatibility check cannot run")}
	}
	for _, k := range requiredKeys {
		if !target.has(k) {
			return ProtocolCompatVerdict{Err: fmt.Errorf("target binary protocol versions missing %q — the staged-target compatibility check cannot run", k)}
		}
	}
	if peerHA == 0 {
		return ProtocolCompatVerdict{Reason: "peer HA protocol unknown (peer not advertising) — fail closed"}
	}
	if peerHA < target.HAProtocolMinCompat || peerHA > target.HAProtocol {
		return ProtocolCompatVerdict{Reason: fmt.Sprintf(
			"peer HA protocol %d outside target window [%d,%d] — not back-compatible; "+
				"use image-replace (replace BOTH nodes, sessions drop)",
			peerHA, target.HAProtocolMinCompat, target.HAProtocol)}
	}
	if peerWire == 0 {
		if unknownWire == PermitUnknownWire {
			return ProtocolCompatVerdict{Compatible: true, Reason: "peer advertises no session-sync wire version (predates #7990) — permitted against the target binary"}
		}
		return ProtocolCompatVerdict{Reason: "peer session-sync protocol unknown — fail closed (replace both nodes, sessions drop)"}
	}
	if int(peerWire) != target.SessionSyncProtocol {
		return ProtocolCompatVerdict{Reason: fmt.Sprintf(
			"target session-sync wire version %d differs from peer %d — after the cut the target could not decode the peer's synced sessions; use image-replace (replace BOTH nodes, sessions drop)",
			target.SessionSyncProtocol, peerWire)}
	}
	return ProtocolCompatVerdict{Compatible: true, Reason: fmt.Sprintf(
		"target binary HA protocol %d (compat floor %d) accepts peer %d; session-sync %d matches — "+
			"mixed-base swap preserves sessions",
		target.HAProtocol, target.HAProtocolMinCompat, peerHA, target.SessionSyncProtocol)}
}
