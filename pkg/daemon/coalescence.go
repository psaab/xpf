// mlx5 interrupt-coalescence tuning (#801).
//
// Phase B Step 0 found that mlx5 NICs on the userspace-dp path boot
// with adaptive coalescing enabled (driver default). That raises the
// effective rx-usecs at low PPS — so the per-packet latency is larger
// than the operator set with rx-usecs=8. This file wires a per-mlx5
// ethtool invocation to disable adaptive coalescing and pin rx-usecs /
// tx-usecs to the operator's value (default 8).
//
// The same allowlist + driver guard as D3 (rss_indirection.go) applies:
// only mlx5_core interfaces that userspace-dp will bind AF_XDP on are
// touched; virtio/iavf/i40e are skipped silently. This is the #797 H1
// invariant carried forward — we never invoke ethtool on a netdev xpf
// does not own.
//
// We reuse the rssExecutor interface so tests don't have to stub a
// second copy of ethtool/sysfs. The method set there is already
// runEthtool + readDriver + listInterfaces — exactly what coalescence
// needs.
//
// The daemon calls this from the same two sites as D3:
//  1. enumerateAndRenameInterfaces() at startup — before XSK bind.
//  2. applyConfig() at commit — idempotent via ethtool -c probe.
package daemon

import (
	"bufio"
	"bytes"
	"log/slog"
	"strconv"
	"strings"
)

// applyCoalescence disables mlx5 adaptive coalescing and pins rx-usecs
// / tx-usecs on every userspace-dp-bound mlx5 interface.
//
// Semantics mirror applyRSSIndirection:
//   - `adaptiveEnable == true`: operator explicitly re-enabled adaptive.
//     We RESTORE adaptive-rx/tx=on. rx-usecs / tx-usecs become a
//     ceiling rather than a fixed value but the kernel manages them.
//   - `adaptiveEnable == false`: disable adaptive, pin rx-usecs / tx-usecs.
//   - Empty allowlist: no-op.
//   - Non-mlx5 iface in allowlist: skip (Codex H1 invariant).
//   - ethtool missing: log + skip gracefully (same as D3).
//   - Idempotent: ethtool -c probe first, skip write if the live values
//     already match.
//
// Never returns an error — coalescence regressions must not break
// interface bring-up.
//
// `capture` may be nil. When non-nil, the pre-xpfd adaptive + rx/tx-usecs
// state of each mlx5 iface is stored on first apply so restore-on-disable
// (B2) can revert to the operator's original values rather than the
// kernel's compiled defaults.
func applyCoalescence(adaptiveEnable bool, rxUsecs, txUsecs int, allowed []string, execer rssExecutor, capture *priorHostTunables) {
	if len(allowed) == 0 {
		slog.Debug("linksetup: coalescence skip (empty allowlist)")
		return
	}
	if rxUsecs <= 0 {
		rxUsecs = defaultCoalesceRX
	}
	if txUsecs <= 0 {
		txUsecs = defaultCoalesceTX
	}
	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		drv := execer.readDriver(iface)
		if drv != mlx5Driver {
			slog.Debug("linksetup: coalescence skip (non-mlx5)",
				"iface", iface, "driver", drv)
			continue
		}
		applyCoalescenceOne(iface, adaptiveEnable, rxUsecs, txUsecs, execer, capture)
	}
}

// applyCoalescenceOne writes the requested coalescence state to one
// mlx5 interface. Errors are logged and swallowed.
//
// Separate function (instead of inline loop body) so the per-iface
// flow can be unit-tested against a single fake executor entry.
func applyCoalescenceOne(iface string, adaptiveEnable bool, rxUsecs, txUsecs int, execer rssExecutor, capture *priorHostTunables) {
	// Defense in depth: re-check driver at the per-iface level so a
	// future caller can't accidentally invoke ethtool on a non-mlx5
	// netdev (parallels rss_indirection's pattern).
	if drv := execer.readDriver(iface); drv != mlx5Driver {
		slog.Debug("linksetup: coalescence skip (non-mlx5 per-iface)",
			"iface", iface, "driver", drv)
		return
	}
	probe, err := execer.runEthtool("-c", iface)
	if err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, coalescence not applied",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -c failed, skipping coalescence",
			"iface", iface, "err", err, "output", strings.TrimSpace(string(probe)))
		return
	}

	liveRX, liveTX, liveAdaptRX, liveAdaptTX, parsed := parseEthtoolCoalesce(probe)
	if parsed {
		// Capture pre-xpfd state on the first apply so restore-on-disable
		// can revert to exactly what the operator had before xpfd wrote.
		capture.captureMlx5Coalesce(iface, mlx5CoalesceState{
			adaptiveRX: liveAdaptRX,
			adaptiveTX: liveAdaptTX,
			rxUsecs:    liveRX,
			txUsecs:    liveTX,
		})
	}
	if !parsed {
		// Couldn't parse any of the fields we care about — still try
		// the write, since the alternative is silent divergence from
		// the declared config. The write's CombinedOutput will give
		// us a real error if something is truly wrong.
		slog.Warn("linksetup: coalescence probe unparseable, writing blindly",
			"iface", iface)
	} else if coalescenceMatches(adaptiveEnable, rxUsecs, txUsecs,
		liveAdaptRX, liveAdaptTX, liveRX, liveTX) {
		slog.Debug("linksetup: coalescence unchanged",
			"iface", iface, "adaptive", adaptiveEnable,
			"rx_usecs", rxUsecs, "tx_usecs", txUsecs)
		return
	}
	// MIN1: drift detection — live values differ from desired and
	// from what we captured on first apply.
	if capture != nil && parsed {
		if prior, ok := capture.mlx5Adaptive[iface]; ok {
			driftRX := prior.rxUsecs != liveRX && liveRX != rxUsecs
			driftTX := prior.txUsecs != liveTX && liveTX != txUsecs
			driftAdapt := (prior.adaptiveRX != liveAdaptRX || prior.adaptiveTX != liveAdaptTX) &&
				(liveAdaptRX != adaptiveEnable || liveAdaptTX != adaptiveEnable)
			if driftRX || driftTX || driftAdapt {
				slog.Warn("linksetup: coalescence drift detected; overwriting",
					"iface", iface,
					"captured_prior_rx_usecs", prior.rxUsecs,
					"captured_prior_tx_usecs", prior.txUsecs,
					"live_rx_usecs", liveRX, "live_tx_usecs", liveTX,
					"writing_rx_usecs", rxUsecs, "writing_tx_usecs", txUsecs)
			}
		}
	}

	adapt := "off"
	if adaptiveEnable {
		adapt = "on"
	}
	args := []string{
		"-C", iface,
		"adaptive-rx", adapt,
		"adaptive-tx", adapt,
		"rx-usecs", strconv.Itoa(rxUsecs),
		"tx-usecs", strconv.Itoa(txUsecs),
	}
	if out, err := execer.runEthtool(args...); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, coalescence not applied",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -C failed",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("linksetup: coalescence applied",
		"iface", iface, "adaptive", adaptiveEnable,
		"rx_usecs", rxUsecs, "tx_usecs", txUsecs)
}

// parseEthtoolCoalesce extracts the four fields applyCoalescenceOne
// cares about from `ethtool -c` output. The format is:
//
//	Coalesce parameters for ge-0-0-1:
//	Adaptive RX: on  TX: on
//	...
//	rx-usecs: 8
//	...
//	tx-usecs: 8
//
// Returns (rxUsecs, txUsecs, adaptiveRX, adaptiveTX, parsed). parsed
// is true if we found at least one of rx-usecs / tx-usecs (i.e. the
// output at least resembled what we expect).
func parseEthtoolCoalesce(out []byte) (rxUsecs, txUsecs int, adaptRX, adaptTX bool, parsed bool) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	// #5250 (A7-b1 F1): bufio.Scanner's default 64 KiB line cap turns a single
	// over-long line into a SILENT truncation of the rest of the output — the
	// remaining fields would read as absent and the live/desired comparison
	// would decide "mismatch" on a partial parse, rewriting coalescence on
	// every commit. Raise the cap and, if the scan still errors, report
	// parsed=false so the caller writes blindly (its documented fail-safe)
	// instead of comparing against half-read values.
	scanner.Buffer(make([]byte, 0, 64*1024), ethtoolCoalesceMaxLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// The "Adaptive RX: on TX: on" line uses a single colon after
		// "Adaptive RX" and embeds both axes. Handle it specially.
		if strings.HasPrefix(line, "Adaptive RX:") {
			// Forms seen in practice:
			//   "Adaptive RX: on  TX: on"
			//   "Adaptive RX: off  TX: off"
			// Split on whitespace and pull the value after each
			// token — this is resilient to column-alignment changes
			// in future ethtool releases.
			fields := strings.Fields(line)
			for i := 0; i < len(fields)-1; i++ {
				switch fields[i] {
				case "RX:":
					adaptRX = fields[i+1] == "on"
					parsed = true
				case "TX:":
					adaptTX = fields[i+1] == "on"
					parsed = true
				}
			}
			continue
		}
		// "rx-usecs: 8" and "tx-usecs: 8" (no leading whitespace after
		// TrimSpace).
		if v, ok := parseLabelledInt(line, "rx-usecs:"); ok {
			rxUsecs = v
			parsed = true
			continue
		}
		if v, ok := parseLabelledInt(line, "tx-usecs:"); ok {
			txUsecs = v
			parsed = true
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("linksetup: ethtool -c output scan failed, treating probe as unparseable",
			"err", err)
		return 0, 0, false, false, false
	}
	return rxUsecs, txUsecs, adaptRX, adaptTX, parsed
}

// ethtoolCoalesceMaxLine is the per-line ceiling for the `ethtool -c` probe
// scan. Real output lines are a few dozen bytes; 1 MiB is far past any
// plausible driver verbosity while still bounding the read.
const ethtoolCoalesceMaxLine = 1 << 20

// parseLabelledInt returns the integer value that follows label in
// line, or (0, false) if the line doesn't start with label. Tolerates
// trailing garbage on the line (ethtool occasionally emits comments).
func parseLabelledInt(line, label string) (int, bool) {
	if !strings.HasPrefix(line, label) {
		return 0, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, label))
	// Grab only the first whitespace-delimited token — guards against
	// "rx-usecs: 8 (factory default)" style output.
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// coalescenceMatches returns true if the live ethtool values already
// reflect the desired state. Saves a write and avoids spurious NIC
// churn on every reconcile.
func coalescenceMatches(wantAdaptive bool, wantRX, wantTX int,
	liveAdaptRX, liveAdaptTX bool, liveRX, liveTX int) bool {
	if liveAdaptRX != wantAdaptive || liveAdaptTX != wantAdaptive {
		return false
	}
	// When adaptive is enabled, rx-usecs / tx-usecs become ceilings
	// that the kernel adjusts dynamically — the live read may differ
	// from the operator's ceiling. We still compare exactly because
	// the write sets both the adaptive flag AND the ceiling in one
	// ethtool call; a mismatch on either means a rewrite is useful.
	if liveRX != wantRX || liveTX != wantTX {
		return false
	}
	return true
}

