package config

import (
	"fmt"
	"sort"
	"strings"
)

// appendDPDThresholdIKEv2AdvisoryLocked adds the #15025 (A16-02)
// commit-time advisory for an IKE gateway that sets an explicit DPD
// `threshold` while it can negotiate IKEv2.
//
// Mechanism: deriveDPD (pkg/ipsec/ike.go) renders
// `dpd_timeout = interval × threshold`, but strongSwan honours
// dpd_timeout for IKEv1 only — the generated swanctl.conf template
// itself documents it as "Timeout for DPD checks (IKEV1 only)". On
// IKEv2, DPD (RFC 7296 §2.4 liveness checks, driven by dpd_delay)
// declares a dead peer only after charon's global retransmission
// budget (charon.retransmit_timeout/base/tries, ≈165s with stock
// defaults) is exhausted, so interval × threshold has no effect
// there. A gateway with no `version` pin negotiates IKEv2 by
// default (the renderer emits `version` only for v1-only/v2-only),
// and a v2-only gateway is IKEv2-only, so on both shapes the
// operator's threshold was silently inert — a dead tunnel was held
// ~27× longer than configured in the validating report.
//
// Why an advisory rather than programming charon's retransmit
// settings: retransmit_timeout/base/tries are daemon-global in
// strongswan.conf, not per-connection, so one gateway's tight DPD
// would change retransmission behaviour for every IKE SA (and the
// initial IKE_SA_INIT exchange) on the box, and the tightest-of-N
// gateways would silently override the rest. The issue accepts the
// advisory as the alternative fix.
//
// Scope: only an EXPLICIT threshold (DPDThreshold > 0) on a
// DPD-enabled gateway that is not v1-only warns. The compiled
// gateway does not record whether threshold was explicit versus the
// deriveDPD default (5), and DPDThreshold is only populated by
// parseDeadPeerDetectionNode from the `threshold` leaf (0 when the
// leaf is absent), so DPDThreshold > 0 is exactly "operator set
// threshold". A v1-only gateway honours dpd_timeout and stays
// silent; a gateway with no threshold leaf never set the inert knob.
//
// A WARNING, never an error, on the strict path: the config is legal
// and IKEv1 peers still honour it. `opts.suppressDPDThresholdIKEv2Advisory`
// silences it on the TOLERANT paths (Store.Load boot, Store.SyncApply
// peer sync) so it does not repeat on every boot of an
// already-committed config (#8357 doctrine).
func appendDPDThresholdIKEv2AdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressDPDThresholdIKEv2Advisory {
		return
	}
	var names []string
	for name, gw := range cfg.Security.IPsec.Gateways {
		if gw == nil {
			continue
		}
		if !gw.DPDEnable && gw.DeadPeerDetect == "" {
			continue
		}
		if gw.DPDThreshold <= 0 {
			continue
		}
		if gw.Version == "v1-only" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
		"security ike gateway %s dead-peer-detection threshold is effective "+
			"for IKEv1 only: strongSwan honours dpd_timeout (interval x "+
			"threshold) on IKEv1, while on IKEv2 — negotiated by default "+
			"when no version is pinned, and the only version on a v2-only "+
			"gateway — a dead peer is declared only after charon's global "+
			"retransmission budget is exhausted, so the configured "+
			"threshold does not shorten IKEv2 dead-peer detection; pin "+
			"`version v1-only` if threshold-based detection is required "+
			"(#15025)",
		strings.Join(names, ", ")))
}
