package rpm

import (
	"github.com/psaab/xpf/pkg/config"
)

// scopeHTTPTargetZone12908 resolves the IPv6 link-local zone of an http-get
// target literal and returns the target rewritten to carry it.
//
// #9026 wrote the shared link-local guard for probeICMP and probeTCP; the
// http-get path was never given it (#12908). An http-get target carries its
// host inside a URL in either form — bare (fe80::1%ge-0/0/3), schemeless
// bracketed ([fe80::1%25ge-0/0/3]:8443) or schemed (http://[fe80::1]/hb) — so
// the probeTCP parse (split the raw target at '%') cannot see it:
// net.ParseIP("http://[fe80::1]/") is nil and the guard was skipped. An
// unscoped literal then reached http.Client, whose dial fails with a plain
// error, which this package counts as PATH LOSS (SuccFail++, state
// transition, `services ip-monitoring` failover) — for a probe that never
// left the box, the #1960 hold-state doctrine inverted.
//
// config.FindTargetIPLiteral finds the literal in every form — the SAME
// extraction the commit-time gate uses, so what strict commit rejects and
// what this runtime guard holds can never drift apart again. A scopeless
// link-local yields ErrProbeSetup (the test HOLDS, mirroring a leniently
// loaded icmp/tcp test); a scoped one is rewritten with the resolved KERNEL
// zone in RFC 6874 %25 form (config.LinuxIfName normalization inside
// resolveLinkLocalZone9026 turns ge-0/0/3 into ge-0-0-3), preserving scheme,
// userinfo, port and path — which also repairs a target whose Junos slash
// zone could never have dialed. Non-literal and non-link-local hosts pass
// through untouched.
func (m *Manager) scopeHTTPTargetZone12908(target, destinationInterface string) (string, error) {
	ip, zone, litStart, litEnd := config.FindTargetIPLiteral(target)
	if ip == nil {
		return target, nil
	}
	resolved, zerr := m.resolveLinkLocalZone9026("http-get", ip, zone, destinationInterface)
	if zerr != nil {
		return "", zerr
	}
	if resolved == "" {
		return target, nil
	}
	return target[:litStart] + "[" + ip.String() + "%25" + resolved + "]" + target[litEnd:], nil
}
