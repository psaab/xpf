package frr

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19083: in cluster mode a static route may not resolve its next hop through
// a BLACKHOLE route.
//
// Why: after a graceful HA stop (or a planned move away) the node's VIPs are
// gone, and an owned static's gateway (on the RETH subnet) then resolves
// recursively through the cluster Null0 default (renderClusterModeDefaults):
// FRR installed it as an ACTIVE kernel blackhole that redistribution exported
// from a node that forwards nothing (#19083, measured on loss). Nothing is
// written at shutdown; instead the render binds staticd's next-hop tracking
// to a route-map that denies resolution through any blackhole next hop, so the
// static goes inactive by itself the moment its gateway's connected route
// leaves.
//
// FRR mechanism (read at tag frr-10.5.1, zebra/zebra_rnh.c and
// zebra_routemap.c): zebra applies a client protocol's NHT route-map to a COPY
// of the route resolving the next hop (copy_state, which copies the nexthop
// group but NOT the tag — a `match tag 2500` map can never match); `match ip|
// ipv6 next-hop type blackhole` compares the resolving route's nexthop type
// (NEXTHOP_TYPE_BLACKHOLE); a deny marks the client's resolution filtered and
// staticd installs no path. Premise cells on udp (FRR 10.5.1): bound over
// existing statics, the blackhole-only ones were withdrawn and `(filtered)`
// within 3 s while one resolving through a real interface route stayed; a
// static whose gateway route then LEFT (the graceful-stop shape) was withdrawn
// within 3 s. docs/log/19083.md has the cells.
//
// Scope: cluster mode only (the cluster default and VIP ownership are cluster
// constructs), the DEFAULT VRF only (the top-level binding is per VRF and the
// cluster defaults exist only in the default VRF; VRF statics are unchanged),
// and staticd only (BGP and every other NHT client are untouched). Recursion
// through a real gateway route — a real default included, #12613's contract —
// is unchanged. A static whose gateway resolves only through an operator
// discard/reject or a generate-route aggregate also goes inactive: that
// agrees with the userspace helper, whose recursion already returns no target
// on a discard/reject row, and with Junos (the next hop is unreachable); the
// compiler warns about that pattern (validateStaticDiscardAnchorWarnings19083).
//
// Residual: zebra answers a NEWLY registering client without applying the map
// (zebra_add_rnh_client), so a static that registers while its gateway
// already resolves only through a blackhole is unfiltered until the next NHT
// event for that next hop. ReevaluateStaticNHT19083 forces one (after a
// demotion's VIP removal); FRR restarting without xpfd, and a registration
// racing the shutdown VIP removal (which runs after frr.Stop), stay residual.

const (
	// clusterStaticNHTRouteMap19083 is the bound map. The reserved
	// ReservedRedistSuffix keeps operator policy names out of it (strict
	// commit refuses the suffix; the tolerant path is fenced by the final-
	// name belt, emittedRouteMapFinalCollision16867).
	clusterStaticNHTRouteMap19083 = "xpf-static-nht" + config.ReservedRedistSuffix
	// clusterStaticNHTRouteMapAlt19083 is an identical, normally unbound map.
	// Rebinding to it and back forces zebra to re-evaluate every static next
	// hop without an unbound window (ip_nht_rm_add evaluates only when the
	// bound NAME changes; unbinding would re-install the filtered statics
	// for a moment).
	clusterStaticNHTRouteMapAlt19083 = "xpf-static-nht-b" + config.ReservedRedistSuffix
	// staticNHTReevalTimeout19083 bounds the rebind batch.
	staticNHTReevalTimeout19083 = 5 * time.Second
)

func clusterStaticNHTMapBody19083(name string) string {
	n := frrName(name)
	return fmt.Sprintf("route-map %s deny 10\n match ip next-hop type blackhole\nexit\n"+
		"route-map %s deny 20\n match ipv6 next-hop type blackhole\nexit\n"+
		"route-map %s permit 30\nexit\n", n, n, n)
}

// staticNHTBindLines19083 are the two bindings of name, v4 then v6.
func staticNHTBindLines19083(name string) []string {
	n := frrName(name)
	return []string{"ip nht static route-map " + n, "ipv6 nht static route-map " + n}
}

// renderClusterStaticNHT19083 renders both maps and binds staticd's v4 and v6
// next-hop tracking to the primary one. Cluster mode only.
func renderClusterStaticNHT19083(fc *FullConfig) string {
	if fc == nil || !fc.ClusterMode {
		return ""
	}
	var b strings.Builder
	b.WriteString(clusterStaticNHTMapBody19083(clusterStaticNHTRouteMap19083))
	b.WriteString(clusterStaticNHTMapBody19083(clusterStaticNHTRouteMapAlt19083))
	b.WriteString("!\n")
	for _, l := range staticNHTBindLines19083(clusterStaticNHTRouteMap19083) {
		b.WriteString(l + "\n")
	}
	b.WriteString("!\n")
	return b.String()
}

// vtyshConfigExecutor19083 runs a batch of configuration lines in one vtysh
// configuration session.
type vtyshConfigExecutor19083 interface {
	VtyshConfigLines(ctx context.Context, lines []string) ([]byte, error)
}

// ReevaluateStaticNHT19083 forces zebra to re-evaluate every static next hop
// against the #19083 map, closing the fresh-registration bypass for statics
// that registered since the last NHT event (see the file comment). It binds
// the identical alternate map and then the primary again, so the running
// config ends as frr.conf renders it. It runs under reloadMu like every FRR
// writer, never touches confGen/writeGen, and is a no-op when the managed
// section as last written does not bind the map (not cluster mode) or the
// manager is stopping.
func (m *Manager) ReevaluateStaticNHT19083() error {
	ex, ok := m.executor().(vtyshConfigExecutor19083)
	if !ok {
		return nil
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.lifetimeCtx().Err() != nil {
		return nil
	}
	data, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !strings.Contains(string(data), staticNHTBindLines19083(clusterStaticNHTRouteMap19083)[0]+"\n") {
		return nil
	}
	lines := append(staticNHTBindLines19083(clusterStaticNHTRouteMapAlt19083),
		staticNHTBindLines19083(clusterStaticNHTRouteMap19083)...)
	ctx, cancel := context.WithTimeout(m.lifetimeCtx(), staticNHTReevalTimeout19083)
	defer cancel()
	if out, err := ex.VtyshConfigLines(ctx, lines); err != nil {
		return fmt.Errorf("re-evaluate static NHT (#19083): %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// VtyshConfigLines runs one vtysh process:
// `vtysh -c "configure terminal" -c <line>... -c end`. The caller's ctx carries
// the bound; cancelling it SIGKILLs the process group, as for frr-reload.py.
// vtysh can exit 0 after FRR rejected a line in a multi -c batch, so a `% `
// diagnostic in the output is reported as an error.
func (realExecutor) VtyshConfigLines(ctx context.Context, lines []string) ([]byte, error) {
	args := []string{"-c", "configure terminal"}
	for _, l := range lines {
		args = append(args, "-c", l)
	}
	args = append(args, "-c", "end")
	cmd := exec.CommandContext(ctx, vtyshBinary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("vtysh configure (%d lines): %w", len(lines), err)
	}
	if bytes.Contains(out, []byte("% ")) {
		return out, fmt.Errorf("vtysh configure (%d lines): FRR reported an error", len(lines))
	}
	return out, nil
}
