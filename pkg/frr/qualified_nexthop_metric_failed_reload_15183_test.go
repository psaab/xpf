package frr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// qnhFailedReloadExecutor15183 models the ospfd route-map state across
// the #15183 failure: frr-reload.py --reload deletes lines that are not
// in frr.conf (the memory-only `set metric N` QNH overlay) BEFORE it
// hits the line FRR rejects, then exits non-zero. A config load
// therefore replaces the daemon state with the metric-free file state
// even when the reload reports failure.
type qnhFailedReloadExecutor15183 struct {
	maps map[string]map[int]r9RouteMapRule

	failReload   bool
	reloadErr    error
	vtyshLoadErr error
	daemonErr    error
	reloadCalls  int
	daemonLoads  int
}

func (e *qnhFailedReloadExecutor15183) applyConfig(text string, replace bool) {
	if replace || e.maps == nil {
		e.maps = make(map[string]map[int]r9RouteMapRule)
	}
	var routeMap, verb string
	var sequence int
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "no" && fields[1] == "route-map" {
			if seq, err := strconv.Atoi(fields[4]); err == nil {
				delete(e.maps[fields[2]], seq)
			}
			continue
		}
		if len(fields) == 4 && fields[0] == "route-map" {
			parsed, err := strconv.Atoi(fields[3])
			if err != nil {
				routeMap = ""
				continue
			}
			routeMap, verb, sequence = fields[1], fields[2], parsed
			if e.maps[routeMap] == nil {
				e.maps[routeMap] = make(map[int]r9RouteMapRule)
			}
			if _, ok := e.maps[routeMap][sequence]; !ok {
				e.maps[routeMap][sequence] = r9RouteMapRule{verb: verb}
			}
			continue
		}
		if routeMap == "" {
			continue
		}
		rule := e.maps[routeMap][sequence]
		rule.verb = verb
		if len(fields) == 3 && fields[0] == "set" && fields[1] == "metric" {
			if value, err := strconv.Atoi(fields[2]); err == nil {
				rule.metric, rule.hasMetric = value, true
			}
		}
		if len(fields) == 3 && fields[0] == "no" && fields[1] == "set" && fields[2] == "metric" {
			rule.metric, rule.hasMetric = 0, false
		}
		e.maps[routeMap][sequence] = rule
	}
}

func (e *qnhFailedReloadExecutor15183) metric(routeMap string, sequence int) (int, bool) {
	rule, ok := e.maps[routeMap][sequence]
	if !ok || !rule.hasMetric {
		return 0, false
	}
	return rule.metric, true
}

func (e *qnhFailedReloadExecutor15183) Vtysh(context.Context, string) (string, error) {
	return "", nil
}

func (e *qnhFailedReloadExecutor15183) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// FrrReloadPy simulates frr-reload.py: it converges the daemon toward
// the metric-free file (deleting the memory-only overlay) and only then
// reports the rejected line.
func (e *qnhFailedReloadExecutor15183) FrrReloadPy(_ context.Context, conf string) error {
	e.reloadCalls++
	data, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	e.applyConfig(string(data), true)
	if e.failReload {
		return e.reloadErr
	}
	return nil
}

func (e *qnhFailedReloadExecutor15183) VtyshLoad(_ context.Context, conf string) ([]byte, error) {
	if e.vtyshLoadErr != nil {
		return nil, e.vtyshLoadErr
	}
	data, err := os.ReadFile(conf)
	if err != nil {
		return nil, err
	}
	e.applyConfig(string(data), false)
	return nil, nil
}

func (e *qnhFailedReloadExecutor15183) VtyshLoadDaemon(_ context.Context, _, conf string) ([]byte, error) {
	if e.daemonErr != nil {
		return nil, e.daemonErr
	}
	data, err := os.ReadFile(conf)
	if err != nil {
		return nil, err
	}
	e.daemonLoads++
	e.applyConfig(string(data), false)
	return nil, nil
}

func (e *qnhFailedReloadExecutor15183) VtyshDaemon(_ context.Context, _, command string) ([]byte, error) {
	name := strings.TrimPrefix(command, "show route-map ")
	var b strings.Builder
	sequences := make([]int, 0, len(e.maps[name]))
	for sequence := range e.maps[name] {
		sequences = append(sequences, sequence)
	}
	sort.Ints(sequences)
	for _, sequence := range sequences {
		rule := e.maps[name][sequence]
		fmt.Fprintf(&b, "%s, sequence %d Invoked 0 (0 milliseconds total)\n Set clauses:\n", rule.verb, sequence)
		if rule.hasMetric {
			fmt.Fprintf(&b, "  metric %d\n", rule.metric)
		}
	}
	return []byte(b.String()), nil
}

func qnhFailedReloadFixture15183(t *testing.T) (*Manager, *qnhFailedReloadExecutor15183, *FullConfig, string) {
	t.Helper()
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
		"set protocols ospf export static",
	)
	fc := &FullConfig{
		OSPF:          compiled.Protocols.OSPF,
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		PolicyOptions: &compiled.PolicyOptions,
	}
	rendered, overlays := New().buildManagedSectionWithQNH11447(fc)
	var routeMap string
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute static route-map ") {
			routeMap = strings.TrimPrefix(line, "redistribute static route-map ")
			break
		}
	}
	if routeMap == "" || !strings.Contains(overlays["ospfd"], "set metric 10\n") {
		t.Fatalf("fixture must render a QNH route-map and ospfd overlay:\n%s\n%v", rendered, overlays)
	}
	exec := &qnhFailedReloadExecutor15183{reloadErr: errors.New("frr-reload.py rejected a line")}
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	m.exec = exec
	m.DisableDegradedRetry()
	t.Cleanup(m.Stop)
	return m, exec, fc, routeMap
}

func wantQNHMetric15183(t *testing.T, exec *qnhFailedReloadExecutor15183, routeMap string) {
	t.Helper()
	if metric, ok := exec.metric(routeMap, 10); !ok || metric != 10 {
		t.Fatalf("ospfd route-map %s sequence 10 metric = %d, %v; want 10, true (overlay lost on failed reload)", routeMap, metric, ok)
	}
}

// TestQNHMetricSurvivesHardReloadFailure15183 pins C04-01 arm 1: both
// frr-reload.py and the additive vtysh -f fallback fail after
// frr-reload.py already deleted the memory-only overlay. The hard
// failure must still restore the overlay (readback-verified) while
// propagating the original failure.
func TestQNHMetricSurvivesHardReloadFailure15183(t *testing.T) {
	m, exec, fc, routeMap := qnhFailedReloadFixture15183(t)
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("initial ApplyFull: %v", err)
	}
	wantQNHMetric15183(t, exec, routeMap)

	vtyshErr := errors.New("vtysh -f rejected a line")
	exec.failReload = true
	exec.vtyshLoadErr = vtyshErr
	err := m.ApplyFull(fc)
	if err == nil || errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("hard-failure ApplyFull error = %v, want a non-degraded hard failure", err)
	}
	if !errors.Is(err, vtyshErr) || !errors.Is(err, exec.reloadErr) {
		t.Fatalf("hard-failure error = %v, want both vtysh and primary causes preserved", err)
	}
	wantQNHMetric15183(t, exec, routeMap)

	// A reconcile failure on the failure path is joined to the original
	// error, never swapped for it or swallowed.
	daemonErr := errors.New("ospfd overlay load refused")
	exec.daemonErr = daemonErr
	err = m.ApplyFull(fc)
	if !errors.Is(err, vtyshErr) || !errors.Is(err, daemonErr) {
		t.Fatalf("joined hard-failure error = %v, want vtysh and overlay causes", err)
	}
}

// TestQNHMetricSurvivesFailedDegradedRetry15183 pins C04-01 arm 2: a
// degraded-retry attempt whose frr-reload.py fails (again deleting the
// overlay first) must restore the overlay even though the episode has
// not converged.
func TestQNHMetricSurvivesFailedDegradedRetry15183(t *testing.T) {
	m, exec, fc, routeMap := qnhFailedReloadFixture15183(t)
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("initial ApplyFull: %v", err)
	}
	wantQNHMetric15183(t, exec, routeMap)

	// Enter the degraded state through the additive fallback (control:
	// the fallback-success path already reconciles today).
	exec.failReload = true
	if err := m.ApplyFull(fc); !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("degraded ApplyFull error = %v, want ErrFRRReloadDegraded", err)
	}
	wantQNHMetric15183(t, exec, routeMap)

	if stop, notFound := m.retryReloadOnce(context.Background()); stop || notFound {
		t.Fatalf("failed retry result = (%v, %v), want (false, false)", stop, notFound)
	}
	wantQNHMetric15183(t, exec, routeMap)
	if !m.ReloadDegraded() {
		t.Fatal("failed retry must leave the manager degraded (no convergence claimed)")
	}

	// Control: once the primary reload succeeds again the retry
	// converges, clears the degraded state, and keeps the metric.
	exec.failReload = false
	if stop, notFound := m.retryReloadOnce(context.Background()); !stop || notFound {
		t.Fatalf("converging retry result = (%v, %v), want (true, false)", stop, notFound)
	}
	wantQNHMetric15183(t, exec, routeMap)
}
