package frr

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type r9RouteMapRule struct {
	verb      string
	metric    int
	hasMetric bool
}

type r9StateExecutor struct {
	maps        map[string]map[int]r9RouteMapRule
	globalLoads []string
}

func (e *r9StateExecutor) applyConfig(text string, replace bool) {
	if replace || e.maps == nil {
		e.maps = make(map[string]map[int]r9RouteMapRule)
	}
	var routeMap, verb string
	var sequence int
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "no" && fields[1] == "route-map" && len(fields) == 5 {
			seq, err := strconv.Atoi(fields[4])
			if err == nil {
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

func (e *r9StateExecutor) Vtysh(context.Context, string) (string, error) { return "", nil }
func (e *r9StateExecutor) FrrReloadPy(_ context.Context, conf string) error {
	data, err := os.ReadFile(conf)
	if err == nil {
		e.applyConfig(string(data), true)
	}
	return err
}
func (e *r9StateExecutor) VtyshLoad(_ context.Context, conf string) ([]byte, error) {
	data, err := os.ReadFile(conf)
	if err == nil {
		text := string(data)
		e.globalLoads = append(e.globalLoads, text)
		e.applyConfig(text, false)
	}
	return nil, err
}
func (e *r9StateExecutor) VtyshLoadDaemon(_ context.Context, _, conf string) ([]byte, error) {
	data, err := os.ReadFile(conf)
	if err == nil {
		e.applyConfig(string(data), false)
	}
	return nil, err
}
func (e *r9StateExecutor) VtyshDaemon(_ context.Context, _, command string) ([]byte, error) {
	const prefix = "show route-map "
	name := strings.TrimPrefix(command, prefix)
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
func (e *r9StateExecutor) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

func r9AddLegacyOverlay(section, overlay string) string {
	var routeMap string
	var sequence int
	for _, line := range strings.Split(overlay, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[0] == "route-map" {
			sequence, _ = strconv.Atoi(fields[3])
			routeMap = fields[1]
			continue
		}
		if routeMap == "" || len(fields) != 3 || fields[0] != "set" || fields[1] != "metric" {
			continue
		}
		needle := fmt.Sprintf("route-map %s permit %d\n", routeMap, sequence)
		position := strings.Index(section, needle)
		if position < 0 {
			panic("overlay sequence absent from rendered config: " + needle)
		}
		position += len(needle)
		section = section[:position] + " set metric " + fields[2] + "\n" + section[position:]
	}
	return section
}

func TestQNHMetricAuthoredMetricSurvivesQNHRemoval11447(t *testing.T) {
	commands := func(two bool) []string {
		base := []string{
			"set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.10 metric 10",
			"set protocols ospf export EXPORT-STATIC",
			"set policy-options policy-statement EXPORT-STATIC term STATIC from protocol static",
			"set policy-options policy-statement EXPORT-STATIC term STATIC then metric 100",
			"set policy-options policy-statement EXPORT-STATIC term STATIC then accept",
		}
		if two {
			base = append(base, "set routing-options static route 198.51.100.0/24 qualified-next-hop 192.0.2.20 metric 20")
		}
		return base
	}
	oldSection, oldOverlays := qnhMetricRenderAndOverlays11447(t, commands(true)...)
	newSection, newOverlays := qnhMetricRenderAndOverlays11447(t, commands(false)...)
	const routeMap = "xpf-qnh-policy-54f103d2d65f8a5a-xpf-redist"
	if !strings.Contains(oldSection, "route-map "+routeMap+" permit 30\n set metric 100") ||
		!strings.Contains(newSection, "route-map "+routeMap+" permit 20\n set metric 100") {
		t.Fatalf("probe render did not place the authored metric at old seq 30 then new seq 20\nold:\n%s\nnew:\n%s", oldSection, newSection)
	}
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			prior := oldSection
			if legacy {
				for _, overlay := range oldOverlays {
					prior = r9AddLegacyOverlay(prior, overlay)
				}
			}
			path := filepath.Join(t.TempDir(), "frr.conf")
			config := "log syslog informational\n" + markerBegin + "\n" + prior + "\n" + markerEnd + "\n"
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			exec := &r9StateExecutor{}
			manager := New()
			manager.frrConf = path
			manager.exec = exec
			manager.DisableDegradedRetry()
			t.Cleanup(manager.Stop)
			if err := manager.commitManagedSection(newSection, newOverlays); err != nil {
				t.Fatalf("commitManagedSection: %v", err)
			}
			actions := qnhMetricActionsFromShow11447(mustR9Show(t, exec, routeMap))
			if got := actions[20]; len(got) != 1 || got[0] != 100 {
				t.Fatalf("authored metric at reused sequence 20 = %v, want [100]", got)
			}
			if legacy {
				if len(exec.globalLoads) != 1 {
					t.Fatalf("legacy load count = %d, want one post-load cleanup", len(exec.globalLoads))
				}
				cleanup := exec.globalLoads[0]
				if !strings.Contains(cleanup, "route-map "+routeMap+" permit 10\n no set metric\n") {
					t.Fatalf("legacy same-sequence generated QNH metric was not cleared:\n%s", cleanup)
				}
				if strings.Contains(cleanup, "route-map "+routeMap+" permit 20\n no set metric\n") {
					t.Fatalf("cleanup cleared the current authored metric at reused sequence 20:\n%s", cleanup)
				}
			}
		})
	}
}

func TestQNHMetricCleanupPreservesCurrentAuthoredDenySequence11447(t *testing.T) {
	const routeMap = "xpf-qnh-policy-deny-r9-xpf-redist"
	section := "! xpf managed config - do not edit\n" +
		"route-map " + routeMap + " permit 10\n" +
		" match ip address prefix-list xpf-qnh-dst-r9\n" +
		" match ip next-hop prefix-list xpf-qnh-nh-r9\n" +
		"exit\n" +
		"route-map " + routeMap + " deny 20\n" +
		" set metric 100\n" +
		"exit\n"
	path := filepath.Join(t.TempDir(), "frr.conf")
	config := "log syslog informational\n" + markerBegin + "\n" + section + markerEnd + "\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	exec := &r9StateExecutor{}
	exec.applyConfig(section, true)
	manager := New()
	manager.frrConf = path
	manager.exec = exec
	manager.qnhMetricOverlayCleanup = newQNHMetricSequenceSet11447()
	manager.qnhMetricOverlayCleanup.add(routeMap, 20)
	manager.DisableDegradedRetry()
	t.Cleanup(manager.Stop)

	manager.reloadMu.Lock()
	err := manager.reconcileQNHMetricOverlaysLocked(context.Background())
	manager.reloadMu.Unlock()
	if err != nil {
		t.Fatalf("reconcileQNHMetricOverlaysLocked: %v", err)
	}
	if rule, ok := exec.maps[routeMap][20]; !ok || rule.verb != "deny" {
		t.Fatalf("current authored deny sequence was removed by stale cleanup: %+v", exec.maps[routeMap])
	}
}

func mustR9Show(t *testing.T, exec *r9StateExecutor, routeMap string) []byte {
	t.Helper()
	out, err := exec.VtyshDaemon(context.Background(), "ospfd", "show route-map "+routeMap)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
