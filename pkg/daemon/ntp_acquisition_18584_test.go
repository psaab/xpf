package daemon

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func ntpRICfg18584(ri ...string) *config.Config {
	cfg := &config.Config{}
	// vrf-mgmt exists only with a management-class interface configured.
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"fxp0": {}}
	cfg.System.NTPServerOptions = map[string]config.NTPServerOption{}
	for i, r := range ri {
		addr := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}[i]
		cfg.System.NTPServers = append(cfg.System.NTPServers, addr)
		cfg.System.NTPServerOptions[addr] = config.NTPServerOption{RoutingInstance: r}
	}
	return cfg
}

// #18584: `routing-instance mgmt` on every server binds chrony's NTP client
// sockets to the management VRF; anything chrony cannot express renders nothing.
func TestRenderChronyAcquisition18584(t *testing.T) {
	if got := renderChronyAcquisition(ntpRICfg18584("mgmt", "mgmt")); !strings.Contains(got, "\nbindacqdevice vrf-mgmt\n") {
		t.Fatalf("mgmt servers: got %q, want a bindacqdevice vrf-mgmt line", got)
	}
	for name, cfg := range map[string]*config.Config{
		"default instance": ntpRICfg18584("", ""),
		"mixed":            ntpRICfg18584("mgmt", ""),
		"unknown":          ntpRICfg18584("nosuch"),
		"no servers":       {},
		"nil":              nil,
	} {
		if got := renderChronyAcquisition(cfg); got != "" {
			t.Errorf("%s: got %q, want no binding", name, got)
		}
	}
	noMgmt := ntpRICfg18584("mgmt")
	noMgmt.Interfaces.Interfaces = nil
	if got := renderChronyAcquisition(noMgmt); got != "" {
		t.Errorf("no management interface (no vrf-mgmt): got %q, want no binding", got)
	}
	cfg := ntpRICfg18584("blue")
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "virtual-router"}}
	if got := renderChronyAcquisition(cfg); !strings.Contains(got, "\nbindacqdevice vrf-blue\n") {
		t.Fatalf("virtual-router instance: got %q, want bindacqdevice vrf-blue", got)
	}
}

// #18584: the binding is written to its own conf.d file and rides the conf.d
// (restart) leg, and the first binding apply of every daemon process restarts
// chrony even when the file is already on disk — chronyd may have started
// before the VRF it binds to existed. Once that restart succeeded, an
// unchanged apply restarts nothing.
func TestApplySystemNTPAcquisitionBinding18584(t *testing.T) {
	d, calls, setOutcome := chronyDaemon6800(t)
	cfg := ntpRICfg18584("mgmt")

	d.applySystemNTP(cfg)
	data, err := os.ReadFile(chronyAcquisitionPath)
	if err != nil || !strings.Contains(string(data), "bindacqdevice vrf-mgmt") {
		t.Fatalf("acquisition file = %q, %v; want bindacqdevice vrf-mgmt", data, err)
	}
	if got, want := calls(), [][2]bool{{true, true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first apply reload requests = %v, want %v (sources + conf.d restart)", got, want)
	}

	d.applySystemNTP(cfg)
	if got := len(calls()); got != 1 {
		t.Fatalf("an unchanged apply after a successful restart must not reload again; requests=%v", calls())
	}

	// A new daemon process over the same on-disk files: nothing changed on
	// disk, but chrony must still be restarted once.
	d2 := &Daemon{}
	d2.applySystemNTP(cfg)
	if got := calls(); len(got) != 2 || got[1] != [2]bool{false, true} {
		t.Fatalf("first apply of a new process must restart chrony once; requests=%v", got)
	}

	// A failed restart is retried: the conf.d leg's reload debt (#6800)
	// replays it on the next apply.
	d3 := &Daemon{}
	setOutcome(chronyReloadOutcome{thresholdFailed: true})
	d3.applySystemNTP(cfg)
	setOutcome(chronyReloadOutcome{})
	d3.applySystemNTP(cfg)
	if got := calls(); len(got) != 4 || got[3][1] != true {
		t.Fatalf("a failed restart must be retried by the next apply; requests=%v", got)
	}

	// Dropping the routing-instance removes the binding and restarts chrony.
	d.applySystemNTP(ntpRICfg18584(""))
	if _, err := os.Stat(chronyAcquisitionPath); !os.IsNotExist(err) {
		t.Fatalf("acquisition file must be removed when no instance is honoured; stat err=%v", err)
	}
	if got := calls(); got[len(got)-1][1] != true {
		t.Fatalf("removing the binding must take the conf.d restart leg; requests=%v", got)
	}
}

// #18584 over-reach guard: a default-instance NTP config never writes the
// acquisition file and never takes the restart leg for it.
func TestApplySystemNTPDefaultInstanceWritesNoBinding18584(t *testing.T) {
	d, calls, _ := chronyDaemon6800(t)
	d.applySystemNTP(ntpRICfg18584(""))
	if _, err := os.Stat(chronyAcquisitionPath); !os.IsNotExist(err) {
		t.Fatalf("default-instance NTP must not write the acquisition file; stat err=%v", err)
	}
	if got, want := calls(), [][2]bool{{true, false}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reload requests = %v, want %v (sources only)", got, want)
	}
}

// #18584: `system processes ntp disable` removes every xpf chrony file,
// including the binding, and takes the conf.d restart leg for it.
func TestApplySystemNTPDisabledRemovesBinding18584(t *testing.T) {
	d, calls, _ := chronyDaemon6800(t)
	d.applySystemNTP(ntpRICfg18584("mgmt"))
	if _, err := os.Stat(chronyAcquisitionPath); err != nil {
		t.Fatalf("precondition: binding written: %v", err)
	}
	off := ntpRICfg18584("mgmt")
	off.System.DisabledProcesses = []string{"ntp"}
	d.applySystemNTP(off)
	if _, err := os.Stat(chronyAcquisitionPath); !os.IsNotExist(err) {
		t.Fatalf("disabled NTP must remove the binding; stat err=%v", err)
	}
	if got := calls(); got[len(got)-1][1] != true {
		t.Fatalf("removing the binding must take the conf.d restart leg; requests=%v", got)
	}
}
