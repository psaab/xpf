package dataplane

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestClassifyRxVlanStagHwParse_10915(t *testing.T) {
	queryErr := errors.New("ethtool query failed")
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want RxVlanStagHwParseState
	}{
		{name: "absent", out: "rx-checksumming: on\n", want: RxVlanStagHwParseAbsent},
		{name: "off", out: "rx-vlan-stag-hw-parse: off\n", want: RxVlanStagHwParseOff},
		{name: "off fixed", out: "rx-vlan-stag-hw-parse: off [fixed]\n", want: RxVlanStagHwParseOff},
		{name: "on", out: "rx-vlan-stag-hw-parse: on\n", want: RxVlanStagHwParseNeedsDisable},
		{name: "on fixed", out: "rx-vlan-stag-hw-parse: on [fixed]\n", want: RxVlanStagHwParseNeedsDisable},
		{name: "unknown query", err: queryErr, want: RxVlanStagHwParseNeedsDisable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyRxVlanStagHwParse([]byte(tc.out), tc.err); got != tc.want {
				t.Fatalf("ClassifyRxVlanStagHwParse() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEnsureRxVlanStagHwParse_10915(t *testing.T) {
	t.Run("absent off and fixed do not toggle", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			out  string
		}{
			{name: "absent", out: "rx-vlan-offload: off\nrx-checksumming: on\n"},
			{name: "off", out: "rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"},
			{name: "off fixed", out: "rx-vlan-stag-hw-parse: off [fixed]\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				calls := 0
				mockEthtool(t, func(args ...string) ([]byte, error) {
					calls++
					if len(args) != 2 || args[0] != "-k" || args[1] != "ge-0-0-0" {
						t.Fatalf("safe/absent feature must not be toggled: ethtool %v", args)
					}
					return []byte(tc.out), nil
				})
				rxErr, stagErr := newRxVlanResult().ensureRxVlanParsePreconditions("ge-0-0-0")
				if rxErr != nil || stagErr != nil {
					t.Fatalf("safe/absent features returned errors: rx=%v stag=%v", rxErr, stagErr)
				}
				if calls != 1 {
					t.Fatalf("ethtool calls = %d, want one state query", calls)
				}
			})
		}
	})

	t.Run("on S-tag offload is disabled", func(t *testing.T) {
		var calls [][]string
		mockEthtool(t, func(args ...string) ([]byte, error) {
			calls = append(calls, append([]string(nil), args...))
			if len(args) > 0 && args[0] == "-k" {
				return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil
			}
			if len(args) == 4 && args[0] == "-K" && args[1] == "ge-0-0-0" &&
				args[2] == "rx-vlan-stag-hw-parse" && args[3] == "off" {
				return nil, nil
			}
			t.Fatalf("unexpected ethtool invocation: %v", args)
			return nil, nil
		})
		r := newRxVlanResult()
		rxErr, stagErr := r.ensureRxVlanParsePreconditions("ge-0-0-0")
		if rxErr != nil || stagErr != nil {
			t.Fatalf("successful S-tag disable returned errors: rx=%v stag=%v", rxErr, stagErr)
		}
		if len(calls) != 2 || calls[1][2] != "rx-vlan-stag-hw-parse" || !r.rxTagStripOffCache["ge-0-0-0"] {
			t.Fatalf("S-tag disable calls/cache = %v / %v, want one S-tag -K and confirmed cache", calls, r.rxTagStripOffCache)
		}
	})

	t.Run("failed S-tag disable is returned and not cached", func(t *testing.T) {
		wantErr := errors.New("ethtool refused S-tag disable")
		mockEthtool(t, func(args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-k" {
				return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil
			}
			return []byte("Operation not supported"), wantErr
		})
		r := newRxVlanResult()
		rxErr, stagErr := r.ensureRxVlanParsePreconditions("ge-0-0-0")
		if rxErr != nil || !errors.Is(stagErr, wantErr) {
			t.Fatalf("failed S-tag disable errors = rx:%v stag:%v, want only wrapped S-tag error", rxErr, stagErr)
		}
		if r.rxTagStripOffCache["ge-0-0-0"] {
			t.Fatal("partial disable failure must not cache both tag-strip preconditions as confirmed")
		}
	})

	t.Run("unknown state attempts both disables", func(t *testing.T) {
		stagErr := errors.New("S-tag disable refused")
		var calls [][]string
		mockEthtool(t, func(args ...string) ([]byte, error) {
			calls = append(calls, append([]string(nil), args...))
			if len(args) > 0 && args[0] == "-k" {
				return nil, errors.New("query unavailable")
			}
			if len(args) == 4 && args[2] == "rxvlan" {
				return nil, nil
			}
			if len(args) == 4 && args[2] == "rx-vlan-stag-hw-parse" {
				return []byte("refused"), stagErr
			}
			t.Fatalf("unexpected ethtool invocation: %v", args)
			return nil, nil
		})
		rxErr, gotStagErr := newRxVlanResult().ensureRxVlanParsePreconditions("ge-0-0-0")
		if rxErr != nil || !errors.Is(gotStagErr, stagErr) {
			t.Fatalf("unknown-state disable errors = rx:%v stag:%v, want S-tag failure only", rxErr, gotStagErr)
		}
		if len(calls) != 3 || calls[1][2] != "rxvlan" || calls[2][2] != "rx-vlan-stag-hw-parse" {
			t.Fatalf("unknown state must query then attempt both disables, got %v", calls)
		}
	})
}

func TestRxVlanStagHwParseActivationError_10915(t *testing.T) {
	if err := rxVlanStagHwParseActivationError("ge-0-0-0", nil); err != nil {
		t.Fatalf("no disable failure must not fail activation: %v", err)
	}
	cause := errors.New("disable failed")
	err := rxVlanStagHwParseActivationError("ge-0-0-0", cause)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "S-tag HW-parse offload could not be disabled") {
		t.Fatalf("S-tag activation error = %v, want scoped wrapped failure", err)
	}
}

// This binds the real compileZones call-site on a parent with NO configured
// 802.1Q VLAN subinterfaces. The separate #5268 C-tag gate tolerates a plain
// parent; #10915 must still fail closed because its in-frame S-tag drop is
// load-bearing on every XDP-adjudicated parent.
func TestRxVlanStagHwParseFailClosedWiredIntoCompile_10915(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil
		case "-K":
			if len(args) == 4 && args[2] == "rx-vlan-stag-hw-parse" {
				return []byte("not supported"), errors.New("ethtool refused S-tag disable")
			}
		}
		return nil, errors.New("unexpected ethtool invocation")
	})

	cfg := cfgVlanParentInZone()
	cfg.Interfaces.Interfaces["ge-0-0-0"].VlanTagging = false
	cfg.Interfaces.Interfaces["ge-0-0-0"].Units = map[int]*config.InterfaceUnit{
		0: {Number: 0, VlanID: 0},
	}
	result := &CompileResult{
		ZoneIDs:             map[string]uint16{"trust": 1},
		ScreenIDs:           make(map[string]uint16),
		rxTagStripOffCache:  make(map[string]bool),
		ifCache:             make(map[string]*net.Interface),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
	result.ifCache["ge-0-0-0"] = &net.Interface{Index: 4242, Name: "ge-0-0-0"}
	result.ifCache["ge-0-0-1"] = &net.Interface{Index: 4243, Name: "ge-0-0-1"}

	err := compileZones(compileRxVlanTestDP{stopIfindex: 4243}, cfg, result)
	if err == nil || !strings.Contains(err.Error(), "S-tag HW-parse offload could not be disabled") {
		t.Fatalf("compileZones must fail closed on S-tag disable failure for a plain parent; got %v", err)
	}
}
