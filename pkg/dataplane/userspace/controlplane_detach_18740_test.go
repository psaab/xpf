package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #18740, acceptance half. With em0 and fxp0 kept out of the compile's attach
// set, the links the compile does attach are exactly the ingress set, so the
// acceptance reconcile has nothing to detach on an unchanged commit.

func snapshot18740(rows ...InterfaceSnapshot) *ConfigSnapshot {
	return &ConfigSnapshot{Interfaces: rows}
}

var (
	dataRow18740 = InterfaceSnapshot{Name: "ge-0-0-9", Zone: "trust", Ifindex: 18741}
	ctrlRow18740 = InterfaceSnapshot{Name: "em0", Zone: "control", Ifindex: 18742}
	mgmtRow18740 = InterfaceSnapshot{Name: "fxp0", Zone: "mgmt", Ifindex: 18743}
)

func recordDetaches18740(t *testing.T) *[]int {
	t.Helper()
	var detaches []int
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, _ bool) (bool, error) {
		if op == "detach" {
			detaches = append(detaches, ifindex)
		}
		return false, nil // observe only: the real DetachXDP runs
	}))
	return &detaches
}

func TestUnchangedCommitsDetachNothing18740(t *testing.T) {
	m := New()
	detaches := recordDetaches18740(t)
	snap := snapshot18740(dataRow18740, ctrlRow18740, mgmtRow18740)
	// What the compile leaves attached: the dataplane link only.
	m.bpfShim.SetLinkForTest(dataRow18740.Ifindex, &reconcilerLink10519{}, nil)

	for i := 0; i < 20; i++ {
		if err := m.syncInterfaceAttachments(&dataplane.CompileResult{}, snap); err != nil {
			t.Fatalf("commit %d: syncInterfaceAttachments: %v", i+1, err)
		}
	}
	if len(*detaches) != 0 {
		t.Fatalf("20 unchanged commits detached %v; an unchanged commit must make no XDP "+
			"transition (#18740)", *detaches)
	}
	if _, ok := m.bpfShim.XDPLinks()[dataRow18740.Ifindex]; !ok {
		t.Fatal("the dataplane link was lost across unchanged commits")
	}

	// CONTROL, the pre-#18740 shape: a control-link shim the compile attached
	// is detached at acceptance. That transient is what the fix removes at the
	// source, so the reconcile must still clean one up (a build upgraded from
	// one that attached it, or a link adopted from a pin).
	m.bpfShim.SetLinkForTest(ctrlRow18740.Ifindex, &reconcilerLink10519{}, nil)
	if err := m.syncInterfaceAttachments(&dataplane.CompileResult{}, snap); err != nil {
		t.Fatalf("control commit: %v", err)
	}
	if want := []int{ctrlRow18740.Ifindex}; !reflect.DeepEqual(*detaches, want) {
		t.Fatalf("control: detached %v, want %v", *detaches, want)
	}

	// TWIN: a real zone change that takes the dataplane link out of the
	// ingress set still detaches it.
	*detaches = nil
	if err := m.syncInterfaceAttachments(&dataplane.CompileResult{}, snapshot18740(ctrlRow18740, mgmtRow18740)); err != nil {
		t.Fatalf("zone-change commit: %v", err)
	}
	if want := []int{dataRow18740.Ifindex}; !reflect.DeepEqual(*detaches, want) {
		t.Fatalf("zone change: detached %v, want %v", *detaches, want)
	}
}

// The two halves must agree in the direction that matters: a name the compile
// keeps out of the attach set must be one the ingress set excludes too.
// Otherwise an adjudicated interface would be left with no shim and the
// helper could not bind it. The fxp/em ingress classes are single-sourced
// from dataplane.ControlPlaneNetdevNameClass; this pins that they still are.
func TestControlPlaneAttachExclusionIsAnIngressExclusion18740(t *testing.T) {
	for _, name := range []string{
		"fxp0", "fxp0.0", "fxp1", "em0", "em0.100", "em1",
		"ge-0-0-0", "ge-7-0-2", "reth0", "fab0", "lo0", "gr-0-0-0",
	} {
		row := InterfaceSnapshot{Name: name, Zone: "z"}
		class, controlPlane := dataplane.ControlPlaneNetdevNameClass(name)
		got := userspaceNetdevExclusionClass(row)
		if controlPlane && got != class {
			t.Errorf("%s: the compile keeps it out of the attach set (%s) but the ingress "+
				"exclusion class is %q; an interface with no shim must not be adjudicated", name, class, got)
		}
		if !controlPlane && (got == "fxp name" || got == "em name") {
			t.Errorf("%s: ingress class %q without the matching attach-set exclusion", name, got)
		}
	}
}
