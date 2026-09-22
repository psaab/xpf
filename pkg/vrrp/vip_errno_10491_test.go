package vrrp

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// annotatedErr10491 models a netlink error whose outer text is an ext-ack/TLV
// message while preserving the kernel errno in its unwrap chain.
type annotatedErr10491 struct {
	cause error
	text  string
}

func (e annotatedErr10491) Error() string { return e.text }
func (e annotatedErr10491) Unwrap() error { return e.cause }

func newVIPErrnoInstance10491(t *testing.T, name string) (*vrrpInstance, chan VRRPEvent) {
	t.Helper()
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           1,
		Priority:          100,
		Family:            "inet",
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: name}, eventCh, nil)
	vi.linkByNameFn = func(n string) (netlink.Link, error) {
		return fiveZeroEightTwoLink(n), nil
	}
	vi.addrDelFn = func(netlink.Link, *netlink.Addr) error { return nil }
	return vi, eventCh
}

func addVIPErrno10491(t *testing.T, injected error) vipActuationResult {
	t.Helper()
	vi, _ := newVIPErrnoInstance10491(t, "xpf-10491-add")
	vi.addrAddFn = func(netlink.Link, *netlink.Addr) error { return injected }
	vi.vipMu.Lock()
	res := vi.addVIPsLocked()
	vi.vipMu.Unlock()
	return res
}

func removeVIPErrno10491(t *testing.T, injected error) error {
	t.Helper()
	vi, _ := newVIPErrnoInstance10491(t, "xpf-10491-remove")
	vi.addrDelFn = func(netlink.Link, *netlink.Addr) error { return injected }
	vi.vipMu.Lock()
	err := vi.removeVIPsLocked(nil)
	vi.vipMu.Unlock()
	return err
}


func TestVIPAddErrnoClassification_10491(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantApplied bool
	}{
		{
			name:        "eexist-errno",
			err:         syscall.Errno(unix.EEXIST),
			wantApplied: true,
		},
		{
			name: "eexist-annotated-tlv",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EEXIST),
				text:  "NLMSGERR_ATTR_MSG: duplicate address",
			},
			wantApplied: true,
		},
		{
			name:        "eexist-pinned-netlink-shape",
			err:         fmt.Errorf("%w: %s", syscall.Errno(unix.EEXIST), "NLMSGERR_ATTR_MSG: duplicate"),
			wantApplied: true,
		},
		{
			name:        "file-exists-string-fallback",
			err:         errors.New("file exists"),
			wantApplied: true,
		},
		{
			name:        "bare-exists-non-eexist",
			err:         errors.New("interface exists but is down"),
			wantApplied: false,
		},
		{
			name:        "eaddrnotavail-errno",
			err:         syscall.Errno(unix.EADDRNOTAVAIL),
			wantApplied: false,
		},
		{
			name: "eaddrnotavail-annotated",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EADDRNOTAVAIL),
				text:  "NLMSGERR_ATTR_MSG: address rejected",
			},
			wantApplied: false,
		},
		{
			name:        "eperm-errno",
			err:         syscall.Errno(unix.EPERM),
			wantApplied: false,
		},
		{
			name: "eperm-annotated",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EPERM),
				text:  "NLMSGERR_ATTR_MSG: address rejected",
			},
			wantApplied: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := addVIPErrno10491(t, tc.err)
			if got := len(res.applied) == 1; got != tc.wantApplied {
				t.Fatalf("applied = %v, want %v (result: %+v)", got, tc.wantApplied, res)
			}
			if got := res.ok(); got != tc.wantApplied {
				t.Fatalf("ok() = %v, want %v (result: %+v)", got, tc.wantApplied, res)
			}
			if tc.wantApplied && len(res.failed) != 0 {
				t.Fatalf("failed = %v, want none", res.failed)
			}
			if !tc.wantApplied && len(res.failed) != 1 {
				t.Fatalf("failed = %v, want one VIP", res.failed)
			}
		})
	}
}

func TestVIPAddOwnershipGate_10491(t *testing.T) {
	vi, eventCh := newVIPErrnoInstance10491(t, "xpf-10491-gate")
	vi.setState(StateBackup)
	vi.suppressGARP.Store(true)
	vi.addrAddFn = func(netlink.Link, *netlink.Addr) error {
		return annotatedErr10491{
			cause: syscall.Errno(unix.EEXIST),
			text:  "NLMSGERR_ATTR_MSG: duplicate address",
		}
	}

	if !vi.becomeMaster() {
		t.Fatal("becomeMaster returned false for an already-present VIP")
	}
	if got := vi.getState(); got != StateMaster {
		t.Fatalf("state = %v, want StateMaster", got)
	}
	for {
		select {
		case ev := <-eventCh:
			if ev.State == StateMaster {
				return
			}
		default:
			t.Fatal("becomeMaster did not publish a StateMaster event")
		}
	}
}

func TestVIPRemoveErrnoClassification_10491(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name: "eaddrnotavail-annotated-tlv",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EADDRNOTAVAIL),
				text:  "NLMSGERR_ATTR_MSG: address absent",
			},
			wantErr: false,
		},
		{
			name:    "eaddrnotavail-pinned-netlink-shape",
			err:     fmt.Errorf("%w: %s", syscall.Errno(unix.EADDRNOTAVAIL), "NLMSGERR_ATTR_MSG: address absent"),
			wantErr: false,
		},
		{
			name: "eexist-annotated-other-errno",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EEXIST),
				text:  "NLMSGERR_ATTR_MSG: delete denied",
			},
			wantErr: true,
		},
		{
			name: "eperm-annotated-other-errno",
			err: annotatedErr10491{
				cause: syscall.Errno(unix.EPERM),
				text:  "NLMSGERR_ATTR_MSG: delete denied",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := removeVIPErrno10491(t, tc.err)
			if got := err != nil; got != tc.wantErr {
				t.Fatalf("error presence = %v, want %v; err = %v", got, tc.wantErr, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "del vip") {
				t.Fatalf("error = %q, want del vip wrapper", err)
			}
		})
	}
}
