package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// annotatedErr10529 models a netlink error whose outer text is an ext-ack/TLV
// message while preserving the kernel errno in its unwrap chain. The synthetic
// shape proves that classification does not depend on errno text being copied
// into Error().
type annotatedErr10529 struct {
	cause error
	text  string
}

func (e annotatedErr10529) Error() string { return e.text }
func (e annotatedErr10529) Unwrap() error { return e.cause }

func reconcileAddrErrno10529(t *testing.T, injected error) (bool, string) {
	t.Helper()
	oldLink, oldList, oldAdd := addrLinkByNameSeam, addrListSeam, addrAddSeam
	oldLogger := slog.Default()
	t.Cleanup(func() {
		addrLinkByNameSeam, addrListSeam, addrAddSeam = oldLink, oldList, oldAdd
		slog.SetDefault(oldLogger)
	})

	addrLinkByNameSeam = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 10529}}, nil
	}
	addrListSeam = func(netlink.Link, int) ([]netlink.Addr, error) {
		return nil, nil
	}
	addrAddSeam = func(netlink.Link, *netlink.Addr) error {
		return injected
	}

	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))
	changed := reconcileInterfaceAddresses("xpf-10529", []string{"10.0.99.1/24"})
	return changed, logs.String()
}

func TestReconcileInterfaceAddressesAddrErrnoClassification10529(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantWarn bool
	}{
		{
			name:     "eexist-errno",
			err:      syscall.Errno(unix.EEXIST),
			wantWarn: false,
		},
		{
			name: "eexist-annotated-tlv",
			err: annotatedErr10529{
				cause: syscall.Errno(unix.EEXIST),
				text:  "NLMSGERR_ATTR_MSG: duplicate address",
			},
			wantWarn: false,
		},
		{
			name:     "eexist-pinned-netlink-shape",
			err:      fmt.Errorf("%w: %s", syscall.Errno(unix.EEXIST), "NLMSGERR_ATTR_MSG: duplicate"),
			wantWarn: false,
		},
		{
			name:     "file-exists-string-fallback",
			err:      errors.New("file exists"),
			wantWarn: false,
		},
		{
			// A non-EEXIST error containing bare "exists" must remain fail-closed.
			name:     "bare-exists-non-eexist",
			err:      errors.New("interface exists but is down"),
			wantWarn: true,
		},
		{
			name:     "eperm-errno",
			err:      syscall.Errno(unix.EPERM),
			wantWarn: true,
		},
		{
			name:     "eaddrnotavail-errno",
			err:      syscall.Errno(unix.EADDRNOTAVAIL),
			wantWarn: true,
		},
		{
			name:     "einval-errno",
			err:      syscall.Errno(unix.EINVAL),
			wantWarn: true,
		},
		{
			name: "other-errno-annotated-with-exists-text",
			err: annotatedErr10529{
				cause: syscall.Errno(unix.EPERM),
				text:  "interface exists check denied",
			},
			wantWarn: true,
		},
		{
			name: "other-errno-annotated-tlv",
			err: annotatedErr10529{
				cause: syscall.Errno(unix.EPERM),
				text:  "NLMSGERR_ATTR_MSG: address rejected",
			},
			wantWarn: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, logs := reconcileAddrErrno10529(t, tc.err)
			if changed {
				t.Fatal("changed = true, want false for failed AddrAdd")
			}
			warned := strings.Contains(logs, "failed to add address to interface")
			if warned != tc.wantWarn {
				t.Fatalf("warning = %v, want %v; logs = %q", warned, tc.wantWarn, logs)
			}
		})
	}
}
