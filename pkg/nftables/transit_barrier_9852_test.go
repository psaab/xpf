package nftables

import (
	"errors"
	"fmt"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestTransitBarrierUnsupportedClassification9852(t *testing.T) {
	single := errors.Join(fmt.Errorf("%w: bridge family unavailable", ErrTransitBarrierBridgeUnsupported))
	if !IsTransitBarrierBridgeUnsupportedOnly(single) {
		t.Fatal("single-child production-shaped join must classify as bridge-only degradation")
	}
	mixed := errors.Join(single, errors.New("inet: permission denied"))
	if IsTransitBarrierBridgeUnsupportedOnly(mixed) {
		t.Fatal("mixed inet plus bridge errors must remain fatal")
	}
	if IsTransitBarrierBridgeUnsupportedOnly(nil) {
		t.Fatal("nil error must not classify as bridge-only degradation")
	}
	plain := errors.Join(errors.New("plain netlink failure"))
	if IsTransitBarrierBridgeUnsupportedOnly(plain) {
		t.Fatal("plain single-child join must not classify as bridge-only degradation")
	}
}

func TestTransitBarrierUnsupportedErrnoTagging9852(t *testing.T) {
	unsupported := []error{unix.ENOENT, unix.EOPNOTSUPP, unix.EAFNOSUPPORT}
	for _, errno := range unsupported {
		t.Run("bridge_"+errno.Error(), func(t *testing.T) {
			in := transitBarrierFakeInstaller9852(nil, errno)
			err := in.InstallTransitBarrier()
			if err == nil {
				t.Fatalf("bridge %v unexpectedly succeeded", errno)
			}
			if !IsTransitBarrierBridgeUnsupportedOnly(err) {
				t.Fatalf("bridge %v error was not tagged as sole unsupported degradation: %v", errno, err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("bridge %v was not preserved through wrapping: %v", errno, err)
			}
		})
	}

	for _, errno := range unsupported {
		t.Run("inet_"+errno.Error(), func(t *testing.T) {
			in := transitBarrierFakeInstaller9852(errno, nil)
			err := in.InstallTransitBarrier()
			if err == nil {
				t.Fatalf("inet %v unexpectedly succeeded", errno)
			}
			if IsTransitBarrierBridgeUnsupportedOnly(err) {
				t.Fatalf("inet %v was misclassified as bridge-only degradation: %v", errno, err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("inet %v was not preserved through wrapping: %v", errno, err)
			}
		})
	}

	t.Run("bridge_permission_denied", func(t *testing.T) {
		in := transitBarrierFakeInstaller9852(nil, unix.EPERM)
		err := in.InstallTransitBarrier()
		if err == nil {
			t.Fatal("bridge EPERM unexpectedly succeeded")
		}
		if IsTransitBarrierBridgeUnsupportedOnly(err) {
			t.Fatalf("bridge EPERM was misclassified as unsupported degradation: %v", err)
		}
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("bridge EPERM was not preserved through wrapping: %v", err)
		}
	})
}

func transitBarrierFakeInstaller9852(inetErr, bridgeErr error) *netlinkInstaller {
	family := 0
	return newNetlinkInstallerConn(func() (*gnft.Conn, error) {
		flushErr := inetErr
		if family == 1 {
			flushErr = bridgeErr
		}
		family++
		calls := 0
		return gnft.New(gnft.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			calls++
			if calls == 3 && flushErr != nil {
				return nil, flushErr
			}
			return nil, nil
		}))
	})
}
