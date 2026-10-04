package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

const (
	interfaceLinkSnapshotDebounce     = 150 * time.Millisecond
	interfaceLinkSnapshotRetryBackoff = 30 * time.Second
)

func (d *Daemon) interfaceLinkSnapshotManager() *dpuserspace.Manager {
	if d == nil {
		return nil
	}
	provider, ok := d.dataplane().(interface{ Manager() *dpuserspace.Manager })
	if !ok {
		return nil
	}
	return provider.Manager()
}

// InterfaceLinkSnapshotPending reports whether a link-triggered snapshot
// refresh or its FIB-generation invalidation failed and is awaiting retry.
func (d *Daemon) InterfaceLinkSnapshotPending() bool {
	return d != nil && d.interfaceLinkSnapshotPending.Load()
}

// queueInterfaceLinkSnapshotRefresh coalesces RTNL events to the newest
// relevant interface name. The manager checks against desired config, not
// retained published rows, so a row dropped while its device is absent remains
// eligible for a later NEWLINK.
func (d *Daemon) queueInterfaceLinkSnapshotRefresh(wake chan string, linuxName string) {
	if wake == nil || linuxName == "" {
		return
	}
	manager := d.interfaceLinkSnapshotManager()
	if manager == nil || !manager.InterfaceLinkNameRelevant(linuxName) {
		return
	}
	select {
	case wake <- linuxName:
		return
	default:
	}
	select {
	case <-wake:
	default:
	}
	select {
	case wake <- linuxName:
	default:
	}
}

func (d *Daemon) queueInterfaceLinkSnapshotResync(wake chan string) {
	manager := d.interfaceLinkSnapshotManager()
	if manager == nil {
		return
	}
	d.queueInterfaceLinkSnapshotRefresh(wake, manager.InterfaceLinkRefreshTriggerName())
}

// interfaceLinkSnapshotRefreshLoop is single-flight. RTNL churn restarts the
// quiet-period debounce; publication errors stay owed and retry on one slow
// timer instead of requiring another event or starting a goroutine per event.
func (d *Daemon) interfaceLinkSnapshotRefreshLoop(ctx context.Context, wake <-chan string) {
	for {
		var linuxName string
		select {
		case <-ctx.Done():
			return
		case linuxName = <-wake:
		}
		if linuxName == "" {
			continue
		}
		var ready bool
		linuxName, ready = debounceInterfaceLinkSnapshot(ctx, wake, linuxName, interfaceLinkSnapshotDebounce)
		if !ready {
			return
		}
		for {
			_, err := d.refreshInterfaceRowsForLink(ctx, linuxName)
			// Cancellation means the worker is leaving, not that its retry debt
			// converged. An acquire rejected by ctx must not look successful.
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				d.interfaceLinkSnapshotPending.Store(false)
				break
			}
			d.interfaceLinkSnapshotPending.Store(true)
			slog.Warn("userspace: interface-link snapshot refresh failed; retaining retry debt",
				"linux_name", linuxName, "err", err)
			timer := time.NewTimer(interfaceLinkSnapshotRetryBackoff)
			retry := false
			for !retry {
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				case nextName := <-wake:
					if nextName != "" {
						linuxName = nextName
					}
				case <-timer.C:
					retry = true
				}
			}
		}
	}
}

func debounceInterfaceLinkSnapshot(ctx context.Context, wake <-chan string, linuxName string, delay time.Duration) (string, bool) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", false
		case nextName := <-wake:
			if nextName != "" {
				linuxName = nextName
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		case <-timer.C:
			return linuxName, true
		}
	}
}

func (d *Daemon) refreshInterfaceRowsForLink(ctx context.Context, linuxName string) (bool, error) {
	if !d.beginBackgroundApply(ctx, "interface-link-snapshot-refresh") {
		return false, nil
	}
	defer d.applySem.Release(1)
	if ctx != nil && ctx.Err() != nil {
		return false, nil
	}
	if d.store == nil {
		return false, nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false, nil
	}
	manager := d.interfaceLinkSnapshotManager()
	if manager == nil {
		return false, nil
	}
	published, err := manager.RefreshInterfaceRowsForLink(cfg, linuxName)
	if err != nil {
		return false, err
	}
	if published {
		d.pendingFIBBump = true
	}
	if !published && !d.pendingFIBBump {
		return false, nil
	}
	if _, err := manager.BumpFIBGeneration(); err != nil {
		d.pendingFIBBump = true
		return false, fmt.Errorf("bump FIB generation after interface-link refresh: %w", err)
	}
	d.pendingFIBBump = false
	return published, nil
}
