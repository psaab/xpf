// Package grpcapi implements the gRPC API server for xpf.
package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Config configures the gRPC server.
type Config struct {
	Store            *configstore.Store
	DP               dataplane.DataPlane
	EventBuf         *logging.EventBuffer
	GC               *conntrack.GC
	Routing          *routing.Manager
	FRR              *frr.Manager
	IPsec            *ipsec.Manager
	Cluster          *cluster.Manager
	DHCP             *dhcp.Manager
	DHCPServer       *dhcpserver.Manager
	RPMResultsFn     func() []*rpm.ProbeResult        // returns live RPM results
	FeedsFn          func() map[string]feeds.FeedInfo // returns live feed status
	LLDPNeighborsFn  func() []*lldp.Neighbor          // returns live LLDP neighbors
	// #846: atomic commit+apply callbacks. The daemon holds its
	// apply semaphore across configstore.Commit, applyConfig, and
	// (for gRPC) syncConfigToPeer, so two concurrent committers
	// can't interleave their commit→apply pairs. Returns ctx.Err()
	// if the request is canceled before the semaphore is acquired
	// (handlers translate to DeadlineExceeded/Canceled).
	CommitFn          func(ctx context.Context, comment string) (*config.Config, error)
	CommitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error)
	VRRPMgr          *vrrp.Manager                    // native VRRP manager
	RAMgr            *ra.Manager                      // embedded RA sender manager
	Version          string                           // software version string
	FabricPeerAddrFn func() []string                  // returns peer fabric IPs (fab0, fab1; empty if standalone)
	FabricVRFDevice  string                           // VRF for fabric interface (e.g. "vrf-mgmt")
	FwdSampler       *fwdstatus.Sampler               // #881: 5s/1m/5m CPU windows for `show chassis forwarding`
}

// Server implements the BpfrxService gRPC service.
type Server struct {
	pb.UnimplementedBpfrxServiceServer
	store              *configstore.Store
	dp                 dataplane.DataPlane
	eventBuf           *logging.EventBuffer
	gc                 *conntrack.GC
	routing            *routing.Manager
	frr                *frr.Manager
	ipsec              *ipsec.Manager
	cluster            *cluster.Manager
	dhcp               *dhcp.Manager
	dhcpServer         *dhcpserver.Manager
	rpmResultsFn       func() []*rpm.ProbeResult
	feedsFn            func() map[string]feeds.FeedInfo
	lldpNeighborsFn    func() []*lldp.Neighbor
	commitFn           func(ctx context.Context, comment string) (*config.Config, error)
	commitConfirmedFn  func(ctx context.Context, minutes int) (*config.Config, error)
	vrrpMgr            *vrrp.Manager
	raMgr              *ra.Manager
	fwdSampler         *fwdstatus.Sampler
	startTime          time.Time
	addr               string
	version            string
	fabricPeerAddrFn   func() []string
	fabricVRFDevice    string
	peerSystemActionFn func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error)
}

func (s *Server) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := s.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

// formatFlowSteering renders the controller status for #789
// `show class-of-service flow-steering`. Returns a one-line
// "unavailable" message when the dataplane is not the userspace
// backend, so remote operators see something instead of an empty
// response.
func (s *Server) formatFlowSteering() string {
	provider, ok := s.dp.(interface {
		FlowSteering() *dpuserspace.FlowSteeringController
	})
	if !ok {
		return "flow-steering: unavailable (dataplane is not the userspace backend)\n"
	}
	ctrl := provider.FlowSteering()
	if ctrl == nil {
		return "flow-steering: unavailable\n"
	}
	m := ctrl.MetricsSnapshot()
	state := "disabled"
	if m.Enabled {
		state = "enabled"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Flow steering controller (#789):\n")
	fmt.Fprintf(&b, "  State: %s\n", state)
	fmt.Fprintf(&b, "  Rules installed:    %d\n", m.RulesInstalled)
	fmt.Fprintf(&b, "  Rules removed:      %d\n", m.RulesRemoved)
	fmt.Fprintf(&b, "  Imbalance detected: %d\n", m.ImbalanceDetected)
	fmt.Fprintf(&b, "  Install failures:   %d\n", m.InstallFailures)
	b.WriteString("\n")
	hist := ctrl.HistorySnapshot()
	if len(hist) == 0 {
		b.WriteString("No re-steer events recorded.\n")
		return b.String()
	}
	b.WriteString("Recent re-steer events:\n")
	for _, ev := range hist {
		fmt.Fprintf(&b, "  %s  iface=%s  loc=%d  q=%d  flow=%q  reason=%s\n",
			ev.At.Format("15:04:05"),
			ev.Iface,
			ev.RuleLoc,
			ev.TargetQueue,
			ev.Flow,
			ev.Reason,
		)
	}
	return b.String()
}

func (s *Server) userspaceDataplaneControl() (interface {
	Status() (dpuserspace.ProcessStatus, error)
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}, error) {
	provider, ok := s.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
		SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
		SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

// NewServer creates a new gRPC server.
// NOTE: gRPC is local-only (127.0.0.1) so all RPCs are inherently trusted.
// Login class RBAC enforcement could be added here via per-RPC interceptors if
// gRPC is ever exposed on non-loopback addresses.
func NewServer(addr string, cfg Config) *Server {
	return &Server{
		store:            cfg.Store,
		dp:               cfg.DP,
		eventBuf:         cfg.EventBuf,
		gc:               cfg.GC,
		routing:          cfg.Routing,
		frr:              cfg.FRR,
		ipsec:            cfg.IPsec,
		cluster:          cfg.Cluster,
		dhcp:             cfg.DHCP,
		dhcpServer:       cfg.DHCPServer,
		rpmResultsFn:     cfg.RPMResultsFn,
		feedsFn:           cfg.FeedsFn,
		lldpNeighborsFn:   cfg.LLDPNeighborsFn,
		commitFn:          cfg.CommitFn,
		commitConfirmedFn: cfg.CommitConfirmedFn,
		vrrpMgr:          cfg.VRRPMgr,
		raMgr:            cfg.RAMgr,
		fwdSampler:       cfg.FwdSampler,
		startTime:        time.Now(),
		addr:             addr,
		version:          cfg.Version,
		fabricPeerAddrFn: cfg.FabricPeerAddrFn,
		fabricVRFDevice:  cfg.FabricVRFDevice,
	}
}

// Run starts the gRPC server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(s.configLockInterceptor),
	)
	pb.RegisterBpfrxServiceServer(srv, s)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("gRPC server listening", "addr", s.addr)
		if err := srv.Serve(lis); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	srv.GracefulStop()
	return nil
}

// RunFabricListener starts an additional gRPC listener on the fabric IP
// so the cluster peer can proxy monitor requests. Blocks until ctx is cancelled.
// vrfDevice may be empty for default VRF, or e.g. "vrf-mgmt".
func (s *Server) RunFabricListener(ctx context.Context, addr, vrfDevice string) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if vrfDevice != "" {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfDevice)
				}
			})
			return err
		},
	}
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		slog.Warn("gRPC fabric listener failed", "addr", addr, "vrf", vrfDevice, "err", err)
		return
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(s.configLockInterceptor),
	)
	pb.RegisterBpfrxServiceServer(srv, s)

	go func() {
		slog.Info("gRPC fabric listener started", "addr", addr, "vrf", vrfDevice)
		if err := srv.Serve(lis); err != nil {
			slog.Warn("gRPC fabric listener error", "err", err)
		}
	}()

	<-ctx.Done()
	srv.GracefulStop()
}

// configLockInterceptor auto-releases stale config locks when a gRPC client
// disconnects (context cancelled) without calling ExitConfigure.
func (s *Server) configLockInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	resp, err := handler(ctx, req)

	// If the client's context was cancelled (disconnect, Ctrl-C), release any
	// config lock held by this connection.
	if ctx.Err() != nil {
		sessionID := peerSessionID(ctx)
		if sessionID != "" {
			if s.store.ExitConfigureSession(sessionID) {
				slog.Info("auto-released config lock on client disconnect", "session", sessionID)
			}
		}
	}
	return resp, err
}

// peerSessionID derives a stable session identifier from the gRPC peer address.
func peerSessionID(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	return p.Addr.String()
}
