package config

import (
	"strings"
	"testing"
)

func TestChassisCluster(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        reth-count 5;
        redundancy-group 0 {
            node 0 priority 100;
            node 1 priority 1;
        }
        redundancy-group 1 {
            node 0 priority 100;
            node 1 priority 1;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/0 weight 255;
                ge-7/0/0 weight 255;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.RethCount != 5 {
		t.Errorf("RethCount = %d, want 5", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	rg0 := cl.RedundancyGroups[0]
	if rg0.ID != 0 {
		t.Errorf("rg0.ID = %d, want 0", rg0.ID)
	}
	if rg0.NodePriorities[0] != 100 {
		t.Errorf("rg0 node 0 priority = %d, want 100", rg0.NodePriorities[0])
	}
	if rg0.NodePriorities[1] != 1 {
		t.Errorf("rg0 node 1 priority = %d, want 1", rg0.NodePriorities[1])
	}
	rg1 := cl.RedundancyGroups[1]
	if rg1.GratuitousARPCount != 8 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 8", rg1.GratuitousARPCount)
	}
	if len(rg1.InterfaceMonitors) != 2 {
		t.Fatalf("rg1 interface-monitors = %d, want 2", len(rg1.InterfaceMonitors))
	}
	if rg1.InterfaceMonitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor[0] = %q, want ge-0/0/0", rg1.InterfaceMonitors[0].Interface)
	}
	if rg1.InterfaceMonitors[0].Weight != 255 {
		t.Errorf("monitor[0] weight = %d, want 255", rg1.InterfaceMonitors[0].Weight)
	}
}

func TestChassisClusterSetSyntax(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster reth-count 3", "set chassis cluster redundancy-group 0 node 0 priority 100", "set chassis cluster redundancy-group 0 node 1 priority 50", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 gratuitous-arp-count 16"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath failed for command %q: %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.RethCount != 3 {
		t.Errorf("RethCount = %d, want 3", cfg.Chassis.Cluster.RethCount)
	}
	if len(cfg.Chassis.Cluster.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cfg.Chassis.Cluster.RedundancyGroups))
	}
	rg0 := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg0.NodePriorities[0] != 100 || rg0.NodePriorities[1] != 50 {
		t.Errorf("rg0 priorities: node0=%d, node1=%d", rg0.NodePriorities[0], rg0.NodePriorities[1])
	}
	rg1 := cfg.Chassis.Cluster.RedundancyGroups[1]
	if rg1.NodePriorities[0] != 200 {
		t.Errorf("rg1 node 0 priority = %d, want 200", rg1.NodePriorities[0])
	}
	if rg1.GratuitousARPCount != 16 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 16", rg1.GratuitousARPCount)
	}
}

func TestChassisClusterExtendedFields(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        node 0;
        heartbeat-interval 500;
        heartbeat-threshold 5;
        reth-count 2;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 4;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", cl.ClusterID)
	}
	if cl.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", cl.NodeID)
	}
	if cl.HeartbeatInterval != 500 {
		t.Errorf("HeartbeatInterval = %d, want 500", cl.HeartbeatInterval)
	}
	if cl.HeartbeatThreshold != 5 {
		t.Errorf("HeartbeatThreshold = %d, want 5", cl.HeartbeatThreshold)
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	for _, rg := range cl.RedundancyGroups {
		if rg.Preempt != (rg.ID == 1) {
			t.Errorf("rg%d.Preempt = %v, want %v", rg.ID, rg.Preempt, rg.ID == 1)
		}
		if rg.NodePriorities[0] != 200 {
			t.Errorf("rg%d node 0 priority = %d, want 200", rg.ID, rg.NodePriorities[0])
		}
		if rg.NodePriorities[1] != 100 {
			t.Errorf("rg%d node 1 priority = %d, want 100", rg.ID, rg.NodePriorities[1])
		}
	}
	if cl.RedundancyGroups[1].GratuitousARPCount != 4 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 4", cl.RedundancyGroups[1].GratuitousARPCount)
	}
}

func TestChassisClusterExtendedFieldsSet(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster heartbeat-interval 500", "set chassis cluster heartbeat-threshold 5", "set chassis cluster reth-count 2", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 node 1 priority 100", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 node 1 priority 100", "set chassis cluster redundancy-group 1 preempt", "set chassis cluster redundancy-group 1 gratuitous-arp-count 4"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q) failed: %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if cl.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", cl.ClusterID)
	}
	if cl.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", cl.NodeID)
	}
	if cl.HeartbeatInterval != 500 {
		t.Errorf("HeartbeatInterval = %d, want 500", cl.HeartbeatInterval)
	}
	if cl.HeartbeatThreshold != 5 {
		t.Errorf("HeartbeatThreshold = %d, want 5", cl.HeartbeatThreshold)
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2", cl.RethCount)
	}
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	for _, rg := range cl.RedundancyGroups {
		if rg.Preempt != (rg.ID == 1) {
			t.Errorf("rg%d.Preempt = %v, want %v", rg.ID, rg.Preempt, rg.ID == 1)
		}
		if rg.NodePriorities[0] != 200 {
			t.Errorf("rg%d node 0 priority = %d, want 200", rg.ID, rg.NodePriorities[0])
		}
		if rg.NodePriorities[1] != 100 {
			t.Errorf("rg%d node 1 priority = %d, want 100", rg.ID, rg.NodePriorities[1])
		}
	}
	if cl.RedundancyGroups[1].GratuitousARPCount != 4 {
		t.Errorf("rg1 gratuitous-arp-count = %d, want 4", cl.RedundancyGroups[1].GratuitousARPCount)
	}
}

func TestChassisClusterSyncOptions(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster configuration-synchronize", "set chassis cluster nat-state-synchronization", "set chassis cluster ipsec-session-synchronization", "set chassis cluster dhcp-lease-synchronization"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if !cl.ConfigSync {
		t.Error("ConfigSync should be true")
	}
	if !cl.NATStateSync {
		t.Error("NATStateSync should be true")
	}
	if !cl.IPsecSASync {
		t.Error("IPsecSASync should be true")
	}
	if !cl.DHCPLeaseSync {
		t.Error("DHCPLeaseSync should be true")
	}
}

func TestChassisClusterSyncOptionsHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        node 0;
        configuration-synchronize;
        nat-state-synchronization;
        ipsec-session-synchronization;
        dhcp-lease-synchronization;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if !cl.ConfigSync {
		t.Error("ConfigSync should be true")
	}
	if !cl.NATStateSync {
		t.Error("NATStateSync should be true")
	}
	if !cl.IPsecSASync {
		t.Error("IPsecSASync should be true")
	}
	if !cl.DHCPLeaseSync {
		t.Error("DHCPLeaseSync should be true")
	}
}

func TestChassisClusterRethAdvertiseInterval(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster reth-advertise-interval 30"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.RethAdvertiseInterval != 30 {
		t.Errorf("RethAdvertiseInterval = %d, want 30", cfg.Chassis.Cluster.RethAdvertiseInterval)
	}
}

func TestChassisClusterRethAdvertiseIntervalHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        reth-advertise-interval 50;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.RethAdvertiseInterval != 50 {
		t.Errorf("RethAdvertiseInterval = %d, want 50", cfg.Chassis.Cluster.RethAdvertiseInterval)
	}
}

func TestChassisClusterHitlessRestartSet(t *testing.T) {
	tree := &ConfigTree{}
	sets := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster hitless-restart"}
	for _, line := range sets {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.HitlessRestart {
		t.Error("HitlessRestart = false, want true")
	}
}

func TestChassisClusterHitlessRestartHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        hitless-restart;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.HitlessRestart {
		t.Error("HitlessRestart = false, want true")
	}
}

func TestChassisClusterHitlessRestartDefault(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.HitlessRestart {
		t.Error("HitlessRestart = true, want false (default)")
	}
}

func TestChassisClusterPeerFencingSet(t *testing.T) {
	tree := &ConfigTree{}
	sets := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster peer-fencing disable-rg"}
	for _, line := range sets {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.PeerFencing != "disable-rg" {
		t.Errorf("PeerFencing = %q, want %q", cfg.Chassis.Cluster.PeerFencing, "disable-rg")
	}
}

func TestChassisClusterPeerFencingHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        peer-fencing disable-rg;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.PeerFencing != "disable-rg" {
		t.Errorf("PeerFencing = %q, want %q", cfg.Chassis.Cluster.PeerFencing, "disable-rg")
	}
}

func TestChassisClusterPeerFencingDefault(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.PeerFencing != "" {
		t.Errorf("PeerFencing = %q, want empty (default)", cfg.Chassis.Cluster.PeerFencing)
	}
}

func TestChassisClusterIPMonitoring(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        node 0;
        redundancy-group 0 {
            node 0 priority 200;
            ip-monitoring {
                global-weight 255;
                global-threshold 200;
                family {
                    inet {
                        10.0.1.1 weight 100;
                        10.0.2.1 weight 80;
                    }
                }
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	rg := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg.IPMonitoring == nil {
		t.Fatal("IPMonitoring is nil")
	}
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Errorf("GlobalWeight = %d, want 255", rg.IPMonitoring.GlobalWeight)
	}
	if rg.IPMonitoring.GlobalThreshold != 200 {
		t.Errorf("GlobalThreshold = %d, want 200", rg.IPMonitoring.GlobalThreshold)
	}
	if len(rg.IPMonitoring.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2", len(rg.IPMonitoring.Targets))
	}
	if rg.IPMonitoring.Targets[0].Address != "10.0.1.1" {
		t.Errorf("target[0].Address = %q, want 10.0.1.1", rg.IPMonitoring.Targets[0].Address)
	}
	if rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Errorf("target[0].Weight = %d, want 100", rg.IPMonitoring.Targets[0].Weight)
	}
	if rg.IPMonitoring.Targets[1].Address != "10.0.2.1" {
		t.Errorf("target[1].Address = %q, want 10.0.2.1", rg.IPMonitoring.Targets[1].Address)
	}
	if rg.IPMonitoring.Targets[1].Weight != 80 {
		t.Errorf("target[1].Weight = %d, want 80", rg.IPMonitoring.Targets[1].Weight)
	}
}

func TestChassisClusterIPMonitoringSetSyntax(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 ip-monitoring global-weight 255", "set chassis cluster redundancy-group 0 ip-monitoring global-threshold 200", "set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.1.1 weight 100", "set chassis cluster redundancy-group 0 ip-monitoring family inet 10.0.2.1 weight 80"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	rg := cfg.Chassis.Cluster.RedundancyGroups[0]
	if rg.IPMonitoring == nil {
		t.Fatal("IPMonitoring is nil")
	}
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Errorf("GlobalWeight = %d, want 255", rg.IPMonitoring.GlobalWeight)
	}
	if rg.IPMonitoring.GlobalThreshold != 200 {
		t.Errorf("GlobalThreshold = %d, want 200", rg.IPMonitoring.GlobalThreshold)
	}
	if len(rg.IPMonitoring.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2", len(rg.IPMonitoring.Targets))
	}
	if rg.IPMonitoring.Targets[0].Address != "10.0.1.1" {
		t.Errorf("target[0].Address = %q, want 10.0.1.1", rg.IPMonitoring.Targets[0].Address)
	}
	if rg.IPMonitoring.Targets[0].Weight != 100 {
		t.Errorf("target[0].Weight = %d, want 100", rg.IPMonitoring.Targets[0].Weight)
	}
	if rg.IPMonitoring.Targets[1].Address != "10.0.2.1" {
		t.Errorf("target[1].Address = %q, want 10.0.2.1", rg.IPMonitoring.Targets[1].Address)
	}
	if rg.IPMonitoring.Targets[1].Weight != 80 {
		t.Errorf("target[1].Weight = %d, want 80", rg.IPMonitoring.Targets[1].Weight)
	}
}

func TestStrictVIPOwnershipHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        reth-count 2;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            strict-vip-ownership;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	if cl.RedundancyGroups[0].StrictVIPOwnership {
		t.Error("rg0.StrictVIPOwnership should be false")
	}
	if !cl.RedundancyGroups[1].StrictVIPOwnership {
		t.Error("rg1.StrictVIPOwnership should be true")
	}
}

func TestStrictVIPOwnershipSetSyntax(t *testing.T) {
	commands := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster reth-count 2", "set chassis cluster redundancy-group 0 node 0 priority 200", "set chassis cluster redundancy-group 0 node 1 priority 100", "set chassis cluster redundancy-group 1 node 0 priority 200", "set chassis cluster redundancy-group 1 node 1 priority 100", "set chassis cluster redundancy-group 1 strict-vip-ownership"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	cl := cfg.Chassis.Cluster
	if len(cl.RedundancyGroups) != 2 {
		t.Fatalf("RedundancyGroups = %d, want 2", len(cl.RedundancyGroups))
	}
	if cl.RedundancyGroups[0].StrictVIPOwnership {
		t.Error("rg0.StrictVIPOwnership should be false")
	}
	if !cl.RedundancyGroups[1].StrictVIPOwnership {
		t.Error("rg1.StrictVIPOwnership should be true")
	}
}

func TestStrictVIPOwnershipDefaultFalse(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node 0 priority 200;
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if len(cfg.Chassis.Cluster.RedundancyGroups) != 1 {
		t.Fatalf("RedundancyGroups = %d, want 1", len(cfg.Chassis.Cluster.RedundancyGroups))
	}
	if cfg.Chassis.Cluster.RedundancyGroups[0].StrictVIPOwnership {
		t.Error("StrictVIPOwnership should default to false")
	}
}

func TestChassisClusterNoRethVRRPSet(t *testing.T) {
	tree := &ConfigTree{}
	sets := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster no-reth-vrrp"}
	for _, line := range sets {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.NoRethVRRP {
		t.Error("NoRethVRRP = false, want true")
	}
}

func TestChassisClusterNoRethVRRPHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        no-reth-vrrp;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.NoRethVRRP {
		t.Error("NoRethVRRP = false, want true")
	}
}

func TestChassisClusterNoRethVRRPDefault(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.NoRethVRRP {
		t.Error("NoRethVRRP = true, want false (default = VRRP enabled)")
	}
}

func TestChassisClusterPrivateRGElectionSet(t *testing.T) {
	tree := &ConfigTree{}
	sets := []string{"set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster private-rg-election"}
	for _, line := range sets {
		cmd, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(cmd); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.PrivateRGElection {
		t.Error("PrivateRGElection = false, want true")
	}
}

func TestChassisClusterPrivateRGElectionHierarchical(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        private-rg-election;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.PrivateRGElection {
		t.Error("PrivateRGElection = false, want true")
	}
}

func TestChassisClusterPrivateRGElectionDefault(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.PrivateRGElection {
		t.Error("PrivateRGElection = false, want true (default)")
	}
}

func TestChassisClusterNoPrivateRGElection(t *testing.T) {
	input := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        no-private-rg-election;
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.PrivateRGElection {
		t.Error("PrivateRGElection = true, want false (no-private-rg-election)")
	}
}

func TestValidateFabric1MissingPeerAddress(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{"fab0": {Name: "fab0"}, "fab1": {Name: "fab1"}}}, Chassis: ChassisConfig{Cluster: &ClusterConfig{FabricInterface: "fab0", FabricPeerAddress: "10.99.1.2", Fabric1Interface: "fab1"}}}
	warnings := ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "fabric1-interface and fabric1-peer-address must both be set") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about incomplete fabric1 config, got none")
	}
}

func TestValidateFabricInterfaceNotDefined(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{"fab0": {Name: "fab0"}}}, Chassis: ChassisConfig{Cluster: &ClusterConfig{FabricInterface: "fab0", FabricPeerAddress: "10.99.1.2", Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.2.2"}}}
	warnings := ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "fabric1-interface") && strings.Contains(w, "not defined") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about undefined fabric1-interface, got none")
	}
}

func TestValidateFabricMembersOverlap(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{"fab0": {Name: "fab0", FabricMembers: []string{"ge-0/0/2", "ge-0/0/3"}}, "fab1": {Name: "fab1", FabricMembers: []string{"ge-0/0/3", "ge-0/0/4"}}}}, Chassis: ChassisConfig{Cluster: &ClusterConfig{FabricInterface: "fab0", FabricPeerAddress: "10.99.1.2", Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.2.2"}}}
	warnings := ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "ge-0/0/3") && strings.Contains(w, "shared between") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning about overlapping fabric member ge-0/0/3, got none")
	}
}

func TestValidateFabricDualValid(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{"fab0": {Name: "fab0", FabricMembers: []string{"ge-0/0/2"}}, "fab1": {Name: "fab1", FabricMembers: []string{"ge-0/0/3"}}, "hb0": {Name: "hb0"}}}, Chassis: ChassisConfig{Cluster: &ClusterConfig{ControlInterface: "hb0", FabricInterface: "fab0", FabricPeerAddress: "10.99.1.2", Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.2.2"}}}
	warnings := ValidateConfig(cfg)
	for _, w := range warnings {
		if strings.Contains(w, "fabric") || strings.Contains(w, "control") {
			t.Errorf("unexpected fabric/control warning: %s", w)
		}
	}
}

func TestInterfaceSlot(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{{"ge-0/0/7", 0}, {"ge-7/0/7", 7}, {"xe-3/1/2", 3}, {"et-0/0/0", 0}, {"fab0", -1}, {"hb0", -1}, {"", -1}}
	for _, tt := range tests {
		if got := InterfaceSlot(tt.name); got != tt.want {
			t.Errorf("InterfaceSlot(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestSlotToNodeID(t *testing.T) {
	if SlotToNodeID(0) != 0 {
		t.Error("slot 0 should map to node 0")
	}
	if SlotToNodeID(7) != 1 {
		t.Error("slot 7 should map to node 1")
	}
	if SlotToNodeID(3) != 0 {
		t.Error("slot 3 should map to node 0")
	}
}

func TestPeerFromPointToPoint(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{{"10.99.1.1/30", "10.99.1.2"}, {"10.99.1.2/30", "10.99.1.1"}, {"10.99.2.1/30", "10.99.2.2"}, {"10.99.2.2/30", "10.99.2.1"}, {"192.168.0.1/31", "192.168.0.0"}, {"192.168.0.0/31", "192.168.0.1"}, {"10.0.0.0/30", ""}, {"10.0.0.3/30", ""}, {"10.0.0.1/24", ""}, {"invalid", ""}, {"", ""}}
	for _, tt := range tests {
		got := peerFromPointToPoint(tt.cidr)
		if got != tt.want {
			t.Errorf("peerFromPointToPoint(%q) = %q, want %q", tt.cidr, got, tt.want)
		}
	}
}

func TestFabricLocalMemberResolution(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab0 unit 0 family inet address 10.99.1.1/30", "set interfaces fab1 fabric-options member-interfaces ge-7/0/7", "set interfaces fab1 unit 0 family inet address 10.99.2.1/30", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	fab0 := cfg.Interfaces.Interfaces["fab0"]
	if fab0 == nil {
		t.Fatal("fab0 not found")
	}
	if fab0.LocalFabricMember != "ge-0/0/7" {
		t.Errorf("fab0 LocalFabricMember = %q, want %q", fab0.LocalFabricMember, "ge-0/0/7")
	}
	fab1 := cfg.Interfaces.Interfaces["fab1"]
	if fab1 == nil {
		t.Fatal("fab1 not found")
	}
	if fab1.LocalFabricMember != "" {
		t.Errorf("fab1 LocalFabricMember = %q, want empty (not this node)", fab1.LocalFabricMember)
	}
}

func TestFabricLocalMemberNode1(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab1 fabric-options member-interfaces ge-7/0/7", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 1"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	fab1 := cfg.Interfaces.Interfaces["fab1"]
	if fab1 == nil {
		t.Fatal("fab1 not found")
	}
	if fab1.LocalFabricMember != "ge-7/0/7" {
		t.Errorf("fab1 LocalFabricMember = %q, want %q", fab1.LocalFabricMember, "ge-7/0/7")
	}
	fab0 := cfg.Interfaces.Interfaces["fab0"]
	if fab0 == nil {
		t.Fatal("fab0 not found")
	}
	if fab0.LocalFabricMember != "" {
		t.Errorf("fab0 LocalFabricMember = %q, want empty", fab0.LocalFabricMember)
	}
}

func TestFabricAutoDetectFabricInterface(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab1 fabric-options member-interfaces ge-7/0/7", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 0", "set chassis cluster control-interface hb0", "set interfaces hb0 unit 0 family inet address 10.99.0.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Chassis.Cluster
	if cc == nil {
		t.Fatal("cluster config not found")
	}
	if cc.FabricInterface != "fab0" {
		t.Errorf("FabricInterface = %q, want %q", cc.FabricInterface, "fab0")
	}
	if cc.Fabric1Interface != "" {
		t.Errorf("Fabric1Interface = %q, want empty (fab1 not local to node0)", cc.Fabric1Interface)
	}
}

func TestFabricAutoDetectDualFabric(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab0 fabric-options member-interfaces ge-7/0/7", "set interfaces fab0 unit 0 family inet address 10.99.1.1/30", "set interfaces fab1 fabric-options member-interfaces ge-0/0/8", "set interfaces fab1 fabric-options member-interfaces ge-7/0/8", "set interfaces fab1 unit 0 family inet address 10.99.2.1/30", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 0", "set chassis cluster control-interface hb0", "set interfaces hb0 unit 0 family inet address 10.99.0.1/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Chassis.Cluster
	if cc == nil {
		t.Fatal("cluster config not found")
	}
	if cc.FabricInterface != "fab0" {
		t.Errorf("FabricInterface = %q, want %q", cc.FabricInterface, "fab0")
	}
	if cc.Fabric1Interface != "fab1" {
		t.Errorf("Fabric1Interface = %q, want %q", cc.Fabric1Interface, "fab1")
	}
	if cc.Fabric1PeerAddress != "10.99.2.2" {
		t.Errorf("Fabric1PeerAddress = %q, want %q", cc.Fabric1PeerAddress, "10.99.2.2")
	}
}

func TestFabricAutoDetectDualFabricNode1(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab0 fabric-options member-interfaces ge-7/0/7", "set interfaces fab0 unit 0 family inet address 10.99.1.2/30", "set interfaces fab1 fabric-options member-interfaces ge-0/0/8", "set interfaces fab1 fabric-options member-interfaces ge-7/0/8", "set interfaces fab1 unit 0 family inet address 10.99.2.2/30", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 1", "set chassis cluster control-interface hb0", "set interfaces hb0 unit 0 family inet address 10.99.0.2/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Chassis.Cluster
	if cc == nil {
		t.Fatal("cluster config not found")
	}
	if cc.FabricInterface != "fab0" {
		t.Errorf("FabricInterface = %q, want %q", cc.FabricInterface, "fab0")
	}
	if cc.Fabric1Interface != "fab1" {
		t.Errorf("Fabric1Interface = %q, want %q", cc.Fabric1Interface, "fab1")
	}
	if cc.Fabric1PeerAddress != "10.99.2.1" {
		t.Errorf("Fabric1PeerAddress = %q, want %q", cc.Fabric1PeerAddress, "10.99.2.1")
	}
}

func TestFabricAutoDetectNode1(t *testing.T) {
	cmds := []string{"set interfaces fab0 fabric-options member-interfaces ge-0/0/7", "set interfaces fab1 fabric-options member-interfaces ge-7/0/7", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 1", "set chassis cluster control-interface hb0", "set chassis cluster fabric-peer-address 10.99.1.1", "set interfaces hb0 unit 0 family inet address 10.99.0.2/30"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Chassis.Cluster
	if cc == nil {
		t.Fatal("cluster config not found")
	}
	if cc.FabricInterface != "fab1" {
		t.Errorf("FabricInterface = %q, want %q", cc.FabricInterface, "fab1")
	}
	if cc.FabricPeerAddress != "10.99.1.1" {
		t.Errorf("FabricPeerAddress = %q, want %q", cc.FabricPeerAddress, "10.99.1.1")
	}
}

func TestFabricLegacyModeNoLocalMember(t *testing.T) {
	cmds := []string{"set interfaces fab0 unit 0 family inet address 10.99.1.1/30", "set chassis cluster authentication-key test-cluster-psk-6611", "set chassis cluster node 0", "set chassis cluster fabric-interface fab0"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	fab0 := cfg.Interfaces.Interfaces["fab0"]
	if fab0 == nil {
		t.Fatal("fab0 not found")
	}
	if fab0.LocalFabricMember != "" {
		t.Errorf("legacy fab0 LocalFabricMember = %q, want empty", fab0.LocalFabricMember)
	}
}

func TestPerUnitTunnelConfig(t *testing.T) {
	cmds := []string{"set interfaces gr-0/0/0 unit 0 point-to-point", "set interfaces gr-0/0/0 unit 0 tunnel source 209.237.133.186", "set interfaces gr-0/0/0 unit 0 tunnel destination 107.161.208.15", "set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination Atherton-Fiber", "set interfaces gr-0/0/0 unit 0 family inet mtu 1456", "set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.22/30", "set interfaces gr-0/0/0 unit 1 point-to-point", "set interfaces gr-0/0/0 unit 1 tunnel source 2602:fd41:20:5::351", "set interfaces gr-0/0/0 unit 1 tunnel destination 2602:ffd3:0:2::7", "set interfaces gr-0/0/0 unit 1 tunnel routing-instance destination Atherton-Fiber", "set interfaces gr-0/0/0 unit 1 family inet mtu 1456", "set interfaces gr-0/0/0 unit 1 family inet address 10.255.192.34/30", "set interfaces gr-0/0/0 unit 1 family inet6 mtu 1436", "set interfaces gr-0/0/0 unit 1 family inet6 address fe80::8/64", "set interfaces gr-0/0/0 unit 1 family inet6 address fc00::e/126"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("gr-0/0/0 interface not found")
	}
	if ifc.Tunnel != nil {
		t.Error("interface-level Tunnel should be nil when only per-unit tunnels are configured")
	}
	unit0, ok := ifc.Units[0]
	if !ok {
		t.Fatal("unit 0 not found")
	}
	if unit0.Tunnel == nil {
		t.Fatal("unit 0 tunnel config is nil")
	}
	if unit0.Tunnel.Name != "gr-0-0-0" {
		t.Errorf("unit 0 Tunnel.Name = %q, want %q", unit0.Tunnel.Name, "gr-0-0-0")
	}
	if unit0.Tunnel.Mode != "gre" {
		t.Errorf("unit 0 Tunnel.Mode = %q, want %q", unit0.Tunnel.Mode, "gre")
	}
	if unit0.Tunnel.Source != "209.237.133.186" {
		t.Errorf("unit 0 Tunnel.Source = %q, want 209.237.133.186", unit0.Tunnel.Source)
	}
	if unit0.Tunnel.Destination != "107.161.208.15" {
		t.Errorf("unit 0 Tunnel.Destination = %q, want 107.161.208.15", unit0.Tunnel.Destination)
	}
	if unit0.Tunnel.RoutingInstance != "Atherton-Fiber" {
		t.Errorf("unit 0 Tunnel.RoutingInstance = %q, want Atherton-Fiber", unit0.Tunnel.RoutingInstance)
	}
	if len(unit0.Tunnel.Addresses) != 1 || unit0.Tunnel.Addresses[0] != "10.255.192.22/30" {
		t.Errorf("unit 0 Tunnel.Addresses = %v, want [10.255.192.22/30]", unit0.Tunnel.Addresses)
	}
	unit1, ok := ifc.Units[1]
	if !ok {
		t.Fatal("unit 1 not found")
	}
	if unit1.Tunnel == nil {
		t.Fatal("unit 1 tunnel config is nil")
	}
	if unit1.Tunnel.Name != "gr-0-0-0u1" {
		t.Errorf("unit 1 Tunnel.Name = %q, want %q", unit1.Tunnel.Name, "gr-0-0-0u1")
	}
	if unit1.Tunnel.Source != "2602:fd41:20:5::351" {
		t.Errorf("unit 1 Tunnel.Source = %q, want 2602:fd41:20:5::351", unit1.Tunnel.Source)
	}
	if unit1.Tunnel.Destination != "2602:ffd3:0:2::7" {
		t.Errorf("unit 1 Tunnel.Destination = %q, want 2602:ffd3:0:2::7", unit1.Tunnel.Destination)
	}
	if unit1.Tunnel.RoutingInstance != "Atherton-Fiber" {
		t.Errorf("unit 1 RoutingInstance = %q, want Atherton-Fiber", unit1.Tunnel.RoutingInstance)
	}
	if len(unit1.Tunnel.Addresses) != 3 {
		t.Errorf("unit 1 Tunnel.Addresses = %v, want 3 entries", unit1.Tunnel.Addresses)
	}
}

// TestClusterNodeIDSet pins #4185: the compiler records whether the
// `chassis cluster node` leaf was actually present (NodeIDSet), so the
// node-identity cross-check can tell an explicit "node 0" from an absent
// leaf (whose NodeID sits at its zero default). RED-on-revert: without the
// NodeIDSet flag the "no node leaf" case below reports NodeIDSet==true.
func TestClusterNodeIDSet(t *testing.T) {
	withLeaf := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
	})
	cfg, err := CompileConfig(withLeaf)
	if err != nil {
		t.Fatalf("CompileConfig(with node leaf): %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.NodeIDSet {
		t.Error("NodeIDSet must be true when `chassis cluster node` is present")
	}
	if cfg.Chassis.Cluster.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", cfg.Chassis.Cluster.NodeID)
	}

	noLeaf := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
	})
	cfg2, err := CompileConfig(noLeaf)
	if err != nil {
		t.Fatalf("CompileConfig(no node leaf): %v", err)
	}
	if cfg2.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil (no leaf)")
	}
	if cfg2.Chassis.Cluster.NodeIDSet {
		t.Error("NodeIDSet must be false when the node leaf is absent (zero default is not node 0)")
	}
}
