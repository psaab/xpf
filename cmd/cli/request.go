package main

import (
	"fmt"
	"strings"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleRequest(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request:", "request")
		return nil
	}
	switch args[0] {
	case "chassis":
		return c.handleRequestChassis(args[1:])
	case "dhcp":
		return c.handleRequestDHCP(args[1:])
	case "protocols":
		return c.handleRequestProtocols(args[1:])
	case "security":
		return c.handleRequestSecurity(args[1:])
	case "system":
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
	if len(args) < 2 {
		printRemoteTreeHelp("request system:", "request", "system")
		return nil
	}

	switch args[1] {
	case "reboot", "halt", "power-off":
		fmt.Printf("%s the system? [yes,no] (no) ", strings.Title(args[1]))
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Printf("%s cancelled\n", strings.Title(args[1]))
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: args[1],
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "zeroize":
		fmt.Println("WARNING: This will erase all configuration and return to factory defaults.")
		fmt.Print("Zeroize the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Zeroize cancelled")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "zeroize",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "software":
		if len(args) < 3 || args[2] != "in-service-upgrade" {
			printRemoteTreeHelp("request system software:", "request", "system", "software")
			return nil
		}
		fmt.Println("WARNING: This will force this node to secondary for all redundancy groups.")
		fmt.Print("Proceed with in-service upgrade? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("ISSU cancelled")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "in-service-upgrade",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request system command: %s", args[1])
	}
}

func (c *ctl) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		printRemoteTreeHelp("request chassis:", "request", "chassis")
		return nil
	}
	args = args[1:]
	if len(args) == 0 {
		printRemoteTreeHelp("request chassis cluster:", "request", "chassis", "cluster")
		return nil
	}
	switch args[0] {
	case "failover":
		return c.handleRequestChassisClusterFailover(args[1:])
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		printRemoteTreeHelp("request chassis cluster:", "request", "chassis", "cluster")
		return nil
	}
}

func (c *ctl) handleRequestChassisClusterFailover(args []string) error {
	if len(args) >= 1 && args[0] == "reset" {
		if len(args) < 3 || args[1] != "redundancy-group" {
			return fmt.Errorf("usage: request chassis cluster failover reset redundancy-group <N>")
		}
		action := "cluster-failover-reset:" + args[2]
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}

	if len(args) >= 3 && args[0] == "data" && args[1] == "node" {
		action := "cluster-failover-data:node" + args[2]
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}

	if len(args) >= 2 && args[0] == "redundancy-group" {
		actionSuffix := args[1]
		if len(args) >= 4 && args[2] == "node" {
			actionSuffix += ":node" + args[3]
		}
		action := "cluster-failover:" + actionSuffix
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}

	return fmt.Errorf("usage: request chassis cluster failover {redundancy-group <N> [node <N>] | data node <N>}")
}

func (c *ctl) handleRequestChassisClusterDataPlane(args []string) error {
	if len(args) == 0 || args[0] != "userspace" {
		printRemoteTreeHelp("request chassis cluster data-plane:", "request", "chassis", "cluster", "data-plane")
		return nil
	}
	args = args[1:]
	var action string
	var target string
	switch {
	case len(args) > 0 && args[0] == "inject-packet":
		slot, mode, extra, err := dpuserspace.ParseInjectPacketCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-inject:%d:%s", slot, mode)
		target = dpuserspace.EncodeInjectPacketTarget(extra)
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		if armed {
			action = "userspace-forwarding:arm"
		} else {
			action = "userspace-forwarding:disarm"
		}
	case len(args) > 0 && args[0] == "queue":
		queueID, _, _, err := dpuserspace.ParseQueueCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-queue:%d:%s", queueID, strings.ToLower(args[2]))
	case len(args) > 0 && args[0] == "binding":
		slot, _, _, err := dpuserspace.ParseBindingCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-binding:%d:%s", slot, strings.ToLower(args[3]))
	default:
		printRemoteTreeHelp("request chassis cluster data-plane userspace:", "request", "chassis", "cluster", "data-plane", "userspace")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: action,
		Target: target,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		printRemoteTreeHelp("request dhcp:", "request", "dhcp")
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "dhcp-renew",
		Target: args[1],
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request protocols:", "request", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols ospf:", "request", "protocols", "ospf")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "ospf-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "bgp":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols bgp:", "request", "protocols", "bgp")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "bgp-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request protocols target: %s", args[0])
	}
}

func (c *ctl) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request security:", "request", "security")
		return nil
	}
	if args[0] != "ipsec" {
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
	if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
		printRemoteTreeHelp("request security ipsec sa:", "request", "security", "ipsec", "sa")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "ipsec-sa-clear",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}
