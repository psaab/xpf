package main

import (
	"fmt"
)

func (c *ctl) handleShowServices(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show services:", "show", "services")
		return nil
	}
	switch args[0] {
	case "rpm":
		return c.showCommand("show services rpm")
	case "ip-monitoring":
		// #1827: only `ip-monitoring status` is valid per cmdtree.
		rest := args[1:]
		if len(rest) == 0 {
			printRemoteTreeHelp("show services ip-monitoring:", "show", "services", "ip-monitoring")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown ip-monitoring target: %s (expected `status`)", rest[0])
		}
		return c.showCommand("show services ip-monitoring status")
	case "application-identification":
		// #653: surface what xpf AppID actually does today. Per
		// cmdtree the only valid leaf is `application-identification
		// status`; reject anything else so typos surface as usage
		// errors instead of being silently swallowed.
		rest := args[1:]
		if len(rest) == 0 {
			printRemoteTreeHelp("show services application-identification:",
				"show", "services", "application-identification")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown application-identification target: %s "+
				"(expected `status`)", rest[0])
		}
		return c.showCommand("show services application-identification status")
	case "user-identification":
		// #16078: only `user-identification status` is valid.
		rest := args[1:]
		if len(rest) == 0 {
			printRemoteTreeHelp("show services user-identification:",
				"show", "services", "user-identification")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown user-identification target: %s "+
				"(expected `status`)", rest[0])
		}
		return c.showCommand("show services user-identification status")
	case "dynamic-dns":
		// #2691 P2: Surface A (router/interface-address) DDNS status.
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show services dynamic-dns detail")
		}
		return c.showCommand("show services dynamic-dns")
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}
