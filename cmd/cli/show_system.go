package main

import (
	"fmt"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleShowSystem(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show system:", "show", "system")
		return nil
	}

	switch args[0] {
	case "commit":
		if len(args) >= 2 && args[1] == "history" {
			return c.showCommand("show system commit history")
		}
		printRemoteTreeHelp("show system commit:", "show", "system", "commit")
		return nil

	case "rollback":
		if len(args) >= 2 {
			if args[1] == "compare" {
				if len(args) != 3 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				// #5052: parse the slot into the int32 the RPC carries.
				// strconv.Atoi + int32() wrapped an out-of-range value
				// (e.g. 4294967297 -> 1) and silently compared the wrong
				// slot with a success exit. The shared parser rejects it.
				n, err := parseRollbackSelector(args[2], "usage: show system rollback compare <N>", 1)
				if err != nil {
					return err
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN: n,
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}

			// #5052: same int32-wrap guard as the compare selector above.
			n, err := parseRollbackSelector(args[1], "usage: show system rollback <N>", 1)
			if err != nil {
				return err
			}
			path, pipe, err := splitShowPipe(args[2:])
			if err != nil {
				return err
			}
			if len(path) > 0 {
				return fmt.Errorf("usage: show system rollback <N> [| display set|xml | compare]")
			}
			if len(pipe) > 0 && pipe[0] == "compare" {
				if len(pipe) != 1 {
					return fmt.Errorf("usage: show system rollback <N> | compare")
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: n})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}
			format, err := parseShowDisplay(pipe, false, false, false)
			if err != nil {
				return err
			}
			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
				N:      n,
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}

		resp, err := c.client.ListHistory(c.ctx(), &pb.ListHistoryRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if len(resp.Entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for _, e := range resp.Entries {
			fmt.Printf("  rollback %d: %s\n", e.Index, e.Timestamp)
		}
		return nil

	case "uptime":
		return c.showSystemInfo("uptime")
	case "memory":
		return c.showSystemInfo("memory")
	case "storage":
		return c.showCommand("show system storage")
	case "processes":
		return c.showSystemInfo("processes")
	case "alarms":
		return c.showCommand("show system alarms")
	case "users":
		return c.showSystemInfo("users")
	case "connections":
		return c.showSystemInfo("connections")
	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil
	case "services":
		return c.showCommand("show system services")
	case "ntp":
		return c.showCommand("show system ntp")
	case "login":
		return c.showCommand("show system login")
	case "syslog":
		return c.showCommand("show system syslog")
	case "internet-options":
		return c.showCommand("show system internet-options")
	case "root-authentication":
		return c.showCommand("show system root-authentication")
	case "backup-router":
		return c.showCommand("show system backup-router")
	case "buffers":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showCommand("show system buffers detail")
		}
		return c.showCommand("show system buffers")
	case "boot-messages":
		return c.showSystemInfo("boot-messages")
	case "core-dumps":
		return c.showCommand("show system core-dumps")
	case "kernel-upgrade":
		// #6495: the #1930 kernel-channel state, rendered daemon-side through
		// pkg/upgrade — the same implementation the console CLI uses.
		return c.showCommand("show system kernel-upgrade")
	case "bootstrap-import":
		// #6496: the day-0 config-import verdict. Rendered daemon-side through
		// pkg/bootstrapshow — the same implementation the in-process console
		// CLI uses — so the two clients cannot show different answers.
		return c.showCommand("show system bootstrap-import")
	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}
