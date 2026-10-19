package main

import (
	"fmt"
	"strings"

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
				// #15657 V45-03: min 0 — rollback 0 is the active config,
				// and the operational baseline is ACTIVE (ActiveBaseline).
				n, err := parseRollbackSelector(args[2], "usage: show system rollback compare <N> (0 = active configuration)", 0)
				if err != nil {
					return err
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN:      n,
					ActiveBaseline: true,
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

			// #5052 int32-wrap guard; #15657: min 0 (active config).
			n, err := parseRollbackSelector(args[1], "usage: show system rollback <N> (0 = active configuration)", 0)
			if err != nil {
				return err
			}
			path, pipe, err := splitShowPipe(args[2:])
			if err != nil {
				return err
			}
			if len(pipe) > 0 && pipe[0] == "compare" {
				if len(pipe) != 1 {
					return fmt.Errorf("usage: show system rollback <N> | compare")
				}
				if len(path) > 0 {
					return fmt.Errorf("usage: show system rollback <N> | compare")
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: n, ActiveBaseline: true})
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
			// #15657 V48-02: pre-pipe tokens are the subtree path for
			// display formats (previously a usage error); every
			// display format is allowed and forwarded with the path.
			format, err := parseShowDisplay(pipe, true, true, true)
			if err != nil {
				return err
			}
			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
				N:      n,
				Format: format,
				Path:   path,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			if len(path) > 0 && resp.Output == "" {
				fmt.Printf("configuration path not found: %s\n", strings.Join(path, " "))
			} else {
				fmt.Print(resp.Output)
			}
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
	case "processes":
		summary := len(args) >= 2 && args[1] == "summary"
		if summary {
			return c.showSystemInfo("processes-summary")
		}
		return c.showSystemInfo("processes")
	case "configuration":
		if len(args) >= 2 && args[1] == "rescue" {
			return c.showSystemInfo("rescue-configuration")
		}
		printRemoteTreeHelp("show system configuration:", "show", "system", "configuration")
		return nil
	case "alarms":
		return c.showCommand("show system alarms")
	case "users":
		return c.showSystemInfo("users")
	case "connections":
		return c.showSystemInfo("connections")
	case "storage":
		return c.showCommand("show system storage")
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
