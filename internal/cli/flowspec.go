package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"
)

// flowspecRuleResponse mirrors api.FlowspecRuleResponse for CLI decoding.
type flowspecRuleResponse struct {
	Key        string    `json:"key"`
	Prefix     string    `json:"prefix"`
	OriginASN  uint32    `json:"origin_asn"`
	PeerAddr   string    `json:"peer_addr"`
	Action     string    `json:"action"`
	InsertedAt time.Time `json:"inserted_at"`
	TTLSeconds int64     `json:"ttl_seconds"`
	ExpiresAt  time.Time `json:"expires_at"`
	DryRun     bool      `json:"dry_run"`
	EventID    string    `json:"event_id"`
}

func newFlowspecCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flowspec",
		Short: "Manage active Flowspec mitigation rules",
	}
	cmd.AddCommand(newFlowspecListCmd(addr))
	cmd.AddCommand(newFlowspecToggleCmd(addr))
	return cmd
}

func newFlowspecListCmd(addr *string) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all active Flowspec rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := apiGet(*addr, "/api/v1/flowspec/rules", nil)
			if err != nil {
				return fmt.Errorf("flowspec list: %w", err)
			}
			defer resp.Body.Close()

			var rules []flowspecRuleResponse
			if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
				return fmt.Errorf("flowspec list: decode: %w", err)
			}

			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rules)
			}

			printFlowspecTable(rules)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")
	return cmd
}

func newFlowspecToggleCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:   "toggle <key>",
		Short: "Toggle dry-run on a Flowspec rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			encoded := url.PathEscape(key)
			path := fmt.Sprintf("/api/v1/flowspec/rules/%s/toggle-dryrun", encoded)

			resp, err := apiPost(*addr, path)
			if err != nil {
				return fmt.Errorf("flowspec toggle: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 404 {
				return fmt.Errorf("flowspec toggle: rule not found: %s", key)
			}
			if resp.StatusCode >= 400 {
				return fmt.Errorf("flowspec toggle: server returned %d", resp.StatusCode)
			}

			var rule flowspecRuleResponse
			if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
				return fmt.Errorf("flowspec toggle: decode: %w", err)
			}

			printFlowspecToggleResult(key, rule)
			return nil
		},
	}
}

// ANSI helpers.
const (
	ansiAmber = "\033[33m"
	ansiRed   = "\033[0;31m"
	ansiBold  = "\033[1m"
	ansiReset = "\033[0m"
)

func dryRunLabel(dryRun bool) string {
	if dryRun {
		return ansiAmber + "yes" + ansiReset
	}
	return ansiRed + ansiBold + "LIVE" + ansiReset
}

func ttlRemaining(expiresAt time.Time) string {
	return max(time.Until(expiresAt), 0).Round(time.Second).String()
}

func printFlowspecTable(rules []flowspecRuleResponse) {
	if len(rules) == 0 {
		fmt.Println("No active Flowspec rules.")
		return
	}

	fmt.Println("RAVEN Flowspec Rules")
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Printf("%-30s %-7s %-8s %-10s %s\n", "KEY", "ACTION", "DRY-RUN", "TTL", "INSERTED")
	for _, r := range rules {
		fmt.Printf("%-30s %-7s %-8s %-10s %s\n",
			r.Key,
			r.Action,
			dryRunLabel(r.DryRun),
			ttlRemaining(r.ExpiresAt),
			r.InsertedAt.Local().Format("2006-01-02 15:04:05"),
		)
	}
	fmt.Println()

	allDryRun := true
	for _, r := range rules {
		if !r.DryRun {
			allDryRun = false
			break
		}
	}
	suffix := ""
	if allDryRun {
		suffix = "  (dry-run mode — no live injection)"
	}
	n := len(rules)
	s := "s"
	if n == 1 {
		s = ""
	}
	fmt.Printf("%d active rule%s%s\n", n, s, suffix)
}

func printFlowspecToggleResult(key string, rule flowspecRuleResponse) {
	fmt.Printf("\n  Rule: %s\n", key)
	if rule.DryRun {
		fmt.Printf("  Dry-run: LIVE → yes (withdrawn from GoBGP)\n\n")
	} else {
		fmt.Printf("  Dry-run: yes → LIVE\n\n")
		fmt.Printf("  ⚠  Live injection enabled. Flowspec rule is now active in GoBGP.\n")
		fmt.Printf("     Run 'raven flowspec toggle \"%s\"' again to\n", key)
		fmt.Printf("     withdraw and return to dry-run mode.\n\n")
	}
}
