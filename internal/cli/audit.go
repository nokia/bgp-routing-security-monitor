package cli

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/nokia/bgp-routing-security-monitor/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd(addr *string) *cobra.Command {
	var router, format string

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Security posture audit for a specific router",
		Long: `Run a read-only security posture audit for a single router.

  raven audit --router 10.0.0.1
  raven audit --router 10.0.0.1 --format json
  raven audit --router 10.0.0.1 --format markdown`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if router == "" {
				return fmt.Errorf("--router is required")
			}

			params := url.Values{"router": {router}}
			resp, err := apiGet(*addr, "/api/v1/audit", params)
			if err != nil {
				return fmt.Errorf("audit: %w", err)
			}
			defer resp.Body.Close()

			var report audit.RouterAuditReport
			if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
				return fmt.Errorf("audit: decode: %w", err)
			}

			switch format {
			case "json":
				out, err := audit.FormatJSON(&report)
				if err != nil {
					return fmt.Errorf("audit: format json: %w", err)
				}
				fmt.Println(out)
			case "markdown":
				fmt.Print(audit.FormatMarkdown(&report))
			default:
				fmt.Print(audit.FormatTable(&report))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&router, "router", "", "Router ID to audit (required)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json|markdown")

	return cmd
}
