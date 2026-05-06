package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/tabwriter"
)

// FormatTable renders the report as a human-readable table using text/tabwriter.
func FormatTable(r *RouterAuditReport) string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "\n  ROUTER AUDIT REPORT\n")
	fmt.Fprintf(&buf, "  ─────────────────────────────────────────────────\n")
	fmt.Fprintf(&buf, "  Router ID:     %s\n", r.RouterID)
	fmt.Fprintf(&buf, "  Generated At:  %s\n", r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&buf, "  Total Routes:  %d\n", r.TotalRoutes)
	fmt.Fprintf(&buf, "  ROV Coverage:  %.1f%%\n", r.ROVCoverage*100)
	fmt.Fprintf(&buf, "  ASPA Coverage: %.1f%%\n\n", r.ASPACoverage*100)

	if len(r.PostureSummary) > 0 {
		fmt.Fprintln(&buf, "  POSTURE SUMMARY")
		tw := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "  POSTURE\tCOUNT\t%")
		for _, posture := range []string{"secured", "origin-only", "path-only", "unverified", "path-suspect", "origin-invalid"} {
			if n := r.PostureSummary[posture]; n > 0 {
				pct := 0.0
				if r.TotalRoutes > 0 {
					pct = float64(n) / float64(r.TotalRoutes) * 100
				}
				fmt.Fprintf(tw, "  %s\t%d\t%.1f%%\n", posture, n, pct)
			}
		}
		tw.Flush()
		fmt.Fprintln(&buf)
	}

	if len(r.Peers) > 0 {
		fmt.Fprintln(&buf, "  PEERS")
		tw := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "  PEER\tASN\tROUTES\tROV\tASPA")
		for _, p := range r.Peers {
			fmt.Fprintf(tw, "  %s\tAS%d\t%d\t%.0f%%\t%.0f%%\n",
				p.PeerAddr, p.PeerASN, p.TotalRoutes, p.ROVCoverage*100, p.ASPACoverage*100)
		}
		tw.Flush()
		fmt.Fprintln(&buf)
	}

	if len(r.TopOffenders) > 0 {
		fmt.Fprintln(&buf, "  TOP OFFENDERS")
		tw := tabwriter.NewWriter(&buf, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "  ORIGIN ASN\tCOUNT\tWORST POSTURE\tEXAMPLE PREFIXES")
		for _, o := range r.TopOffenders {
			prefixes := "-"
			if len(o.Prefixes) > 0 {
				prefixes = o.Prefixes[0]
				if len(o.Prefixes) > 1 {
					prefixes += fmt.Sprintf(" (+%d more)", len(o.Prefixes)-1)
				}
			}
			fmt.Fprintf(tw, "  AS%d\t%d\t%s\t%s\n", o.OriginASN, o.Count, o.Posture, prefixes)
		}
		tw.Flush()
		fmt.Fprintln(&buf)
	}

	if len(r.Recommendations) > 0 {
		fmt.Fprintln(&buf, "  RECOMMENDATIONS")
		for i, rec := range r.Recommendations {
			fmt.Fprintf(&buf, "  %d. %s\n", i+1, rec)
		}
		fmt.Fprintln(&buf)
	}

	return buf.String()
}

// FormatJSON renders the report as indented JSON.
func FormatJSON(r *RouterAuditReport) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// FormatMarkdown renders the report as GitHub-Flavored Markdown.
func FormatMarkdown(r *RouterAuditReport) string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# Router Audit Report: %s\n\n", r.RouterID)
	fmt.Fprintf(&buf, "Generated: %s\n\n", r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintln(&buf, "| Metric | Value |")
	fmt.Fprintln(&buf, "|---|---|")
	fmt.Fprintf(&buf, "| Total Routes | %d |\n", r.TotalRoutes)
	fmt.Fprintf(&buf, "| ROV Coverage | %.1f%% |\n", r.ROVCoverage*100)
	fmt.Fprintf(&buf, "| ASPA Coverage | %.1f%% |\n\n", r.ASPACoverage*100)

	if len(r.PostureSummary) > 0 {
		fmt.Fprintf(&buf, "## Posture Summary\n\n")
		fmt.Fprintln(&buf, "| Posture | Count | % |")
		fmt.Fprintln(&buf, "|---|---|---|")
		for _, posture := range []string{"secured", "origin-only", "path-only", "unverified", "path-suspect", "origin-invalid"} {
			if n := r.PostureSummary[posture]; n > 0 {
				pct := 0.0
				if r.TotalRoutes > 0 {
					pct = float64(n) / float64(r.TotalRoutes) * 100
				}
				fmt.Fprintf(&buf, "| %s | %d | %.1f%% |\n", posture, n, pct)
			}
		}
		fmt.Fprintln(&buf)
	}

	if len(r.Peers) > 0 {
		fmt.Fprintf(&buf, "## Peers\n\n")
		fmt.Fprintln(&buf, "| Peer | ASN | Routes | ROV | ASPA |")
		fmt.Fprintln(&buf, "|---|---|---|---|---|")
		for _, p := range r.Peers {
			fmt.Fprintf(&buf, "| %s | AS%d | %d | %.0f%% | %.0f%% |\n",
				p.PeerAddr, p.PeerASN, p.TotalRoutes, p.ROVCoverage*100, p.ASPACoverage*100)
		}
		fmt.Fprintln(&buf)
	}

	if len(r.TopOffenders) > 0 {
		fmt.Fprintf(&buf, "## Top Offenders\n\n")
		fmt.Fprintln(&buf, "| Origin ASN | Count | Worst Posture | Example Prefixes |")
		fmt.Fprintln(&buf, "|---|---|---|---|")
		for _, o := range r.TopOffenders {
			prefixes := "-"
			if len(o.Prefixes) > 0 {
				prefixes = o.Prefixes[0]
				if len(o.Prefixes) > 1 {
					prefixes += fmt.Sprintf(" (+%d more)", len(o.Prefixes)-1)
				}
			}
			fmt.Fprintf(&buf, "| AS%d | %d | %s | %s |\n", o.OriginASN, o.Count, o.Posture, prefixes)
		}
		fmt.Fprintln(&buf)
	}

	if len(r.Recommendations) > 0 {
		fmt.Fprintf(&buf, "## Recommendations\n\n")
		for _, rec := range r.Recommendations {
			fmt.Fprintf(&buf, "- %s\n", rec)
		}
		fmt.Fprintln(&buf)
	}

	return buf.String()
}
