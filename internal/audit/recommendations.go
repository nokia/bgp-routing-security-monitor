package audit

import "fmt"

// generateRecommendations applies 7 condition rules to produce actionable advice.
func generateRecommendations(r *RouterAuditReport) []string {
	var recs []string

	// Rule 1: No ROV coverage at all.
	if r.TotalRoutes > 0 && r.ROVCoverage == 0 {
		recs = append(recs, "No ROV coverage detected — connect to an RPKI validator cache (RTR) to enable Route Origin Validation.")
	}

	// Rule 2: ROV coverage exists but is below 50%.
	if r.ROVCoverage > 0 && r.ROVCoverage < 0.5 {
		recs = append(recs, fmt.Sprintf(
			"ROV coverage is low (%.0f%%) — consider adding more RPKI validator caches to improve coverage.",
			r.ROVCoverage*100,
		))
	}

	// Rule 3: Origin-invalid routes are present.
	if n := r.PostureSummary["origin-invalid"]; n > 0 {
		recs = append(recs, fmt.Sprintf(
			"%d origin-invalid route(s) detected — consider deploying a reject-invalid ROV policy to drop these.",
			n,
		))
	}

	// Rule 4: No ASPA coverage at all.
	if r.TotalRoutes > 0 && r.ASPACoverage == 0 {
		recs = append(recs, "No ASPA coverage detected — enable an RTR v2 cache to start AS Path Validation.")
	}

	// Rule 5: ASPA coverage exists but is below 30%.
	if r.ASPACoverage > 0 && r.ASPACoverage < 0.3 {
		recs = append(recs, fmt.Sprintf(
			"ASPA coverage is low (%.0f%%) — encourage BGP neighbors to publish ASPA records to improve path validation.",
			r.ASPACoverage*100,
		))
	}

	// Rule 6: Path-suspect routes are present.
	if n := r.PostureSummary["path-suspect"]; n > 0 {
		recs = append(recs, fmt.Sprintf(
			"%d path-suspect route(s) indicate likely route leaks — consider enforcing ASPA validation to reject these.",
			n,
		))
	}

	// Rule 7: Three or more persistent offender ASNs.
	if len(r.TopOffenders) >= 3 {
		recs = append(recs, fmt.Sprintf(
			"%d persistent offender ASN(s) identified (AS%d, AS%d, AS%d ...) — review prefix/origin filtering for these peers.",
			len(r.TopOffenders),
			r.TopOffenders[0].OriginASN,
			r.TopOffenders[1].OriginASN,
			r.TopOffenders[2].OriginASN,
		))
	}

	if len(recs) == 0 && r.TotalRoutes > 0 {
		recs = append(recs, "No issues found — routing security posture looks healthy.")
	}

	return recs
}
