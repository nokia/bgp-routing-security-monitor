package audit

import (
	"sort"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

const maxOffenders = 10
const maxOffenderPrefixes = 5

// postureOrder maps a posture string to a severity rank (lower = worse).
var postureOrder = map[string]int{
	"origin-invalid": 0,
	"path-suspect":   1,
	"path-only":      2,
	"unverified":     3,
	"origin-only":    4,
	"secured":        5,
}

// Analyze computes a RouterAuditReport for the given peer address from the supplied
// route slice (typically routetable.Table.AllPrePolicy()).
// An empty peerAddr matches all routes. It is a pure function: no I/O,
// no side-effects, safe to call from tests.
func Analyze(peerAddr string, routes []*types.Route) *RouterAuditReport {
	var local []*types.Route
	for _, r := range routes {
		if peerAddr == "" || r.PeerAddr.String() == peerAddr {
			local = append(local, r)
		}
	}

	report := &RouterAuditReport{
		RouterID:       peerAddr,
		GeneratedAt:    time.Now(),
		TotalRoutes:    len(local),
		PostureSummary: make(map[string]int),
	}

	if len(local) == 0 {
		report.Recommendations = generateRecommendations(report)
		return report
	}

	type peerAccum struct {
		peerASN  uint32
		total    int
		rovCov   int
		aspaCov  int
		postures map[string]int
	}
	peers := make(map[string]*peerAccum)

	type offenderAccum struct {
		count    int
		posture  string
		prefixes []string
	}
	offenders := make(map[uint32]*offenderAccum)

	var rovCovered, aspaCovered int

	for _, r := range local {
		posture := string(r.SecurityPosture)
		if posture == "" {
			posture = "unverified"
		}

		report.PostureSummary[posture]++

		if r.ROV.State != types.ROVNotFound {
			rovCovered++
		}
		if r.ASPA.State != types.ASPAUnknown {
			aspaCovered++
		}

		peerKey := r.PeerAddr.String()
		if peers[peerKey] == nil {
			peers[peerKey] = &peerAccum{
				peerASN:  r.PeerASN,
				postures: make(map[string]int),
			}
		}
		pa := peers[peerKey]
		pa.total++
		pa.postures[posture]++
		if r.ROV.State != types.ROVNotFound {
			pa.rovCov++
		}
		if r.ASPA.State != types.ASPAUnknown {
			pa.aspaCov++
		}

		if posture == "origin-invalid" || posture == "path-suspect" {
			asn := r.OriginASN()
			if asn == 0 {
				asn = r.PeerASN
			}
			if asn != 0 {
				off := offenders[asn]
				if off == nil {
					off = &offenderAccum{}
					offenders[asn] = off
				}
				off.count++
				if off.posture == "" || postureOrder[posture] < postureOrder[off.posture] {
					off.posture = posture
				}
				if len(off.prefixes) < maxOffenderPrefixes {
					off.prefixes = append(off.prefixes, r.Prefix.String())
				}
			}
		}
	}

	total := len(local)
	report.ROVCoverage = float64(rovCovered) / float64(total)
	report.ASPACoverage = float64(aspaCovered) / float64(total)

	for peerKey, pa := range peers {
		pr := PeerAuditReport{
			PeerAddr:       peerKey,
			PeerASN:        pa.peerASN,
			TotalRoutes:    pa.total,
			PostureSummary: pa.postures,
		}
		if pa.total > 0 {
			pr.ROVCoverage = float64(pa.rovCov) / float64(pa.total)
			pr.ASPACoverage = float64(pa.aspaCov) / float64(pa.total)
		}
		report.Peers = append(report.Peers, pr)
	}
	sort.Slice(report.Peers, func(i, j int) bool {
		return report.Peers[i].TotalRoutes > report.Peers[j].TotalRoutes
	})

	type kv struct {
		asn  uint32
		data *offenderAccum
	}
	var offList []kv
	for asn, data := range offenders {
		offList = append(offList, kv{asn, data})
	}
	sort.Slice(offList, func(i, j int) bool {
		if offList[i].data.count != offList[j].data.count {
			return offList[i].data.count > offList[j].data.count
		}
		return offList[i].asn < offList[j].asn
	})
	if len(offList) > maxOffenders {
		offList = offList[:maxOffenders]
	}
	for _, item := range offList {
		report.TopOffenders = append(report.TopOffenders, OffenderEntry{
			OriginASN: item.asn,
			Count:     item.data.count,
			Posture:   item.data.posture,
			Prefixes:  item.data.prefixes,
		})
	}

	report.Recommendations = generateRecommendations(report)
	return report
}
