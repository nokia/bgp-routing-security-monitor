package flowspec

import (
	"encoding/binary"

	api "github.com/osrg/gobgp/v4/api"
)

// BuildFlowspecPath builds a GoBGP api.Path for a destination-prefix
// drop or rate-limit rule (RFC 8955 Type 1 destination prefix + traffic-rate
// extended community). AFI is inferred from prefix (IPv4 → AFI_IP, IPv6 →
// AFI_IP6). If rule.OriginASN > 0, an informational type-12 extended community
// is appended to tag the source AS; this is not a Flowspec match condition.
func BuildFlowspecPath(rule *FlowspecRule) (*api.Path, error) {
	return buildFlowspecPath(rule, false)
}

// BuildFlowspecWithdraw builds the withdrawal Path for GoBGP DeletePath.
func BuildFlowspecWithdraw(rule *FlowspecRule) (*api.Path, error) {
	return buildFlowspecPath(rule, true)
}

func buildFlowspecPath(rule *FlowspecRule, withdraw bool) (*api.Path, error) {
	afi := api.Family_AFI_IP
	if rule.Prefix.Addr().Is6() {
		afi = api.Family_AFI_IP6
	}

	nlri := &api.NLRI{
		Nlri: &api.NLRI_FlowSpec{
			FlowSpec: &api.FlowSpecNLRI{
				Rules: []*api.FlowSpecRule{
					{
						Rule: &api.FlowSpecRule_IpPrefix{
							IpPrefix: &api.FlowSpecIPPrefix{
								Type:      1, // RFC 8955 Type 1 = destination prefix
								PrefixLen: uint32(rule.Prefix.Bits()),
								Prefix:    rule.Prefix.Addr().String(),
								Offset:    0,
							},
						},
					},
				},
			},
		},
	}

	family := &api.Family{
		Afi:  afi,
		Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
	}

	// Determine traffic-rate value: 0 = drop, N = rate-limit in bps.
	var rate float32
	if rule.Action == FlowspecActionRateLimit {
		rate = rule.RateLimit
	}

	communities := []*api.ExtendedCommunity{
		{
			Extcom: &api.ExtendedCommunity_TrafficRate{
				TrafficRate: &api.TrafficRateExtended{
					Asn:  0,
					Rate: rate,
				},
			},
		},
	}

	// Informational type-12 extended community encoding the origin ASN.
	// This is metadata only and is not a Flowspec traffic-match condition.
	if rule.OriginASN > 0 {
		val := make([]byte, 6)
		binary.BigEndian.PutUint32(val[2:], rule.OriginASN)
		communities = append(communities, &api.ExtendedCommunity{
			Extcom: &api.ExtendedCommunity_Unknown{
				Unknown: &api.UnknownExtended{
					Type:  0x0c, // type 12, informational source-AS tag
					Value: val,
				},
			},
		})
	}

	// Flowspec routes have no real nexthop — actions live in the extended
	// communities — but GoBGP's AddPath rejects Flowspec without an
	// MpReachNLRI attribute carrying a zero nexthop.
	nexthop := "0.0.0.0"
	if afi == api.Family_AFI_IP6 {
		nexthop = "::"
	}

	pattrs := []*api.Attribute{
		{
			Attr: &api.Attribute_Origin{
				Origin: &api.OriginAttribute{
					Origin: 2, // INCOMPLETE — matches gobgp CLI behaviour
				},
			},
		},
		{
			Attr: &api.Attribute_MpReach{
				MpReach: &api.MpReachNLRIAttribute{
					Family:   family,
					NextHops: []string{nexthop},
					Nlris:    []*api.NLRI{nlri},
				},
			},
		},
		{
			Attr: &api.Attribute_ExtendedCommunities{
				ExtendedCommunities: &api.ExtendedCommunitiesAttribute{
					Communities: communities,
				},
			},
		},
	}

	return &api.Path{
		Nlri:       nlri,
		Family:     family,
		Pattrs:     pattrs,
		IsWithdraw: withdraw,
	}, nil
}
