package stats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnit_Deserialize(t *testing.T) {
	testCases := []struct {
		db   *unitDB
		name string
		want unit
	}{{
		name: "empty",
		want: unit{
			domains:            map[string]uint64{},
			blockedDomains:     map[string]uint64{},
			clients:            map[string]uint64{},
			nResult:            []uint64{0, 0, 0, 0, 0, 0},
			id:                 0,
			nTotal:             0,
			timeSum:            0,
			upstreamsResponses: map[string]uint64{},
			upstreamsTimeSum:   map[string]uint64{},
		},
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
	}, {
		name: "basic",
		want: unit{
			domains: map[string]uint64{
				"example.com": 1,
			},
			blockedDomains: map[string]uint64{
				"example.net": 1,
			},
			clients: map[string]uint64{
				"127.0.0.1": 2,
			},
			nResult: []uint64{0, 1, 1, 0, 0, 0},
			id:      0,
			nTotal:  2,
			timeSum: 246912,
			upstreamsResponses: map[string]uint64{
				"1.2.3.4": 2,
			},
			upstreamsTimeSum: map[string]uint64{
				"1.2.3.4": 246912,
			},
		},
		db: &unitDB{
			NResult: []uint64{0, 1, 1, 0, 0, 0},
			Domains: []countPair{{
				"example.com", 1,
			}},
			BlockedDomains: []countPair{{
				"example.net", 1,
			}},
			Clients: []countPair{{
				"127.0.0.1", 2,
			}},
			NTotal:  2,
			TimeAvg: 123456,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := unit{}
			got.deserialize(tc.db)
			require.Equal(t, tc.want, got)
		})
	}
}
