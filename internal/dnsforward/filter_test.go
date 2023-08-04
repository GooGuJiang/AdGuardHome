package dnsforward

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleDNSRequest_handleDNSRequest(t *testing.T) {
	rules := `
||blocked.domain^
@@||allowed.domain^
||cname.specific^$dnstype=~CNAME
||0.0.0.1^$dnstype=~A
||::1^$dnstype=~AAAA
0.0.0.0 duplicate.domain
0.0.0.0 duplicate.domain
`

	forwardConf := ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		FilteringConfig: FilteringConfig{
			ProtectionEnabled: true,
			BlockingMode:      BlockingModeDefault,
			EDNSClientSubnet: &EDNSClientSubnet{
				Enabled: false,
			},
		},
	}
	filters := []filtering.Filter{{
		ID: 0, Data: []byte(rules),
	}}

	f, err := filtering.New(&filtering.Config{}, filters)
	require.NoError(t, err)
	f.SetEnabled(true)

	s, err := NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   f,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	err = s.Prepare(&forwardConf)
	require.NoError(t, err)

	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{
		&aghtest.Upstream{
			CName: map[string][]string{
				"cname.exception.": {"cname.specific."},
				"should.block.":    {"blocked.domain."},
				"allowed.first.":   {"allowed.domain.", "blocked.domain."},
				"blocked.first.":   {"blocked.domain.", "allowed.domain."},
			},
			IPv4: map[string][]net.IP{
				"a.exception.": {{0, 0, 0, 1}},
			},
			IPv6: map[string][]net.IP{
				"aaaa.exception.": {net.ParseIP("::1")},
			},
		},
	}
	startDeferStop(t, s)

	testCases := []struct {
		req     *dns.Msg
		name    string
		wantAns []dns.RR
	}{{
		req:  createTestMessage("cname.exception."),
		name: "cname_exception",
		wantAns: []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "cname.exception.",
				Rrtype: dns.TypeCNAME,
			},
			Target: "cname.specific.",
		}},
	}, {
		req:  createTestMessage("should.block."),
		name: "blocked_by_cname",
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "should.block.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: netutil.IPv4Zero(),
		}},
	}, {
		req:  createTestMessage("a.exception."),
		name: "a_exception",
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "a.exception.",
				Rrtype: dns.TypeA,
			},
			A: net.IP{0, 0, 0, 1},
		}},
	}, {
		req:  createTestMessageWithType("aaaa.exception.", dns.TypeAAAA),
		name: "aaaa_exception",
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "aaaa.exception.",
				Rrtype: dns.TypeAAAA,
			},
			AAAA: net.ParseIP("::1"),
		}},
	}, {
		req:  createTestMessage("allowed.first."),
		name: "allowed_first",
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "allowed.first.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: netutil.IPv4Zero(),
		}},
	}, {
		req:  createTestMessage("blocked.first."),
		name: "blocked_first",
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "blocked.first.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: netutil.IPv4Zero(),
		}},
	}, {
		req:  createTestMessage("duplicate.domain."),
		name: "duplicate_domain",
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   "duplicate.domain.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: netutil.IPv4Zero(),
		}},
	}}

	for _, tc := range testCases {
		dctx := &proxy.DNSContext{
			Proto: proxy.ProtoUDP,
			Req:   tc.req,
			Addr:  &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1},
		}

		t.Run(tc.name, func(t *testing.T) {
			err = s.handleDNSRequest(nil, dctx)
			require.NoError(t, err)
			require.NotNil(t, dctx.Res)

			assert.Equal(t, tc.wantAns, dctx.Res.Answer)
		})
	}
}

func TestHandleDNSRequest_filterDNSResponse(t *testing.T) {
	const (
		passedIPv4Str  = "1.1.1.1"
		blockedIPv4Str = "1.2.3.4"
		blockedIPv6Str = "1234::cdef"
		blockRules     = blockedIPv4Str + "\n" + blockedIPv6Str + "\n"
	)

	var (
		passedIPv4  net.IP = netip.MustParseAddr(passedIPv4Str).AsSlice()
		blockedIPv4 net.IP = netip.MustParseAddr(blockedIPv4Str).AsSlice()
		blockedIPv6 net.IP = netip.MustParseAddr(blockedIPv6Str).AsSlice()
	)

	filters := []filtering.Filter{{
		ID: 0, Data: []byte(blockRules),
	}}

	f, err := filtering.New(&filtering.Config{}, filters)
	require.NoError(t, err)

	f.SetEnabled(true)

	s, err := NewServer(DNSCreateParams{
		DHCPServer:  testDHCP,
		DNSFilter:   f,
		PrivateNets: netutil.SubnetSetFunc(netutil.IsLocallyServed),
	})
	require.NoError(t, err)

	testCases := []struct {
		name     string
		reqFQDN  string
		wantRule string
		respAns  []dns.RR
		qType    uint16
	}{{
		name:     "pass",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: "",
		respAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: passedIPv4,
		}},
		qType: dns.TypeA,
	}, {
		name:     "ipv4",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: blockedIPv4Str,
		respAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: blockedIPv4,
		}},
		qType: dns.TypeA,
	}, {
		name:     "ipv6",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: blockedIPv6Str,
		respAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
			},
			AAAA: blockedIPv6,
		}},
		qType: dns.TypeAAAA,
	}, {
		name:     "ipv4hint",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: blockedIPv4Str,
		respAns: []dns.RR{&dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
			},
			Target: aghtest.ReqFQDN,
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{blockedIPv4}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{}},
			},
		}},
		qType: dns.TypeHTTPS,
	}, {
		name:     "ipv6hint",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: blockedIPv6Str,
		respAns: []dns.RR{&dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
			},
			Target: aghtest.ReqFQDN,
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{blockedIPv6}},
			},
		}},
		qType: dns.TypeHTTPS,
	}, {
		name:     "ipv4_ipv6_hints",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: blockedIPv4Str,
		respAns: []dns.RR{&dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
			},
			Target: aghtest.ReqFQDN,
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{blockedIPv4}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{blockedIPv6}},
			},
		}},
		qType: dns.TypeHTTPS,
	}, {
		name:     "pass_hints",
		reqFQDN:  aghtest.ReqFQDN,
		wantRule: "",
		respAns: []dns.RR{&dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   aghtest.ReqFQDN,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
			},
			Target: aghtest.ReqFQDN,
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{passedIPv4}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{}},
			},
		}},
		qType: dns.TypeHTTPS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := createTestMessageWithType(tc.reqFQDN, tc.qType)
			resp := newResp(dns.RcodeSuccess, req, tc.respAns)

			pctx := &proxy.DNSContext{
				Proto: proxy.ProtoUDP,
				Req:   req,
				Res:   resp,
				Addr:  &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1},
			}

			res, rErr := s.filterDNSResponse(pctx, &filtering.Settings{
				ProtectionEnabled: true,
				FilteringEnabled:  true,
			})
			require.NoError(t, rErr)

			if tc.wantRule == "" {
				assert.Nil(t, res)

				return
			}

			want := &filtering.Result{
				IsFiltered: true,
				Reason:     filtering.FilteredBlockList,
				Rules: []*filtering.ResultRule{{
					Text: tc.wantRule,
				}},
			}
			assert.Equal(t, want, res)
		})
	}
}
