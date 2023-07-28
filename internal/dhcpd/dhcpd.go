// Package dhcpd provides a DHCP server.
package dhcpd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/exp/slices"
)

const (
	// DefaultDHCPLeaseTTL is the default time-to-live for leases.
	DefaultDHCPLeaseTTL = uint32(timeutil.Day / time.Second)

	// DefaultDHCPTimeoutICMP is the default timeout for waiting ICMP responses.
	DefaultDHCPTimeoutICMP = 1000
)

// Currently used defaults for ifaceDNSAddrs.
const (
	defaultMaxAttempts int           = 10
	defaultBackoff     time.Duration = 500 * time.Millisecond
)

// Lease contains the necessary information about a DHCP lease.  It's used as is
// in the database, so don't change it until it's absolutely necessary, see
// [dataVersion].
type Lease struct {
	// Expiry is the expiration time of the lease.
	Expiry time.Time `json:"expires"`

	// Hostname of the client.
	Hostname string `json:"hostname"`

	// HWAddr is the physical hardware address (MAC address).
	HWAddr net.HardwareAddr `json:"mac"`

	// IP is the IP address leased to the client.
	IP netip.Addr `json:"ip"`

	// IsStatic defines if the lease is static.
	IsStatic bool `json:"static"`
}

// Clone returns a deep copy of l.
func (l *Lease) Clone() (clone *Lease) {
	if l == nil {
		return nil
	}

	return &Lease{
		Expiry:   l.Expiry,
		Hostname: l.Hostname,
		HWAddr:   slices.Clone(l.HWAddr),
		IP:       l.IP,
		IsStatic: l.IsStatic,
	}
}

// IsBlocklisted returns true if the lease is blocklisted.
//
// TODO(a.garipov): Just make it a boolean field.
func (l *Lease) IsBlocklisted() (ok bool) {
	if len(l.HWAddr) == 0 {
		return false
	}

	for _, b := range l.HWAddr {
		if b != 0 {
			return false
		}
	}

	return true
}

// MarshalJSON implements the json.Marshaler interface for Lease.
func (l Lease) MarshalJSON() ([]byte, error) {
	var expiryStr string
	if !l.IsStatic {
		// The front-end is waiting for RFC 3999 format of the time
		// value.  It also shouldn't got an Expiry field for static
		// leases.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/2692.
		expiryStr = l.Expiry.Format(time.RFC3339)
	}

	type lease Lease
	return json.Marshal(&struct {
		HWAddr string `json:"mac"`
		Expiry string `json:"expires,omitempty"`
		lease
	}{
		HWAddr: l.HWAddr.String(),
		Expiry: expiryStr,
		lease:  lease(l),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for *Lease.
func (l *Lease) UnmarshalJSON(data []byte) (err error) {
	type lease Lease
	aux := struct {
		*lease
		HWAddr string `json:"mac"`
	}{
		lease: (*lease)(l),
	}
	if err = json.Unmarshal(data, &aux); err != nil {
		return err
	}

	l.HWAddr, err = net.ParseMAC(aux.HWAddr)
	if err != nil {
		return fmt.Errorf("couldn't parse MAC address: %w", err)
	}

	return nil
}

// OnLeaseChangedT is a callback for lease changes.
type OnLeaseChangedT func(flags int)

// flags for onLeaseChanged()
const (
	LeaseChangedAdded = iota
	LeaseChangedAddedStatic
	LeaseChangedRemovedStatic
	LeaseChangedRemovedAll

	LeaseChangedDBStore
)

// GetLeasesFlags are the flags for GetLeases.
type GetLeasesFlags uint8

// GetLeasesFlags values
const (
	LeasesDynamic GetLeasesFlags = 0b01
	LeasesStatic  GetLeasesFlags = 0b10

	LeasesAll = LeasesDynamic | LeasesStatic
)

// Interface is the DHCP server that deals with both IP address families.
type Interface interface {
	Start() (err error)
	Stop() (err error)

	// Enabled returns true if the is running.
	//
	// TODO(e.burkov):  Currently, we need this method to determine whether the
	// local domain suffix should be considered while resolving A/AAAA requests.
	// This is because other parts of the code aren't aware of the DNS suffixes
	// in DHCP clients names and caller is responsible for trimming it.  This
	// behavior may change in the future.
	Enabled() (ok bool)

	// Leases returns all the leases in the database.
	Leases() (leases []*dhcpsvc.Lease)

	// MacByIP returns the MAC address of a client with ip.  It returns nil if
	// there is no such client, due to an assumption that a DHCP client must
	// always have a HardwareAddr.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have an IP address.
	HostByIP(ip netip.Addr) (host string)

	// IPByHost returns the IP address of the DHCP client with the given
	// hostname.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have an IP address.
	IPByHost(host string) (ip netip.Addr)

	WriteDiskConfig(c *ServerConfig)
}

// server is the DHCP service that handles DHCPv4, DHCPv6, and HTTP API.
type server struct {
	srv4 DHCPServer
	srv6 DHCPServer

	// TODO(a.garipov): Either create a separate type for the internal config or
	// just put the config values into Server.
	conf *ServerConfig

	// Called when the leases DB is modified
	onLeaseChanged []OnLeaseChangedT
}

// type check
var _ Interface = (*server)(nil)

// Create initializes and returns the DHCP server handling both address
// families.  It also registers the corresponding HTTP API endpoints.
func Create(conf *ServerConfig) (s *server, err error) {
	s = &server{
		conf: &ServerConfig{
			ConfigModified: conf.ConfigModified,

			HTTPRegister: conf.HTTPRegister,

			Enabled:       conf.Enabled,
			InterfaceName: conf.InterfaceName,

			LocalDomainName: conf.LocalDomainName,

			dbFilePath: filepath.Join(conf.DataDir, dataFilename),
		},
	}

	// TODO(e.burkov):  Don't register handlers, see TODO on
	// [aghhttp.RegisterFunc].
	s.registerHandlers()

	v4Enabled, v6Enabled, err := s.setServers(conf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.conf.Conf4 = conf.Conf4
	s.conf.Conf6 = conf.Conf6

	if s.conf.Enabled && !v4Enabled && !v6Enabled {
		return nil, fmt.Errorf("neither dhcpv4 nor dhcpv6 srv is configured")
	}

	// Migrate leases db if needed.
	err = migrateDB(conf)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	// Don't delay database loading until the DHCP server is started,
	// because we need static leases functionality available beforehand.
	err = s.dbLoad()
	if err != nil {
		return nil, fmt.Errorf("loading db: %w", err)
	}

	return s, nil
}

// setServers updates DHCPv4 and DHCPv6 servers created from the provided
// configuration conf.
func (s *server) setServers(conf *ServerConfig) (v4Enabled, v6Enabled bool, err error) {
	v4conf := conf.Conf4
	v4conf.InterfaceName = s.conf.InterfaceName
	v4conf.notify = s.onNotify
	v4conf.Enabled = s.conf.Enabled && v4conf.RangeStart.IsValid()

	s.srv4, err = v4Create(&v4conf)
	if err != nil {
		if v4conf.Enabled {
			return false, false, fmt.Errorf("creating dhcpv4 srv: %w", err)
		}

		log.Debug("dhcpd: warning: creating dhcpv4 srv: %s", err)
	}

	v6conf := conf.Conf6
	v6conf.InterfaceName = s.conf.InterfaceName
	v6conf.notify = s.onNotify
	v6conf.Enabled = s.conf.Enabled && len(v6conf.RangeStart) != 0

	s.srv6, err = v6Create(v6conf)
	if err != nil {
		return v4conf.Enabled, false, fmt.Errorf("creating dhcpv6 srv: %w", err)
	}

	return v4conf.Enabled, v6conf.Enabled, nil
}

// Enabled returns true when the server is enabled.
func (s *server) Enabled() (ok bool) {
	return s.conf.Enabled
}

// resetLeases resets all leases in the lease database.
func (s *server) resetLeases() (err error) {
	err = s.srv4.ResetLeases(nil)
	if err != nil {
		return err
	}

	if s.srv6 != nil {
		err = s.srv6.ResetLeases(nil)
		if err != nil {
			return err
		}
	}

	return s.dbStore()
}

// server calls this function after DB is updated
func (s *server) onNotify(flags uint32) {
	if flags == LeaseChangedDBStore {
		err := s.dbStore()
		if err != nil {
			log.Error("updating db: %s", err)
		}

		return
	}

	s.notify(int(flags))
}

func (s *server) notify(flags int) {
	for _, f := range s.onLeaseChanged {
		f(flags)
	}
}

// WriteDiskConfig - write configuration
func (s *server) WriteDiskConfig(c *ServerConfig) {
	c.Enabled = s.conf.Enabled
	c.InterfaceName = s.conf.InterfaceName
	c.LocalDomainName = s.conf.LocalDomainName

	s.srv4.WriteDiskConfig4(&c.Conf4)
	s.srv6.WriteDiskConfig6(&c.Conf6)
}

// Start will listen on port 67 and serve DHCP requests.
func (s *server) Start() (err error) {
	err = s.srv4.Start()
	if err != nil {
		return err
	}

	err = s.srv6.Start()
	if err != nil {
		return err
	}

	return nil
}

// Stop closes the listening UDP socket
func (s *server) Stop() (err error) {
	err = s.srv4.Stop()
	if err != nil {
		return err
	}

	err = s.srv6.Stop()
	if err != nil {
		return err
	}

	return nil
}

// Leases returns the list of active DHCP leases.
func (s *server) Leases() (leases []*dhcpsvc.Lease) {
	ls := append(s.srv4.GetLeases(LeasesAll), s.srv6.GetLeases(LeasesAll)...)
	leases = make([]*dhcpsvc.Lease, len(ls))
	for i, l := range ls {
		leases[i] = &dhcpsvc.Lease{
			Expiry:   l.Expiry,
			Hostname: l.Hostname,
			HWAddr:   l.HWAddr,
			IP:       l.IP,
			IsStatic: l.IsStatic,
		}
	}

	return leases
}

// MACByIP returns a MAC address by the IP address of its lease, if there is
// one.
func (s *server) MACByIP(ip netip.Addr) (mac net.HardwareAddr) {
	if ip.Is4() {
		return s.srv4.FindMACbyIP(ip)
	}

	return s.srv6.FindMACbyIP(ip)
}

// HostByIP implements the [Interface] interface for *server.
func (s *server) HostByIP(ip netip.Addr) (host string) {
	if ip.Is4() {
		return s.srv4.HostByIP(ip)
	}

	return s.srv6.HostByIP(ip)
}

// IPByHost implements the [Interface] interface for *server.
func (s *server) IPByHost(host string) (ip netip.Addr) {
	if ip = s.srv4.IPByHost(host); ip != (netip.Addr{}) {
		ip = s.srv6.IPByHost(host)
	}

	return ip
}

// AddStaticLease - add static v4 lease
func (s *server) AddStaticLease(l *Lease) error {
	return s.srv4.AddStaticLease(l)
}
