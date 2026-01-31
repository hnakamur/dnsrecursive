package dnsrecursive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/hnakamur/dnsrecursive/dnsplay"
)

const dnsPortStr = "53"

type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, network, address string) (r *dns.Msg, rtt time.Duration, err error)
}

type Option func(r *Resolver2)

type Resolver2 struct {
	exchanger       Exchanger
	rootNameservers []netip.Addr
	logger          Logger

	lookupID atomic.Uint64
}

func NewResolver2(exchanger Exchanger, rootNameservers []netip.Addr, opts ...Option) *Resolver2 {
	r := &Resolver2{
		exchanger:       exchanger,
		rootNameservers: rootNameservers,
		logger:          slog.Default(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

type Logger interface {
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
	Enabled(ctx context.Context, level slog.Level) bool
}

func WithLogger(logger Logger) Option {
	return func(r *Resolver2) {
		r.logger = logger
	}
}

type query struct {
	Name  string `json:"name"`
	QType uint16 `json:"qtype"`
}

func (q *query) String() string {
	return fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.QType])
}

func (q *query) MarshalJSON() ([]byte, error) {
	query := struct {
		Name  string `json:"name"`
		QType string `json:"qtype"`
	}{
		Name:  q.Name,
		QType: dns.TypeToString[q.QType],
	}
	return json.Marshal(query)
}

func (c *Resolver2) LookupRecord(ctx context.Context, name, qType string) ([]dns.RR, error) {
	pos := c.newRecursePosition()

	// do the requested query from root servers.
	q := &query{Name: name, QType: dns.StringToType[qType]}
	c.info(ctx, "LookupRecord start", "pos", pos, "query", q)
	defer func() {
		c.info(ctx, "LookupRecord exit", "pos", pos, "query", q)
	}()

	r, err := c.lookupRecursiveMulti(ctx, pos, q, c.rootNameservers)
	if err != nil {
		c.warn(ctx, err.Error(), "pos", pos)
		return nil, err
	}
	if r.Authoritative {
		return r.Answer, nil
	}
	if len(r.Ns) == 0 {
		c.warn(ctx, "failed to get target query result nor authority nameserver names", "pos", pos)
		return nil, errors.New("failed to get target query result nor authority nameserver names")
	}

	// query for authority nameserver addresses from root servers.
	pos.NsCount = len(r.Ns)
	for nsIndex := range r.Ns {
		pos.NsIndex = nsIndex + 1
		nsRecord, ok := r.Ns[nsIndex].(*dns.NS)
		if !ok {
			c.warn(ctx, "authority record type is not NS", "pos", pos, "rtype", dns.TypeToString[dns.RRToType(r.Ns[nsIndex])])
			continue
		}

		nsQueryV4 := &query{Name: nsRecord.Ns, QType: dns.TypeA}
		pos.setStep("2-v4")
		c.debug(ctx, "LookupRecord start querying IPv4 address of authority nameservers", "pos", pos, "nsQueryV4", nsQueryV4)
		r2v4, err := c.lookupRecursiveMulti(ctx, pos, nsQueryV4, c.rootNameservers)
		if err != nil {
			c.warn(ctx, err.Error(), "pos", pos)
		} else if r2v4.Authoritative {
			// do the requested query to authority nameservers.
			if nsAddrsV4 := getAddressesFromRRSet(r2v4.Answer); len(nsAddrsV4) > 0 {
				pos.setStep("3-v4")
				c.debug(ctx, "LookupRecord start querying to authority nameserver with IPv4", "po", pos, "query", q, "nsAddrsV4", nsAddrsV4)
				r3v4, err := c.lookupRecursiveMulti(ctx, pos, q, nsAddrsV4)
				if err != nil {
					c.warn(ctx, err.Error(), "pos", pos)
				} else if r3v4.Authoritative {
					return r3v4.Answer, nil
				}
			}
		} else {
			c.warn(ctx, "failed to get authoritative nameserver IPv4 addresses for query", "pos", pos)
		}

		nsQueryV6 := &query{Name: nsRecord.Ns, QType: dns.TypeAAAA}
		pos.setStep("2-v6")
		c.debug(ctx, "LookupRecord start querying IPv6 address of authority nameservers", "pos", pos, "nsQueryV6", nsQueryV6)
		r2v6, err := c.lookupRecursiveMulti(ctx, pos, nsQueryV6, c.rootNameservers)
		if err != nil {
			c.warn(ctx, err.Error(), "pos", pos)
		} else if r2v6.Authoritative {
			// do the requested query to authority nameservers.
			if nsAddrsV6 := getAddressesFromRRSet(r2v6.Answer); len(nsAddrsV6) > 0 {
				pos.setStep("3-v6")
				c.debug(ctx, "LookupRecord start querying to authority nameserver with IPv6", "po", pos, "query", q, "nsAddrsV6", nsAddrsV6)
				r3v6, err := c.lookupRecursiveMulti(ctx, pos, q, nsAddrsV6)
				if err != nil {
					c.warn(ctx, err.Error(), "pos", pos)
				} else if r3v6.Authoritative {
					return r3v6.Answer, nil
				}
			}
		} else {
			c.warn(ctx, "failed to get authoritative nameserver IPv6 addresses for query", "pos", pos)
		}

		c.warn(ctx, "failed to get authoritative query response from one authority nameserver", "pos", pos)
	}
	return nil, errors.New("failed to get target query result from all authority nameservers")
}

type recursePosition struct {
	LookupID uint64 `json:"lookupId"`
	Step     string `json:"step"`
	NsIndex  int    `json:"nsIndex,omitzero"`
	NsCount  int    `json:"nsCount,omitzero"`
	Depth    int    `json:"depth"`
	Index    int    `json:"index,omitzero"`
	Count    int    `json:"count,omitzero"`
}

func (c *Resolver2) newRecursePosition() *recursePosition {
	return &recursePosition{
		LookupID: c.lookupID.Add(1),
		Step:     "1",
		Depth:    1,
	}
}

func (p *recursePosition) setStep(s string) {
	p.Step = s
	p.Depth = 1
	p.Index = 0
	p.Count = 0
}

func (c *Resolver2) lookupRecursiveMulti(ctx context.Context, pos *recursePosition, query *query, nameservers []netip.Addr) (*dns.Msg, error) {
	depth := pos.Depth
	for i, ns := range nameservers {
		pos.Depth = depth
		pos.Index = i + 1
		pos.Count = len(nameservers)
		r, err := c.lookupRecursiveOne(ctx, pos, query, ns)
		if err != nil {
			c.warn(ctx, "lookup failed on one nameserver", "pos", pos, "query", query, "nameserver", ns, "err", err)
			continue
		}
		return r, nil
	}
	return nil, errors.New("lookup failed on all nameservers")
}

func (c *Resolver2) lookupRecursiveOne(ctx context.Context, pos *recursePosition, query *query, nameserver netip.Addr) (*dns.Msg, error) {
	r, err := c.doQueryUDPWithTCPFallback(ctx, pos, query, nameserver)
	if err != nil {
		return nil, err
	}
	if r.Authoritative {
		return r, nil
	}
	if len(r.Ns) == 0 {
		return nil, fmt.Errorf("no authority in non-authoritative DNS query response, query=%s", query)
	}

	addrs := getAddressesFromRRSet(r.Extra)
	if len(addrs) == 0 {
		return r, nil
	}
	pos.Depth++
	return c.lookupRecursiveMulti(ctx, pos, query, addrs)
}

func getAddressesFromRRSet(rr []dns.RR) []netip.Addr {
	if len(rr) == 0 {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(rr))
	for _, r := range rr {
		if addr, ok := getAddrFromRR(r); ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func getAddrFromRR(rr dns.RR) (netip.Addr, bool) {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.Addr, true
	case *dns.AAAA:
		return r.AAAA.Addr, true
	default:
		return netip.Addr{}, false
	}
}

func (c *Resolver2) doQueryUDPWithTCPFallback(ctx context.Context, pos *recursePosition, query *query, nameserver netip.Addr) (*dns.Msg, error) {
	r, err := c.doQueryProto(ctx, pos, query, nameserver, "udp")
	if err != nil {
		return nil, err
	}
	if !r.Truncated {
		return r, nil
	}
	r, err = c.doQueryProto(ctx, pos, query, nameserver, "tcp")
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Resolver2) doQueryProto(ctx context.Context, pos *recursePosition, query *query, nameserver netip.Addr, protocol string) (*dns.Msg, error) {
	network := normalizeNetworkForAddr(protocol, nameserver)

	m := dns.NewMsg(query.Name, query.QType)
	m.RecursionDesired = false
	respMsg, _, err := c.exchanger.Exchange(ctx, m, network, net.JoinHostPort(nameserver.String(), dnsPortStr))
	if c.logger.Enabled(ctx, slog.LevelInfo) {
		resp := dnsplay.NewResponseFromMsg(respMsg)
		c.info(ctx, "doQueryProto after exchange", "pos", pos, "protocol", protocol, "nameserver", nameserver, "query", query, "response", resp, "error", err)
	}
	if err != nil {
		return nil, err
	}

	// Check response ID matches the query ID.
	//
	// http://ietf.org/rfc/rfc1034.txt
	// 5.3.3. Algorithm
	// It should also check that the response matches the query it
	// sent using the ID field in the response.
	if respMsg.ID != m.ID {
		return nil, errors.New("response ID does not match query ID")
	}
	return respMsg, nil
}

func normalizeNetworkForAddr(protocol string, addr netip.Addr) string {
	if strings.HasSuffix(protocol, "4") || strings.HasSuffix(protocol, "6") {
		return protocol
	}
	if addr.Is4() {
		return protocol + "4"
	}
	return protocol + "6"
}

func (c *Resolver2) debug(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, slog.LevelDebug, msg, args...)
}

func (c *Resolver2) info(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, slog.LevelInfo, msg, args...)
}

func (c *Resolver2) warn(ctx context.Context, msg string, args ...any) {
	c.logger.Log(ctx, slog.LevelWarn, msg, args...)
}

func (c *Resolver2) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	c.logger.Log(ctx, level, msg, args...)
}
