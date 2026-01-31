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
	"time"

	"codeberg.org/miekg/dns"
)

const dnsPortStr = "53"

// query Q1 to root server
// while got ns and additional:
//   query Q1 to that server
//   return result if authoritative
// if got ns and no additional:
//   query Q2(address of ns) to root server
//   while got ns and additional:
//     query Q2 to that server
//     save ns if authoritative
//   query Q1 to ns server
//   return result

type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, network, address string) (r *dns.Msg, rtt time.Duration, err error)
}

type Logger interface {
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
}

type Option func(r *Resolver2)

type Resolver2 struct {
	exchanger       Exchanger
	rootNameservers []netip.Addr
	logger          Logger
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

type queryResultKind int

const (
	queryResultKindFailed queryResultKind = iota
	queryResultKindGotAuthoritativeAnswer
	queryResultKindGotAuthorityWithoutExtra
)

func (c *Resolver2) LookupRecord(ctx context.Context, name, qType string) ([]dns.RR, error) {
	// do the requested query from root servers.
	q := &query{Name: name, QType: dns.StringToType[qType]}
	c.info(ctx, "LookupRecord start first round", "query", q)

	r, k, err := c.lookupRecursiveMulti(ctx, q, c.rootNameservers)
	if err != nil {
		return nil, err
	}
	if k == queryResultKindGotAuthoritativeAnswer {
		return r.Answer, nil
	}
	if k != queryResultKindGotAuthorityWithoutExtra {
		return nil, errors.New("failed to get target query result nor authority nameserver names")
	}

	// query for authority nameserver addresses from root servers.
	firstNs, ok := r.Ns[0].(*dns.NS)
	if !ok {
		return nil, fmt.Errorf("authority record type is not NS, record=%s", r.Ns[0])
	}

	nsQuery := &query{Name: firstNs.Ns, QType: dns.TypeA}
	c.info(ctx, "LookupRecord start querying address of authority nameservers", "query", q, "nsQuery", nsQuery)

	r2, k2, err := c.lookupRecursiveMulti(ctx, nsQuery, c.rootNameservers)
	if err != nil {
		return nil, err
	}
	if k2 != queryResultKindGotAuthoritativeAnswer {
		return nil, errors.New("failed to get authority nameserver addresses for query")
	}

	// do the requested query to authority nameservers.
	nsAddrs := getAddressesFromRRSet(r2.Answer)
	c.info(ctx, "LookupRecord start querying to authority nameserver", "query", q, "nsAddrs", nsAddrs)
	r3, k3, err := c.lookupRecursiveMulti(ctx, q, nsAddrs)
	if err != nil {
		return nil, err
	}
	if k3 != queryResultKindGotAuthoritativeAnswer {
		return nil, errors.New("failed to get query result from authority nameserver")
	}

	return r3.Answer, nil
}

func (c *Resolver2) lookupRecursiveMulti(ctx context.Context, query *query, nameservers []netip.Addr) (*dns.Msg, queryResultKind, error) {
	for _, ns := range nameservers {
		r, k, err := c.lookupRecursiveOne(ctx, query, ns)
		if err != nil {
			c.warn(ctx, "lookup failed on one nameserver", "query", query, "nameserver", ns, "err", err)
			continue
		}
		return r, k, nil
	}
	return nil, queryResultKindFailed, fmt.Errorf("lookup failed on all servers, query=%s, nameservers=%v", query, nameservers)
}

func (c *Resolver2) lookupRecursiveOne(ctx context.Context, query *query, nameserver netip.Addr) (*dns.Msg, queryResultKind, error) {
	r, err := c.doQueryUDPWithTCPFallback(ctx, query, nameserver)
	if err != nil {
		return nil, queryResultKindFailed, err
	}
	if r.Authoritative {
		return r, queryResultKindGotAuthoritativeAnswer, nil
	}
	if len(r.Ns) == 0 {
		return nil, queryResultKindFailed, fmt.Errorf("no authority in non-authoritative DNS query response, query=%s", query)
	}

	addrs := getAddressesFromRRSet(r.Extra)
	if len(addrs) == 0 {
		return r, queryResultKindGotAuthorityWithoutExtra, nil
	}
	return c.lookupRecursiveMulti(ctx, query, addrs)
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

func (c *Resolver2) doQueryUDPWithTCPFallback(ctx context.Context, query *query, nameserver netip.Addr) (*dns.Msg, error) {
	r, err := c.doQueryProto(ctx, query, nameserver, "udp")
	if err != nil {
		return nil, err
	}
	if !r.Truncated {
		return r, nil
	}
	r, err = c.doQueryProto(ctx, query, nameserver, "tcp")
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Resolver2) doQueryProto(ctx context.Context, query *query, nameserver netip.Addr, protocol string) (*dns.Msg, error) {
	network := normalizeNetworkForAddr(protocol, nameserver)

	m := dns.NewMsg(query.Name, query.QType)
	m.RecursionDesired = false
	respMsg, _, err := c.exchanger.Exchange(ctx, m, network, net.JoinHostPort(nameserver.String(), dnsPortStr))
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
