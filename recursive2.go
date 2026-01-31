package dnsrecursive

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

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

type Resolver2 struct {
	exchanger       Exchanger
	rootNameservers []netip.Addr
}

func NewResolver2(exchanger Exchanger, rootNameservers []netip.Addr) *Resolver2 {
	return &Resolver2{
		exchanger:       exchanger,
		rootNameservers: rootNameservers,
	}
}

type query struct {
	Name  string
	QType uint16
}

func (q *query) String() string {
	return fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.QType])
}

type queryResultKind int

const (
	queryResultKindFailed queryResultKind = iota
	queryResultKindGotAuthoritativeAnswer
	queryResultKindGotAuthorityWithoutExtra
)

func (c *Resolver2) LookupRecord(ctx context.Context, name, qType string) ([]dns.RR, error) {
	log.Printf("dnsrecursive.Client.LookupRecord start, name=%s, qType=%s", name, qType)
	// do the requested query from root servers.
	q := &query{Name: name, QType: dns.StringToType[qType]}
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
	log.Printf("dnsrecursive.Client.LookupRecord query for nameserver address, name=%s, qType=%s", firstNs.Ns, "A")

	nsQuery := &query{Name: firstNs.Ns, QType: dns.TypeA}
	r2, k2, err := c.lookupRecursiveMulti(ctx, nsQuery, c.rootNameservers)
	if err != nil {
		return nil, err
	}
	if k2 != queryResultKindGotAuthoritativeAnswer {
		return nil, errors.New("failed to get authority nameserver addresses for query")
	}

	// do the requested query to authority nameservers.
	nsAddrs := getAddressesFromRRSet(r2.Answer)
	log.Printf("dnsrecursive.Client.LookupRecord query to authority nameserver, name=%s, qType=%s, nsAddrs=%v", name, qType, nsAddrs)
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
			log.Printf("lookup failed on one server, query=%s, nameserver=%s, continue to next server, err=%s", query, ns, err)
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

const dnsPortStr = "53"

func (c *Resolver2) doQueryProto(ctx context.Context, query *query, nameserver netip.Addr, protocol string) (*dns.Msg, error) {
	network := normalizeNetworkForAddr(protocol, nameserver)

	m := dns.NewMsg(query.Name, query.QType)
	m.RecursionDesired = false
	respMsg, _, err := c.exchanger.Exchange(ctx, m, network, net.JoinHostPort(nameserver.String(), dnsPortStr))
	return respMsg, err
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
