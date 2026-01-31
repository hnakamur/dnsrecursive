package dnsplay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"codeberg.org/miekg/dns"
)

type Query struct {
	Nameserver string
	Protocol   string
	Name       string
	QType      string
	Flags      []string `yaml:",flow"`
}

func newQuery(nameserver netip.Addr, protocol string, m *dns.Msg) *Query {
	if len(m.Question) != 1 {
		panic("question count must be one")
	}
	q := m.Question[0]

	return &Query{
		Nameserver: nameserver.String(),
		Protocol:   protocol,
		Name:       q.Header().Name,
		QType:      rrTypeString(q),
		Flags:      msgToFlags(m),
	}
}

func (q *Query) chcekInput(m *dns.Msg, network, address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("address must be in ip_address:port format")
	} else if port != dnsPortStr {
		return errors.New("port of address must be 53")
	}

	if host != q.Nameserver {
		return fmt.Errorf("nameserver address mismatch, got=%s, want=%s", host, q.Nameserver)
	}
	if network != q.Protocol {
		return fmt.Errorf("protocol mismatch, got=%s, want=%s", network, q.Protocol)
	}

	if len(m.Question) != 1 {
		return errors.New("question count must be one")
	}
	qInput := m.Question[0]

	if qName := qInput.Header().Name; qName != q.Name {
		return fmt.Errorf("query name mismatch, got=%s, want=%s", qName, q.Name)
	}
	if qType := rrTypeString(qInput); qType != q.QType {
		return fmt.Errorf("query type mismatch, got=%s, want=%s", qType, q.QType)
	}
	if inputFlags := msgToFlags(m); !slices.Equal(inputFlags, q.Flags) {
		return fmt.Errorf("query message flags mismatch, got=%v, want=%v", inputFlags, q.Flags)
	}
	return nil
}
