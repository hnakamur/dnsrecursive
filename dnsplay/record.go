package dnsplay

import (
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	pkgrdata "codeberg.org/miekg/dns/rdata"
	"go.yaml.in/yaml/v4"
)

type Record struct {
	Name  string
	TTL   uint32
	RType string
	RData string
}

func newRecords(rr []dns.RR) []Record {
	if len(rr) == 0 {
		return nil
	}
	ret := make([]Record, len(rr))
	for i := range rr {
		ret[i] = newRecord(rr[i])
	}
	return ret
}

func newRecord(rr dns.RR) Record {
	return Record{
		Name:  rr.Header().Name,
		TTL:   rr.Header().TTL,
		RType: rrTypeString(rr),
		RData: rr.Data().String(),
	}
}

type records []Record

func (r records) MarshalYAML() (any, error) {
	seq := &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  "!!seq",
	}

	for _, rr := range []Record(r) {
		var n yaml.Node
		if err := n.Encode(rr); err != nil {
			return nil, err
		}
		n.Style = yaml.FlowStyle
		seq.Content = append(seq.Content, &n)
	}

	return seq, nil
}

func (r *Record) toRData() (dns.RDATA, error) {
	switch r.RType {
	case "A":
		addr, err := netip.ParseAddr(r.RData)
		if err != nil {
			return nil, fmt.Errorf("parse A RData: %s", err)
		}
		return pkgrdata.A{Addr: addr}, nil
	case "AAAA":
		addr, err := netip.ParseAddr(r.RData)
		if err != nil {
			return nil, fmt.Errorf("parse AAAA RData: %s", err)
		}
		return pkgrdata.AAAA{Addr: addr}, nil
	case "NS":
		return pkgrdata.NS{Ns: r.RData}, nil
	case "CNAME":
		return pkgrdata.CNAME{Target: r.RData}, nil
	default:
		rdata, err := dns.New(fmt.Sprintf("%s %d IN %s %s", r.Name, r.TTL, r.RType, r.RData))
		if err != nil {
			return nil, fmt.Errorf("parse %s RData: %s", r.RType, err)
		}
		return rdata, nil
	}
}

func (r records) ToRRs() ([]dns.RR, error) {
	if len(r) == 0 {
		return nil, nil
	}
	rr := make([]dns.RR, len(r))
	for i := range r {
		var err error
		rr[i], err = r[i].ToRR()
		if err != nil {
			return nil, err
		}
	}
	return rr, nil
}

func (r *Record) ToRR() (dns.RR, error) {
	rdata, err := r.toRData()
	if err != nil {
		return nil, fmt.Errorf("failed to convert Record to RR: %s", err)
	}
	h := dns.Header{
		Name:  r.Name,
		Class: dns.ClassINET,
		TTL:   r.TTL,
	}
	return newRRFromHeaderAndRDATA(h, rdata), nil
}

func rrTypeString(rr dns.RR) string {
	return dnsutil.TypeToString(dns.RRToType(rr))
}

func newRRFromHeaderAndRDATA(h dns.Header, rdata dns.RDATA) dns.RR {
	switch rd := rdata.(type) {
	case pkgrdata.A:
		return &dns.A{Hdr: h, A: rd}
	case pkgrdata.AAAA:
		return &dns.AAAA{Hdr: h, AAAA: rd}
	case pkgrdata.AFSDB:
		return &dns.AFSDB{Hdr: h, AFSDB: rd}
	case pkgrdata.CAA:
		return &dns.CAA{Hdr: h, CAA: rd}
	case pkgrdata.CERT:
		return &dns.CERT{Hdr: h, CERT: rd}
	case pkgrdata.CNAME:
		return &dns.CNAME{Hdr: h, CNAME: rd}
	case pkgrdata.CSYNC:
		return &dns.CSYNC{Hdr: h, CSYNC: rd}
	case pkgrdata.DELEG:
		return &dns.DELEG{Hdr: h, DELEG: rd}
	case pkgrdata.DHCID:
		return &dns.DHCID{Hdr: h, DHCID: rd}
	case pkgrdata.DNAME:
		return &dns.DNAME{Hdr: h, DNAME: rd}
	case pkgrdata.DNSKEY:
		return &dns.DNSKEY{Hdr: h, DNSKEY: rd}
	case pkgrdata.DS:
		return &dns.DS{Hdr: h, DS: rd}
	case pkgrdata.DSYNC:
		return &dns.DSYNC{Hdr: h, DSYNC: rd}
	case pkgrdata.EID:
		return &dns.EID{Hdr: h, EID: rd}
	case pkgrdata.EUI48:
		return &dns.EUI48{Hdr: h, EUI48: rd}
	case pkgrdata.EUI64:
		return &dns.EUI64{Hdr: h, EUI64: rd}
	case pkgrdata.GID:
		return &dns.GID{Hdr: h, GID: rd}
	case pkgrdata.GPOS:
		return &dns.GPOS{Hdr: h, GPOS: rd}
	case pkgrdata.HINFO:
		return &dns.HINFO{Hdr: h, HINFO: rd}
	case pkgrdata.HIP:
		return &dns.HIP{Hdr: h, HIP: rd}
	case pkgrdata.IPN:
		return &dns.IPN{Hdr: h, IPN: rd}
	case pkgrdata.ISDN:
		return &dns.ISDN{Hdr: h, ISDN: rd}
	case pkgrdata.KX:
		return &dns.KX{Hdr: h, KX: rd}
	case pkgrdata.L32:
		return &dns.L32{Hdr: h, L32: rd}
	case pkgrdata.L64:
		return &dns.L64{Hdr: h, L64: rd}
	case pkgrdata.LOC:
		return &dns.LOC{Hdr: h, LOC: rd}
	case pkgrdata.LP:
		return &dns.LP{Hdr: h, LP: rd}
	case pkgrdata.MB:
		return &dns.MB{Hdr: h, MB: rd}
	case pkgrdata.MD:
		return &dns.MD{Hdr: h, MD: rd}
	case pkgrdata.MF:
		return &dns.MF{Hdr: h, MF: rd}
	case pkgrdata.MG:
		return &dns.MG{Hdr: h, MG: rd}
	case pkgrdata.MINFO:
		return &dns.MINFO{Hdr: h, MINFO: rd}
	case pkgrdata.MR:
		return &dns.MR{Hdr: h, MR: rd}
	case pkgrdata.MX:
		return &dns.MX{Hdr: h, MX: rd}
	case pkgrdata.NAPTR:
		return &dns.NAPTR{Hdr: h, NAPTR: rd}
	case pkgrdata.NID:
		return &dns.NID{Hdr: h, NID: rd}
	case pkgrdata.NIMLOC:
		return &dns.NIMLOC{Hdr: h, NIMLOC: rd}
	case pkgrdata.NINFO:
		return &dns.NINFO{Hdr: h, NINFO: rd}
	case pkgrdata.NS:
		return &dns.NS{Hdr: h, NS: rd}
	case pkgrdata.NSAPPTR:
		return &dns.NSAPPTR{Hdr: h, NSAPPTR: rd}
	case pkgrdata.NSEC:
		return &dns.NSEC{Hdr: h, NSEC: rd}
	case pkgrdata.NSEC3:
		return &dns.NSEC3{Hdr: h, NSEC3: rd}
	case pkgrdata.NSEC3PARAM:
		return &dns.NSEC3PARAM{Hdr: h, NSEC3PARAM: rd}
	case pkgrdata.NULL:
		return &dns.NULL{Hdr: h, NULL: rd}
	case pkgrdata.OPENPGPKEY:
		return &dns.OPENPGPKEY{Hdr: h, OPENPGPKEY: rd}
	case pkgrdata.PTR:
		return &dns.PTR{Hdr: h, PTR: rd}
	case pkgrdata.PX:
		return &dns.PX{Hdr: h, PX: rd}
	case pkgrdata.RFC3597:
		return &dns.RFC3597{Hdr: h, RFC3597: rd}
	case pkgrdata.RKEY:
		return &dns.RKEY{Hdr: h, RKEY: rd}
	case pkgrdata.RP:
		return &dns.RP{Hdr: h, RP: rd}
	case pkgrdata.RRSIG:
		return &dns.RRSIG{Hdr: h, RRSIG: rd}
	case pkgrdata.RT:
		return &dns.RT{Hdr: h, RT: rd}
	case pkgrdata.SMIMEA:
		return &dns.SMIMEA{Hdr: h, SMIMEA: rd}
	case pkgrdata.SOA:
		return &dns.SOA{Hdr: h, SOA: rd}
	case pkgrdata.SRV:
		return &dns.SRV{Hdr: h, SRV: rd}
	case pkgrdata.SSHFP:
		return &dns.SSHFP{Hdr: h, SSHFP: rd}
	case pkgrdata.SVCB:
		return &dns.SVCB{Hdr: h, SVCB: rd}
	case pkgrdata.TA:
		return &dns.TA{Hdr: h, TA: rd}
	case pkgrdata.TALINK:
		return &dns.TALINK{Hdr: h, TALINK: rd}
	case pkgrdata.TKEY:
		return &dns.TKEY{Hdr: h, TKEY: rd}
	case pkgrdata.TLSA:
		return &dns.TLSA{Hdr: h, TLSA: rd}
	case pkgrdata.TSIG:
		return &dns.TSIG{Hdr: h, TSIG: rd}
	case pkgrdata.TXT:
		return &dns.TXT{Hdr: h, TXT: rd}
	case pkgrdata.UID:
		return &dns.UID{Hdr: h, UID: rd}
	case pkgrdata.UINFO:
		return &dns.UINFO{Hdr: h, UINFO: rd}
	case pkgrdata.URI:
		return &dns.URI{Hdr: h, URI: rd}
	case pkgrdata.X25:
		return &dns.X25{Hdr: h, X25: rd}
	case pkgrdata.ZONEMD:
		return &dns.ZONEMD{Hdr: h, ZONEMD: rd}
	default:
		panic(fmt.Sprintf("unsupported rdata type (%T) in NewRRFromRDATA", rdata))
	}
}
