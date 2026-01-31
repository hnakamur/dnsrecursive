package dnsplay

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"go.yaml.in/yaml/v4"
)

type Exchange struct {
	Query    Query    `json:"query"`
	Response Response `json:"response"`
}

type Response struct {
	Flags  []string `json:"flags"`
	Answer []Record `json:"answer"`
	Ns     []Record `json:"ns"`
	Extra  []Record `json:"extra"`
	Error  string   `json:"error,omitempty"`
}

func NewExchangeFromMsg(nameserver netip.Addr, protocol string, m, r *dns.Msg) *Exchange {
	return &Exchange{
		Query:    *newQuery(nameserver, protocol, m),
		Response: *NewResponseFromMsg(r),
	}
}

func NewResponseFromMsg(r *dns.Msg) *Response {
	return &Response{
		Flags:  msgToFlags(r),
		Answer: newRecords(r.Answer),
		Ns:     newRecords(r.Ns),
		Extra:  newRecords(r.Extra),
	}
}

func msgToFlags(r *dns.Msg) []string {
	var flags []string
	h := r.MsgHeader
	if h.Response {
		flags = append(flags, "qr")
	}
	if h.Authoritative {
		flags = append(flags, "aa")
	}
	if h.Truncated {
		flags = append(flags, "tc")
	}
	if h.RecursionDesired {
		flags = append(flags, "rd")
	}
	if h.RecursionAvailable {
		flags = append(flags, "ra")
	}
	if h.Zero {
		flags = append(flags, "z")
	}
	if h.AuthenticatedData {
		flags = append(flags, "ad")
	}
	if h.CheckingDisabled {
		flags = append(flags, "cd")
	}
	if h.Security {
		flags = append(flags, "do")
	}
	if h.CompactAnswers {
		flags = append(flags, "co")
	}
	if h.Delegation {
		flags = append(flags, "de")
	}
	return flags
}

func (r *Response) setFlags(msg *dns.Msg) {
	setHeaderFlagsByStrings(msg, r.Flags)
}

func setHeaderFlagsByStrings(msg *dns.Msg, flags []string) {
	// reset RecursionDesired which is set by dns.New().
	msg.RecursionDesired = false

	for _, f := range flags {
		switch f {
		case "qr":
			msg.Response = true
		case "aa":
			msg.Authoritative = true
		case "tc":
			msg.Truncated = true
		case "rd":
			msg.RecursionDesired = true
		case "ra":
			msg.RecursionAvailable = true
		case "z":
			msg.Zero = true
		case "ad":
			msg.AuthenticatedData = true
		case "cd":
			msg.CheckingDisabled = true
		case "do":
			msg.Security = true
		case "co":
			msg.CompactAnswers = true
		case "de":
			msg.Delegation = true
		}
	}
}

func (r Response) MarshalYAML() (any, error) {
	flags, err := encodeYamlNodeWithFlowStyle(r.Flags)
	if err != nil {
		return nil, err
	}

	answer, err := encodeYamlNode(records(r.Answer))
	if err != nil {
		return nil, err
	}

	ns, err := encodeYamlNode(records(r.Ns))
	if err != nil {
		return nil, err
	}

	extra, err := encodeYamlNode(records(r.Extra))
	if err != nil {
		return nil, err
	}

	content := []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "flags"},
		flags,
		{Kind: yaml.ScalarNode, Value: "answer"},
		answer,
		{Kind: yaml.ScalarNode, Value: "ns"},
		ns,
		{Kind: yaml.ScalarNode, Value: "extra"},
		extra,
	}

	if r.Error != "" {
		content = append(content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "error"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: r.Error},
		)
	}

	return &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: content,
	}, nil
}

func encodeYamlNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

func encodeYamlNodeWithFlowStyle(v any) (*yaml.Node, error) {
	n, err := encodeYamlNode(v)
	if err != nil {
		return nil, err
	}
	n.Style = yaml.FlowStyle
	return n, nil
}

func (r *Response) ToMsg(q *dns.Msg) (*dns.Msg, error) {
	respMsg := new(dns.Msg)
	dnsutil.SetReply(respMsg, q)
	r.setFlags(respMsg)

	var err error
	respMsg.Answer, err = records(r.Answer).ToRRs()
	if err != nil {
		return nil, err
	}
	respMsg.Ns, err = records(r.Ns).ToRRs()
	if err != nil {
		return nil, err
	}
	respMsg.Extra, err = records(r.Extra).ToRRs()
	if err != nil {
		return nil, err
	}
	return respMsg, nil
}
