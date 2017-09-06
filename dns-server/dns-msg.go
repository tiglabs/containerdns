// Copyright (c) 2017 The skydns Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package dnsServer
import (
	"net"
	"github.com/miekg/dns"
)

type ServiceRecord struct {
	Dnstype 	string `json:"type,omitempty"`
	RecordSource 	string `json:"source,omitempty"`
	DnsHost       	string `json:"host,omitempty"`
	DnsTtl         	uint32 `json:"ttl,omitempty"`

	DnsPort        int    `json:"port,omitempty"`
	DnsPriority    int    `json:"priority,omitempty"`
	DnsWeight      int    `json:"weight,omitempty"`

	DnsText        string `json:"text,omitempty"`
	DnsMail        bool   `json:"mail,omitempty"`
	Cluster        string   `json:"cluster,omitempty"`
	// Etcd key
	Key string `json:"-"`
}


// NewRecordA returns a new A record based on the Service.
func (s *ServiceRecord) NewRecordA(name string, ip net.IP) *dns.A {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.DnsTtl}, A: ip}
}

// NewRecordAAAA returns a new AAAA record based on the Service.
func (s *ServiceRecord) NewRecordAAAA(name string, ip net.IP) *dns.AAAA {
	return &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.DnsTtl}, AAAA: ip}
}

// NewRecordCname returns a new CNAME record based on the Service.
func (s *ServiceRecord) NewRecordCname(name string, target string) *dns.CNAME {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: s.DnsTtl}, Target: target}
}

// NewRecordNS returns a new NS record based on the Service.
func (s *ServiceRecord) NewRecordNS(name string, target string) *dns.NS {
	return &dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: s.DnsTtl}, Ns: target}
}

// NewRecordTXT returns a new TXT record based on the Service.
func (s *ServiceRecord) NewRecordTXT(name string) *dns.TXT {
	return &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: s.DnsTtl},  Txt: []string{s.DnsText}}
}

// NewRecordPTR returns a new PTR record based on the Service.
func (s *ServiceRecord) NewRecordPTR(name string, ttl uint32) *dns.PTR {
	return &dns.PTR{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: dns.Fqdn(s.DnsHost)}
}
// NewRecordSRV returns a new SRV record based on the Service.
func (s *ServiceRecord) NewRecordSRV(name string, weight uint16) *dns.SRV {
	return &dns.SRV{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: s.DnsTtl},
		Priority: uint16(s.DnsPriority), Weight: weight, Port: uint16(s.DnsPort), Target: dns.Fqdn(s.DnsHost)}
}

// NewRecordMx returns a new MX record based on the Service.
func (s *ServiceRecord) NewRecordMx(name string) *dns.MX {
	return &dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: s.DnsTtl},
		Preference: uint16(s.DnsPriority), Mx: dns.Fqdn(s.DnsHost)}
}


