// Copyright (c) 2017 The skydns Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package dnsServer

import (
	"encoding/json"
	"fmt"
	 "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/golang/glog"
	"github.com/ipdcode/skydns/queue"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"math"
	"net"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "2.1.0"
const DnsPathPrefix  = "skydns"

var (
	EtcdCachesLock   sync.RWMutex                                              // lcok EtcdRecordCaches
	EtcdRecordCaches map[string][]ServiceRecord = make(map[string][]ServiceRecord) //
	EtcdRecordUpdateTime map[string]time.Time = make(map[string]time.Time)  //
)

type server struct {
	backend Backend
	dnsUDPclient  *dns.Client // used for forwarding queries
	dnsTCPclient  *dns.Client // used for forwarding queries
	rcache        *Cache
	ipMonitorPath   string
	dnsDomains        [] string
	dnsAddr           string
	msgPool         *queue.Queue
	syncPeriod      time.Duration

	forwardNameServers []string
	subDomainServers  map[string][]string
/*	nsDomain  string // "ns.dns". + config.Domain
	mailDomain string // "mail". + config.Domain
	txtDomain  string // "txt". + config.Domain
	hostMaster string // "ns.dns". + config.Domain*/
	minTtl    uint32
}

type Backend interface {
	Records(name string) ([]ServiceRecord, error)
	ReverseRecord(name string) (*ServiceRecord, error)
	Get(name string) ([]ServiceRecord, int64, error)
	GetRaw(name string) (*clientv3.GetResponse, error)
}

func (s *server) ParseRecords(kv *mvccpb.KeyValue) (*ServiceRecord, error) {
	record := new(ServiceRecord)
	if err := json.Unmarshal(kv.Value, record); err != nil {
		return nil, err
	}
	record.Key = string(kv.Key)
	if record.DnsPriority == 0 {
		record.DnsPriority = int(10)
	}
	return record, nil
}


func appendDnsDomain(s1, s2 string) string {
	if len(s2) > 0 && s2[0] == '.' {
		return s1 + s2
	}
	return s1 + "." + s2
}
// New returns a new skydns server.
func New(backend Backend,domains[]string ,addr,ipMonitorPath string,forwardNameServers []string, subDomainServers map[string][]string,cacheSize int ,random,hold bool) *server {
	s := new (server)
	s. backend   =      backend
	timeOut :=    30 * time.Second
	s.dnsUDPclient=  &dns.Client{Net: "udp", ReadTimeout: timeOut, WriteTimeout: timeOut, SingleInflight: true}
	s.dnsTCPclient=  &dns.Client{Net: "tcp", ReadTimeout: timeOut, WriteTimeout: timeOut, SingleInflight: true}
	s.dnsDomains = domains[:]
	s.dnsAddr   = addr
	s.ipMonitorPath= ipMonitorPath
	s.msgPool = queue.QueueNew()
	s.msgPool.Reset = cacheMsgRest
	s.syncPeriod = 10 * time.Minute
	s.minTtl = 60
	s.rcache =    NewMsgCache(cacheSize,random, hold,s.minTtl)
	s.forwardNameServers = forwardNameServers[:]
	s.subDomainServers = subDomainServers
	return s
}

// Path converts a domainname to an etcd path. If s looks like service.staging.skydns.local.,
// the resulting key will be /skydns/local/skydns/staging/service .
func DnsPath(s string) string {
	l := dns.SplitDomainName(s)
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	pathOrg := path.Join(append([]string{"/" + DnsPathPrefix + "/"}, l...)...)
	//add
	return pathOrg + "/"
}

// Domain is the opposite of Path.
func DnsDomain(s string) string {
	l := strings.Split(s, "/")
	// start with 1, to strip /skydns
	for i, j := 1, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return dns.Fqdn(strings.Join(l[2:len(l)-1], "."))
}

func (s *server) getSvcDomainName(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[2:], ".") // ingoore the first

	return domainKey[:len(domainKey)-len(DnsPathPrefix)-1]

}
func (s *server) getSvcCnameName(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[1:], ".")
	// ignore the head skydns.
	return domainKey[:len(domainKey)-len(DnsPathPrefix)-1]
}

func (s *server) updateRcacheParseRecord(kv *mvccpb.KeyValue) interface{} {
	if kv == nil {
		return nil
	}
	record, err := s.ParseRecords(kv)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return nil
	}
	ip := net.ParseIP(record.DnsHost)
	switch {
	case ip == nil:
		name := s.getSvcCnameName(record.Key)
		return record.NewRecordCname(name, dns.Fqdn(record.DnsHost))
	case ip.To4() != nil:
		name := s.getSvcDomainName(record.Key)
		return record.NewRecordA(name, ip.To4())
	default:
		glog.Infof("updateRcacheParseRecord err \n")
	}
	return nil
}

// add a record to canme typeA  map
func (s *server)doCreateRecordInCacheCname( record *ServiceRecord){
	if ip := net.ParseIP(record.DnsHost); ip == nil{
		key := dns.Fqdn(record.DnsHost)
		glog.V(2).Infof("ecord.Host = %s key =%s\n",record.DnsHost, s.getSvcCnameName(record.Key))
		s.rcache.InsertCachedDataCnameTypeAMap(key,s.getSvcCnameName(record.Key))
	}
}
// add a record to canme typeA  map
func (s *server) createRecordInCacheCname(kv *mvccpb.KeyValue){
	if kv == nil {
		return
	}
	record, err := s.ParseRecords(kv)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	if record.Dnstype != "CNAME"{
		return
	}
	s.doCreateRecordInCacheCname(record)
	return
}
// del a record to canme typeA  map
func (s *server) deleteRecordInCacheCname(kv *mvccpb.KeyValue)  {
	if kv == nil {
		return
	}
	record, err := s.ParseRecords(kv)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	if record.Dnstype != "CNAME"{
		return
	}

	if ip := net.ParseIP(record.DnsHost); ip == nil{
		key := dns.Fqdn(record.DnsHost)
		s.rcache.DelCachedDataCnameTypeAMap(key,s.getSvcCnameName(record.Key))
	}
	return
}

func (s *server)  WatchForDnsDomain(domain string, watchidx int64,client clientv3.Client){

	var watcher clientv3.WatchChan
	recordCatched := false

reWatch:
        if recordCatched{
		watchidx = watchidx+1
		recordCatched = false
	}
	glog.Infof("WatchForDomain idx : %d ", watchidx)
	opts := []clientv3.OpOption{}
	if watchidx > 0 {
		opts = append(opts, clientv3.WithRev(watchidx))
	}
	opts = append(opts, clientv3.WithPrefix())
	opts = append(opts, clientv3.WithPrevKV())

	ctx, cancel := context.WithTimeout(context.Background(), 2*s.syncPeriod)
	defer cancel()

	watcher = client.Watch(ctx, DnsPath(domain), opts...)
        var wres clientv3.WatchResponse

	for wres = range watcher {
		if wres.Err() != nil {
			err := wres.Err()
			glog.Infof("err : %s ", err)
			watchidx = wres.Header.Revision
			goto reWatch
		}
		for _, e := range wres.Events {
			s.UpdateRcache(e)
			recordCatched = true
		}

	}
	if err := wres.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err =%s\n",err)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	if err := ctx.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err =%s\n",err)
		watchidx = wres.Header.Revision
		goto reWatch
	}

	glog.Infof("WatchForDomain out : %d  watcher=%v domain =%s\n", watchidx,watcher,domain)
}

func (s *server) UpdateRcache(e *clientv3.Event) {
	glog.V(2).Infof("UpdateRcache: e = %+v", e)

	switch e.Type {
	case clientv3.EventTypePut:
		if e.IsCreate() {
			s.createRecordInCacheCname(e.Kv)
			valNew := s.updateRcacheParseRecord(e.Kv)
			if valNew != nil {
				s.SetEtcdCachedRecord(e.Kv)
				s.rcache.UpdateRcacheSet(valNew)

			}
		} else {
			valNew := s.updateRcacheParseRecord(e.Kv)
			var valOld interface{} = nil
			if e.PrevKv != nil {
				valOld = s.updateRcacheParseRecord(e.PrevKv)
			}
			if valNew != nil && valOld != nil {
				s.UpdateEtcdCachedRecord(e.PrevKv, e.Kv)
				s.rcache.UpdateRcacheUpdate(valOld, valNew)

			} else if valNew != nil {
				s.SetEtcdCachedRecord(e.Kv)
				s.rcache.UpdateRcacheSet(valNew)

			} else {
				glog.Infof("UpdateRcache  set err \n")
			}
		}

	case clientv3.EventTypeDelete:
		s.deleteRecordInCacheCname(e.PrevKv)

		valA := s.updateRcacheParseRecord(e.PrevKv)
		if valA != nil {
			s.DeleteEtcdCachedRecord(e.PrevKv)
			s.rcache.UpdateRcacheDelete(valA)

		} else {
			glog.Infof("UpdateRcache  del err \n")
		}
	default:
		glog.Infof("the action not monitored: Action =%d kv=%v", e.Type, e.Kv)

	}
}

// Run is a blocking operation that starts the server listening on the DNS ports.
func (s *server) RunToEnd()  {
	mux := dns.NewServeMux()
	mux.Handle(".", s)
	go func() {
		if err := dns.ListenAndServe(s.dnsAddr, "tcp", mux); err != nil {
			glog.Fatalf("%s", err)
		}
	}()
	glog.Infof("ready for queries on %v for %s://%s ", s.dnsDomains, "tcp", s.dnsAddr)
	go func() {
		if err := dns.ListenAndServe(s.dnsAddr, "udp", mux); err != nil {
			glog.Fatalf("%s", err)
		}
	}()
	glog.Infof("ready for queries on %s for %s://%s ", s.dnsDomains, "udp", s.dnsAddr)
	select{}
}


func FitUdpSize(m *dns.Msg) (*dns.Msg) {
	m.Truncated = true
	m.Extra = nil
	min, max := 0, len(m.Answer)
	original := make([]dns.RR, len(m.Answer))
	copy(original, m.Answer)
	for {
		if min == max {
			break
		}
		mid := (min + max) / 2
		m.Answer = original[:mid]

		if m.Len() < 512 {
			min++
			continue
		}
		max = mid

	}
	if max > 1 {
		max--
	}
	m.Answer = m.Answer[:max]
	return m
}

func (s *server) checkAndWtiteMsg(w dns.ResponseWriter, req *dns.Msg,m *dns.Msg, tcp,write bool){
	if !tcp {
		if  m.Len() > 512{
			m = FitUdpSize(m)
		}
	}else{
		if m.Len() > dns.MaxMsgSize {
			atomic.AddInt64(&statsErrorCountOverflow, 1)
			msgFail := new(dns.Msg)
			s.dnsServerFailure(msgFail, req)
			w.WriteMsg(msgFail)
			return
		}
	}
	if req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA {
		s.RoundRobinRecords(m.Answer)
	}

	if write{
		if err := w.WriteMsg(m); err != nil {
			glog.Infof("failure to return reply %q", err)
		}
	}
}


func (s *server) RoundRobinRecords(answers []dns.RR) {
	if len(answers) ==1{
		return
	}
	if len(answers) ==2{
		swapIdx := int(dns.Id()) % 2
		if swapIdx ==1{
			answers[0], answers[1] = answers[1], answers[0]
		}
		return
	}
	maxLen := len(answers)
	for idx := 0; idx < maxLen ; idx++ {
		swapIdx := int(dns.Id()) % maxLen
		if swapIdx == idx {
			continue
		}
		answers[idx], answers[swapIdx] = answers[swapIdx],answers[idx]
	}
}

func (s *server)getMsgResource(req *dns.Msg)*dns.Msg{
	var m *dns.Msg
	msgP := s.msgPool.DeQueue()
	if msgP == nil{
		m = new(dns.Msg)
	}else{
		m = msgP.(*dns.Msg)
	}
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Compress = true
	return m
}

func (s *server)processLocalDomainRecord(w dns.ResponseWriter, req *dns.Msg, m *dns.Msg,remoteIp,parentDomain string, timeNow time.Time){
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	tcp := isTCPQuery(w)
	EtcdCachesLock.RLock()
	updateTime := s.GetEtcdRecordLastUpdateTime(name)
	EtcdCachesLock.RUnlock()

	defer func() {
		s.checkAndWtiteMsg(w,req,m,tcp,false)
		if q.Qtype == dns.TypeA && !tcp{
			//when insert we could not chage the EtcdCaches with the EtcdCachesLock
			EtcdCachesLock.RLock()
			updateTimeNow := s.GetEtcdRecordLastUpdateTime(name)
			if updateTimeNow.Equal(updateTime){
				s.rcache.Add2MsgCache(CacheKey(q, tcp), m, remoteIp, timeNow, false)
			}
			EtcdCachesLock.RUnlock()
		}
		if err := w.WriteMsg(m); err != nil {
			glog.Infof("failure to return reply %q", err)
		}
	}()

	var dnsRecords, extra []dns.RR
	var err error
	switch q.Qtype {
	case dns.TypeNS:
		nsDomain := ""
		for _, domain := range(s.dnsDomains){
			if name == domain {
				nsDomain = appendDnsDomain("ns.dns", domain)
				break
			}
		}
		if nsDomain != ""{
			dnsRecords, extra, err = s.getNSRecordsBind9Record(q, nsDomain )
		}

	case dns.TypeA, dns.TypeAAAA:
		// domain name return bind9 type
		for _, domain := range(s.dnsDomains){
			if name != domain{
				continue
			}
			nsDomain := appendDnsDomain("ns.dns", domain)
			ns, extra, _ := s.getNSRecordsBind9Record(q, nsDomain )
			m.Ns = append(m.Ns, ns...)
			m.Extra = append(m.Extra, extra...)
			dnsIpname := "dns-ip.dns." + nsDomain
			dnsRecords, err := s.getAddressRecords(q, dnsIpname, false)
			if isEtcdNameNotFound(err, s) {
				s.dnsNameError(m, req,parentDomain)
				return
			}
			m.Answer = append(m.Answer, dnsRecords...)
			return
		}

		dnsRecords, err = s.getAddressRecords(q, name, false)

	case dns.TypeTXT:
		txtDomain := ""
		for _, domain := range(s.dnsDomains){
			if name == domain {
				txtDomain = appendDnsDomain("txt", domain)
				break
			}
		}
		if txtDomain != ""{
			dnsRecords, err = s.getTXTRecords(q, txtDomain )
		}

	case dns.TypeCNAME:
		dnsRecords, err = s.getCNAMERecords(q, name)

	case dns.TypeMX:
		mailDomain := ""
		for _, domain := range(s.dnsDomains){
			if name == domain {
				mailDomain = appendDnsDomain("mail", domain)
				break
			}
		}
		if mailDomain != ""{
			dnsRecords, extra, err = s.getMXRecords(q, mailDomain,tcp)
		}

	case dns.TypeSRV:
		dnsRecords, extra, err = s.getSRVRecords(q, name,tcp)
	default:
		s.dnsServerFailure(m, req)
		return
	}
	if isEtcdNameNotFound(err, s) {
		s.dnsNameError(m, req,parentDomain)
		return
	}
	m.Answer = append(m.Answer, dnsRecords...)
	m.Extra = append(m.Extra, extra...)

	if len(m.Answer) == 0 { // NODATA response
		atomic.AddInt64(&statsNoDataCount, 1)
		m.Ns = []dns.RR{s.genDnsNewSOA(parentDomain)}
		m.Ns[0].Header().Ttl = 60
	}
}


// ServeDNS is the handler for DNS requests

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
        m := s.getMsgResource(req)
	defer s.msgPool.EnQueue(m)
	timeNow := time.Now().Local()
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	tcp := false
	if tcp = isTCPQuery(w); tcp {
		atomic.AddInt64(&statsRequestCountTcp, 1)
	} else {
		atomic.AddInt64(&statsRequestCountUdp, 1)
	}
	atomic.AddInt64(&statsRequestCount, 1)

	glog.V(3).Infof("received DNS Request for %q from %q with type %d", q.Name, w.RemoteAddr(), q.Qtype)

	// Check cache first.
	remoteAddr := w.RemoteAddr().String() //10.8.65.158:42158
	remoteIp := strings.Split(remoteAddr, ":")
	m1 := s.rcache.SearchRecordInCache(q, tcp, m.Id, remoteIp[0], timeNow)
	if m1 != nil {
		atomic.AddInt64(&statsRequestCountCached, 1)
		glog.V(4).Infof("cache hit %q: %v\n ", q.Name, m1)
		s.checkAndWtiteMsg(w,req,m1,tcp,true)
		MsgCachePool.EnQueue(m1)
		return
	}

	if q.Qclass == dns.ClassCHAOS  || q.Qtype == dns.TypePTR  {
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			glog.Infof("failure to return reply %q", err)
		}
		return
	}
	atomic.AddInt64(&statsCacheMissResponse, 1)
	// cluster domain forward
	for subKey, subVal := range s.subDomainServers {
		if strings.HasSuffix(name, subKey) {
			resp := s.dnsDomainForward(w, req, subVal,remoteIp[0], timeNow)
			glog.V(4).Infof("ServeSubDomainForward %q: %v \n ", q.Name, resp.Answer)
			return
		}
	}
	// domain local
	for _, domain := range s.dnsDomains {
		if strings.HasSuffix(name, domain) {
			// find local record and insert to cache
			s.processLocalDomainRecord(w,req,m,remoteIp[0],domain ,timeNow)
			return
		}
	}
        // ex-domain froward
	resp := s.dnsDomainForward(w, req,s.forwardNameServers, remoteIp[0], timeNow)
	glog.V(4).Infof("ServeDNSForward %q: %v \n ", q.Name, resp.Answer)
	return
}


func (s *server) getAddressRecords(q dns.Question, name string, preCname bool) (dnsRecords []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		glog.V(1).Infof("AddressRecords err  %s q name=%s\n", err.Error(), q.Name)
		return nil, err
	}
	for _, record := range etcdRecords {
		if record.DnsHost == "" {
			continue
		}
		ip := net.ParseIP(record.DnsHost)
		if ip == nil {
			if q.Name == dns.Fqdn(record.DnsHost) {
				continue
			}
			cnameRecord := record.NewRecordCname(q.Name, dns.Fqdn(record.DnsHost))
			if preCname {
				glog.Infof("CNAME lookup limit of 1 exceeded for %s", cnameRecord)
				continue
			}
			ipRecords, err := s.getAddressRecords(dns.Question{Name: dns.Fqdn(record.DnsHost), Qtype: q.Qtype, Qclass: q.Qclass},
				strings.ToLower(dns.Fqdn(record.DnsHost)), true)
			if err == nil {
				if len(ipRecords) > 0 {
					dnsRecords = append(dnsRecords, cnameRecord) // we do not need the record just return the ip
					dnsRecords = append(dnsRecords, ipRecords...)
				}
			}
			continue
		}
		if ip.To4() != nil && (q.Qtype == dns.TypeA ) {
			dnsRecords = append(dnsRecords, record.NewRecordA(q.Name, ip.To4()))
		}else if ip.To4() == nil && (q.Qtype == dns.TypeAAAA ){
			dnsRecords = append(dnsRecords, record.NewRecordAAAA(q.Name, ip.To16()))
		}
	}
	return dnsRecords, nil
}

func (s *server)AddressRecordsCheck (name string, recordCaches map[string][]ServiceRecord,preCname bool) (dnsRecords []dns.RR, err error) {
	for _, record := range recordCaches[name] {
		if record.DnsHost == "" {
			continue
		}
		ip := net.ParseIP(record.DnsHost)
		// cname
		if ip == nil{
			if name == dns.Fqdn(record.DnsHost) {
				continue
			}
			cnameRecord := record.NewRecordCname(name, dns.Fqdn(record.DnsHost))
			if preCname {
				glog.Infof("CNAME lookup limit of 1 exceeded for %s", cnameRecord)
				continue
			}
			ipRecords, err := s.AddressRecordsCheck(dns.Fqdn(record.DnsHost),recordCaches, true)
			if err == nil {
				if len(ipRecords) > 0 {
					dnsRecords = append(dnsRecords, cnameRecord) // we do not need the record just return the ip
					dnsRecords = append(dnsRecords, ipRecords...)
				}
			}
			continue
		}
		if ip.To4() != nil{
			dnsRecords = append(dnsRecords, record.NewRecordA(name, ip.To4()))
		}
	}
	return dnsRecords, nil
}
func (s *server) getCNAMERecords(q dns.Question, name string) (dnsRecords []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, err
	}
	if len(etcdRecords) > 0 {
		record := etcdRecords[0]
		if ip := net.ParseIP(record.DnsHost); ip == nil {
			dnsRecords = append(dnsRecords, record.NewRecordCname(q.Name, dns.Fqdn(record.DnsHost)))
		}
	}
	return dnsRecords, nil
}

func (s *server) getNSRecords(q dns.Question, name string) (dnsRecords []dns.RR, extra []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, nil, err
	}
	for _, record := range etcdRecords {
		ip := net.ParseIP(record.DnsHost)
		if ip == nil{
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		}
		if ip.To4() != nil{
			record.DnsHost = DnsDomain(record.Key)
			dnsRecords = append(dnsRecords, record.NewRecordNS(q.Name, record.DnsHost))
			extra = append(extra, record.NewRecordA(record.DnsHost, ip.To4()))

		}else {
			record.DnsHost = DnsDomain(record.Key)
			dnsRecords = append(dnsRecords, record.NewRecordNS(q.Name, record.DnsHost))
			extra = append(extra, record.NewRecordAAAA(record.DnsHost, ip.To16()))
		}
	}
	return dnsRecords, extra, nil
}


func (s *server) getNSRecordsBind9Record(q dns.Question, name string) (dnsRecords []dns.RR, extra []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, nil, err
	}
	for _, record := range etcdRecords {
		ip := net.ParseIP(record.DnsHost)
		if ip == nil{
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		}
		if ip.To4() != nil{
			domain := DnsDomain(record.Key)
			domain = strings.Replace(domain, "ns.dns.", "", 1)
			record.DnsHost = domain
			dnsRecords = append(dnsRecords, record.NewRecordNS(q.Name, record.DnsHost))
			extra = append(extra, record.NewRecordA(record.DnsHost, ip.To4()))
		}else{
			domain := DnsDomain(record.Key)
			domain = strings.Replace(domain, "ns.dns.", "", 1)
			record.DnsHost = domain
			dnsRecords = append(dnsRecords, record.NewRecordNS(q.Name, record.DnsHost))
			extra = append(extra, record.NewRecordAAAA(record.DnsHost, ip.To16()))
		}
	}
	return dnsRecords, extra, nil
}

func (s *server) isSubDomain(name string ) bool {
	for _, domain := range s.dnsDomains {
		if strings.HasSuffix(name, domain){
			return true
		}
	}
	return false
}
func (s *server) getSRVRecords(q dns.Question, name string,tcp bool) (dnsRecords []dns.RR, extra []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, nil, err
	}
	// get the sum of the same Priority
	weightSum := make(map[int]int)
	for _, record := range etcdRecords {
		weight := 100
		if record.DnsWeight != 0 {
			weight = record.DnsWeight
		}
		if _, ok := weightSum[record.DnsPriority]; !ok {
			weightSum[record.DnsPriority] = weight
			continue
		}
		weightSum[record.DnsPriority] += weight
	}
	foundRecord := make(map[string]bool)
	for _, record := range etcdRecords {
		weightf := 100.0 / float64(weightSum[record.DnsPriority])
		if record.DnsWeight == 0 {
			weightf *= 100
		} else {
			weightf *= float64(record.DnsWeight)
		}
		weight := uint16(math.Floor(weightf))
		ip := net.ParseIP(record.DnsHost)
		if ip == nil{
			srv := record.NewRecordSRV(q.Name, weight)
			dnsRecords = append(dnsRecords, srv)
			if _, ok := foundRecord[srv.Target]; ok {
				break
			}
			foundRecord[srv.Target] = true
			if !s.isSubDomain(srv.Target) {
				continue
			}
			addr, e1 := s.getAddressRecords(dns.Question{srv.Target, dns.ClassINET, dns.TypeA}, srv.Target, false)
			if e1 == nil {
				extra = append(extra, addr...)
			}
			continue
		}
		if ip.To4() != nil {
			record.DnsHost = DnsDomain(record.Key)
			newR := record.NewRecordSRV(q.Name, weight)
			dnsRecords = append(dnsRecords, newR)
			extra = append(extra, record.NewRecordA(newR.Target, ip.To4()))
		}else{
			record.DnsHost = DnsDomain(record.Key)
			newR := record.NewRecordSRV(q.Name, weight)
			dnsRecords = append(dnsRecords, newR)
			extra = append(extra, record.NewRecordAAAA(newR.Target, ip.To16()))
		}
	}
	return dnsRecords, extra, nil
}

func (s *server) getMXRecords(q dns.Question, name string,tcp bool) (dnsRecords []dns.RR, extra []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, nil, err
	}
	foundRecord := make(map[string]bool)
	for _, record := range etcdRecords {
		if !record.DnsMail {
			continue
		}
		ip := net.ParseIP(record.DnsHost)
		if ip == nil {
			mxR := record.NewRecordMx(q.Name)
			dnsRecords = append(dnsRecords, mxR)
			if _, ok := foundRecord[mxR.Mx]; ok {
				break
			}
			foundRecord[mxR.Mx] = true
			if !s.isSubDomain( mxR.Mx) {
				continue
			}
			// Internal name
			addr, e1 := s.getAddressRecords(dns.Question{mxR.Mx, dns.ClassINET, dns.TypeA}, mxR.Mx, false)
			if e1 == nil {
				extra = append(extra, addr...)
			}
			continue
		}

		if ip.To4() != nil {
			record.DnsHost = DnsDomain(record.Key)
			dnsRecords = append(dnsRecords, record.NewRecordMx(q.Name))
			extra = append(extra, record.NewRecordA(record.DnsHost, ip.To4()))
		} else {
			record.DnsHost = DnsDomain(record.Key)
			dnsRecords = append(dnsRecords, record.NewRecordMx(q.Name))
			extra = append(extra, record.NewRecordAAAA(record.DnsHost, ip.To16()))
		}
	}
	return dnsRecords, extra, nil
}

func (s *server) getTXTRecords(q dns.Question, name string) (dnsRecords []dns.RR, err error) {
	etcdRecords, err := s.backend.Records(name)
	if err != nil {
		return nil, err
	}
	for _, record := range etcdRecords {
		if record.DnsText == "" {
			continue
		}
		dnsRecords = append(dnsRecords, record.NewRecordTXT(q.Name))
	}
	return dnsRecords, nil
}


func (s *server) genDnsNewSOA(domain string ) dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: domain , Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      appendDnsDomain("ns1",domain ),
		Mbox:    appendDnsDomain("hostmaster@",domain ),
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 14400,
		Retry:   3600,
		Expire:  604800,
		Minttl:  s.minTtl,
	}

}

func (s *server) isDuplicateCNAME(r *dns.CNAME, dnsRecords []dns.RR) bool {
	for _, rec := range dnsRecords {
		if v, ok := rec.(*dns.CNAME); ok {
			if v.Target == r.Target {
				return true
			}
		}
	}
	return false
}

func (s *server) dnsNameError(m, req *dns.Msg,domain string) {
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{s.genDnsNewSOA(domain)}
	m.Ns[0].Header().Ttl = s.minTtl
	atomic.AddInt64(&statsErrorCountNoname, 1)
}

func (s *server) dnsNoDataError(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeSuccess)
	m.Ns = []dns.RR{s.genDnsNewSOA("")}
	m.Ns[0].Header().Ttl = s.minTtl
	atomic.AddInt64(&statsNoDataCount, 1)

}

func (s *server) dnsServerFailure(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeServerFailure)
	atomic.AddInt64(&statsErrorCountServfail, 1)
}


func isTCPQuery(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

func isEtcdNameNotFound(err error, s *server) bool {
	if err != nil {
		if strings.HasPrefix(err.Error(),"key not found") {
			return true
		}
		glog.Infof("error from backend: %s", err)
	}
	return false
}
