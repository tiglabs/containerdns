// Copyright (c) 2017 The containerdns Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package dnsServer

import (
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"sync/atomic"
	"time"
)
func (s *server) dnsForwardErr(w dns.ResponseWriter, req *dns.Msg, remoteIp string, timeNow time.Time) *dns.Msg {
	if len(s.forwardNameServers) == 0 {
		glog.Infof("can not forward, no nameservers defined")
	} else {
		glog.Infof("can not forward, name too short (less than %d labels): `%s'", 2, req.Question[0].Name)
	}
	tcp := isTCPQuery(w)

	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	m.Authoritative = false
	s.rcache.Add2MsgCache(CacheKey(req.Question[0], tcp),m,remoteIp,timeNow,true)
	m.RecursionAvailable = true
	w.WriteMsg(m)
	return m
}


func (s *server) dnsDomainForward(w dns.ResponseWriter, req *dns.Msg,forwardServers []string, remoteIp string, timeNow time.Time) *dns.Msg {
	atomic.AddInt64(&statsForwardCount, 1)
	tcp := isTCPQuery(w)
	if len(s.forwardNameServers) == 0 || dns.CountLabel(req.Question[0].Name) < 2 {
		s.dnsForwardErr(w,req,remoteIp,timeNow)
	}
	var msgForward   *dns.Msg
	var err error
	for  _, forwardServer := range forwardServers{
		if !tcp{
			msgForward, _, err = s.dnsUDPclient.Exchange(req, forwardServer)
		}else{
			msgForward, _, err = s.dnsTCPclient.Exchange(req, forwardServer)
		}
		if err == nil {
			msgForward.Compress = true
			msgForward.Id = req.Id
			s.rcache.Add2MsgCache(CacheKey(req.Question[0], tcp), msgForward,remoteIp,timeNow,true)
			w.WriteMsg(msgForward)
			return msgForward
		}
	}
	glog.Infof("failure to forward request %q, req name:%s", err, req.Question[0].Name)
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	s.rcache.Add2MsgCache(CacheKey(req.Question[0], tcp), m, remoteIp, timeNow, true)
	w.WriteMsg(m)
	return m
}