// Copyright (c) 2017 The skydns Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package dnsServer

import (
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	statsErrorCountRefused   int64 = 0
	statsErrorCountOverflow  int64 = 0
	statsErrorCountTruncated int64 = 0
	statsErrorCountServfail  int64 = 0
	statsErrorCountNoname    int64 = 0

	statsRequestCountTcp    int64 = 0
	statsRequestCountUdp    int64 = 0
	statsRequestCount       int64 = 0
	statsForwardCount       int64 = 0
	statsCacheMissResponse  int64 = 0
	statsRequestCountCached int64 = 0

	statsStubForwardCount int64 = 0

	statsNoDataCount int64 = 0

	statsDnssecOkCount   int64 = 0
	statsDnssecCacheMiss int64 = 0
)

var statsAuthToken = ""

type comStats struct {
	RequestCount    int64 `json:"reqCount,omitempty"`
	ForwardCount    int64 `json:"forwardCount,omitempty"`
	CacheMissCount  int64 `json:"cacheMissCount,omitempty"`
	DataCachedCount int64 `json:"dataCachedCount,omitempty"`
	CacheSizeUsed    int   `json:"cacheSizeUsed,omitempty"`
	DomainSize    int   `json:"domainSize,omitempty"`
	ErrorCountNoname   int64 `json:"noNameCount,omitempty"`
	ErrorCountOverflow int64 `json:"overFlowCount,omitempty"`
	ErrorNoDataCount   int64 `json:"noDataCount,omitempty"`
}
type domainStats struct {
	RequestCount  int64     `json:"reqCount,omitempty"`
	LastQueryTime time.Time `json:"lastQueryTime,omitempty"`
	FirstQueryTime time.Time `json:"firstQueryTime,omitempty"`
}

type domainMsgInfo struct {
	Msgs []ServiceRecord      `json:"msgs,omitempty"`
	UpdateTime time.Time `json:"updateTime,omitempty"`
}

type controller struct {
	CacheTtl uint64 `json:"cacheTtl,omitempty"`
	SyncPeriod uint64 `json:"syncPeriod,omitempty"`
}

func (a *server) getReqBody(r *http.Request, c *controller) {
	result, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	json.Unmarshal([]byte(result), c)
}
func (s *server) ConfigList(w http.ResponseWriter, r *http.Request) {
	var c controller
	c.CacheTtl = s.rcache.CacheForwardTtlGet()
	c.SyncPeriod = uint64(s.syncPeriod  / time.Minute)
	b, err := json.Marshal(c)
	if err != nil {
		fmt.Fprintf(w, "%s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))

}
func (s *server) ConfigSet(w http.ResponseWriter, r *http.Request) {
	var c controller
	s.getReqBody(r, &c)
	if c.CacheTtl > 0 {
		s.rcache.CacheForwardTtlSet(c.CacheTtl)
	}
	if c.SyncPeriod > 0 {
		s.syncPeriod = time.Duration(c.SyncPeriod ) * time.Minute
	}
	fmt.Fprintf(w, "%s\n", "OK")
}

func (s *server) statsList(w http.ResponseWriter, r *http.Request) {
	var sta comStats
	sta.ForwardCount = statsForwardCount
	sta.DataCachedCount = statsRequestCountCached
	sta.CacheMissCount = statsCacheMissResponse
	sta.CacheSizeUsed = s.rcache.CacheSizeUsed()
	sta.DomainSize    = s.GetDomainSize()
	sta.ErrorCountNoname = statsErrorCountNoname
	sta.ErrorCountOverflow = statsErrorCountOverflow
	sta.ErrorNoDataCount = statsNoDataCount

	sta.RequestCount = statsRequestCount

	b, err := json.Marshal(sta)
	if err != nil {
		fmt.Fprintf(w, "%s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))

}

func basicAuth(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token == statsAuthToken {
			handler.ServeHTTP(w, r)
			return
		}
		fmt.Fprintf(w, "No authorized\n")
	}
}
func (s *server) statsShowCache(w http.ResponseWriter, r *http.Request) {

	var sta domainStats
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	countUdp, lasttime,firsttime := s.rcache.ShowCacheStats(domain, false)
	if countUdp == 0 {
		fmt.Fprintf(w, "%s\n", "domain not found")
		return
	}
	sta.LastQueryTime = lasttime
	sta.FirstQueryTime = firsttime
	sta.RequestCount = countUdp
	b, err := json.Marshal(sta)
	if err != nil {
		fmt.Fprintf(w, "%s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))
}

func (s *server) domainShowL1Cache(w http.ResponseWriter, r *http.Request) {
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	msgs,update := s.ShowEtcdCacheDnsDomain(domain)
	var info domainMsgInfo
	info.UpdateTime = update
	info.Msgs = msgs

	if len(msgs) > 0 {
		b, err := json.Marshal(info)
		if err != nil {
			fmt.Fprintf(w, "%s\n", err.Error())
			return
		}
		fmt.Fprintf(w, "%s\n", string(b))
	} else {
		fmt.Fprintf(w, "no found domain : %s\n", domain)
		return
	}
}
func (s *server) domainPostL1Cache(w http.ResponseWriter, r *http.Request) {
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	ok := s.UpdateEtcdCacheDnsDomain(domain)
	if ok {
		fmt.Fprintf(w, "OK\n")
	} else {
		fmt.Fprintf(w, "no found domain: %s\n", domain)
	}
}


func (s *server) domainDeleteL1Cache(w http.ResponseWriter, r *http.Request) {
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	ok := s.DeleteEtcdCacheDnsDomain(domain)
	if ok {
		fmt.Fprintf(w, "OK\n")
	} else {
		fmt.Fprintf(w, "no found domain: %s\n", domain)
	}
	return
}

func (s *server) domainShowCache(w http.ResponseWriter, r *http.Request) {
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	msg := s.rcache.ShowCacheDnsDomain(domain, false)
	if msg == nil {
		fmt.Fprintf(w, "no found domain: %s\n", domain)
		return
	}

	b, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(w, "%s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))

}

func (s *server) domainDeleteCache(w http.ResponseWriter, r *http.Request) {
	//udp
	vars := mux.Vars(r)
	domain := vars["domain"]
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	ok := s.rcache.DeleteCacheDnsDomain(domain, false)
	if ok {
		fmt.Fprintf(w, "OK\n")
	} else {
		fmt.Fprintf(w, "no found domain: %s\n", domain)
	}
	return
}
func (s *server) Statistics(stAddr string, auth string) {
	if stAddr == "" {
		return
	}
	statsAuthToken = auth
	_, err := net.Dial("tcp", stAddr)
	if err == nil {
		glog.Fatalf("statics the addr is used:%s\n", stAddr)
	}
	r := mux.NewRouter()
	r.HandleFunc("/skydns/stats", s.statsList).Methods("GET")
	r.HandleFunc("/skydns/stats/{domain}", s.statsShowCache).Methods("GET")

	r.HandleFunc("/skydns/domain/{domain}", s.domainShowCache).Methods("GET")
	r.HandleFunc("/skydns/domain/{domain}", s.domainDeleteCache).Methods("DELETE")

	r.HandleFunc("/skydns/domainL1/{domain}", s.domainShowL1Cache).Methods("GET")
	r.HandleFunc("/skydns/domainL1/{domain}", s.domainDeleteL1Cache).Methods("DELETE")
	r.HandleFunc("/skydns/domainL1/{domain}", s.domainPostL1Cache).Methods("POST")

	r.HandleFunc("/skydns/master", s.ConfigList).Methods("GET")
	r.HandleFunc("/skydns/master", s.ConfigSet).Methods("POST")

	http.HandleFunc("/", basicAuth(r))
	glog.Infof("statistics enabled on :%s", stAddr)
	err = http.ListenAndServe(stAddr, nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to start API service:%s", err))
	}

}
