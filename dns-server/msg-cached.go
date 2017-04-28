// Copyright (c) 2017 The skydns Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package dnsServer

import (
	"bytes"
	"crypto/sha1"
	"hash/fnv"
	"sync"
	"time"
	"github.com/ipdcode/skydns/queue"
	"github.com/golang/glog"
	"github.com/miekg/dns"
)

// Elem hold an answer and additional section that returned from the cache.
// The signature is put in answer, extra is empty there. This wastes some memory.
type cacheElem struct {
	sync.Mutex
	expiration      time.Time // time added + TTL, after this the elem is invalid
	msg             *dns.Msg
	mAnswer         map[string]int // keep to return the pre ip
	ips             []dns.RR       //msg typeA records
	cnames          []dns.RR       //msg cname records
	requestCount    int64
	requestLastTime time.Time
	requestFirstTime time.Time
	forwarding      bool // if true we don not check the ip
}
// cnametypeA hold a record to the host and alias map
type cnametypeA struct{
	alians       []string
	updateTime  time.Time
	toDel       bool
}

// Cache is a cache that holds on the a number of RRs or DNS messages. The cache
// eviction is randomized.
type Cache struct {
	sync.RWMutex
	capacity      int
	elemsMap             map[string]*cacheElem
	AvaliableIps  map[string]bool // the host alive
	AvaliableIpsUpdateTime     time.Time
	// the map to record canme name value
	// the key is the domain of typeA val alias-domains
	cnameMapTypeA  map[string]* cnametypeA// the host alive

	ttl           time.Duration
	minTtl        uint32
	pickRandomOne bool
	ipHold        bool
}
var MsgCachePool *queue.Queue

func  cacheMsgRest(val interface{}) {
	msg := val.(*dns.Msg)
	msg.MsgHdr = dns.MsgHdr{0,false,0,false,false,false,false,false,false,false,0}
	msg.Question = []dns.Question{}
	msg.Answer = []dns.RR{}
	msg.Ns = []dns.RR{}
	msg.Extra = []dns.RR{}
}
// New returns a new cache with the capacity and the ttl specified.
func NewMsgCache(capacity int, randomOne bool, ipHold bool,minTtl uint32) *Cache {
	c := new(Cache)
	c.elemsMap = make(map[string]*cacheElem)
	c.AvaliableIps = make(map[string]bool)
	c.cnameMapTypeA = make(map[string]*cnametypeA)
	c.capacity = capacity
	c.ipHold = ipHold
	c.ttl = 60 * time.Second
	c.minTtl  = minTtl
	c.pickRandomOne = randomOne
	MsgCachePool = queue.QueueNew()
	MsgCachePool.Reset = cacheMsgRest
	return c
}
func keyPack(i uint16) []byte{ return []byte{byte(i >> 8), byte(i)} }

func (c *Cache) Capacity() int { return c.capacity }

func (c *Cache) CacheSizeUsed() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.elemsMap)
}
func (c *Cache) CacheForwardTtlGet() uint64 {
	c.RLock()
	defer c.RUnlock()
	return uint64(c.ttl / time.Second)
}
func (c *Cache) CacheForwardTtlSet(ttl uint64) {
	c.Lock()
	defer c.Unlock()
	c.ttl = time.Duration(ttl) * time.Second
}

func (c *Cache) Remove(s string) {
	c.Lock()
	delete(c.elemsMap, s)
	c.Unlock()
}
func (c *Cache) EnsureNoExist(name string, qtype uint16, tcp bool) {
	h := sha1.New()
	i := append([]byte(name), keyPack(qtype)...)
	if tcp {
		i = append(i, byte(254))
	}
	key := string(h.Sum(i))
	c.Lock()
	if _, ok := c.elemsMap[key]; ok {
		glog.V(2).Infof("del key =%s type =%d\n", key, qtype)
		delete(c.elemsMap, key)
	}
	c.Unlock()
}

// the key in cache is diff from domain
func (c *Cache) KeyTypeA(name string, dnssec, tcp bool) string {
	h := sha1.New()
	i := append([]byte(name), keyPack(dns.TypeA)...)
	if dnssec {
		i = append(i, byte(255))
	}
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}

func (c *Cache) syncCmpMsgAnswerSame (vals1 []dns.RR,vals2 []dns.RR)bool{
	if len(vals1) != len(vals2){
		return false
	}
	for _,val1 := range(vals1){
		//typeA
		valAnswerA, b := val1.(*dns.A)
		if b{
			i :=0
			for _,val2 :=range(vals2){
				i++
				valAnswerB, b := val2.(*dns.A)
				if b{
					if 0 == bytes.Compare(valAnswerB.A, valAnswerA.A){
						break
					}
				}
			}
			if i >len(vals2){
				return false
			}
		}
		// cname
		valAnswerC, c := val1.(*dns.CNAME)
		if c{
			i :=0
			for _,val2 :=range(vals2){
				i++
				valAnswerB, b := val2.(*dns.CNAME)
				if b{
					if valAnswerB.Target == valAnswerC.Target{
						break
					}
				}
			}
			if i >len(vals2){
				return false
			}
		}
	}
        return true
}
func (c *Cache) SyncCheckCachedRecords (mAnswers map[string][]dns.RR) {
	cache2Del := make(map[string]bool)
	c.RLock()
	for key ,val := range(c.elemsMap){
		if _, ok := mAnswers[key]; !ok {
			cache2Del[key] = true
			continue
		}
		if ! c.syncCmpMsgAnswerSame(val.msg.Answer, mAnswers[key]){
			cache2Del[key] = true
		}
	}
	c.RUnlock()
	// del rubbish record, we do not care what happened  during the RUnlock and Lock
	c.Lock()
	i := 0
	for key ,_ := range(cache2Del){
		if _, ok := c.elemsMap[key]; ok {
			i++
			delete(c.elemsMap, key)
		}
	}
	c.Unlock()
	if i >0{
		glog.Infof("sync cache2Del :%d real del :%d\n",len(cache2Del),i)
	}
}
func (c *Cache) ShowCacheStats(domain string, tcp bool) (int64, time.Time,time.Time) {
	//udp
	c.RLock()
	defer c.RUnlock()
	key := c.KeyTypeA(domain, false, tcp)
	if e, ok := c.elemsMap[key]; ok {
		return e.requestCount, e.requestLastTime,e.requestFirstTime
	} else {
		return 0, time.Time{},time.Time{}
	}
}
func (c *Cache) ShowCacheDnsDomain(domain string, tcp bool) *dns.Msg {
	//udp
	c.Lock()
	defer c.Unlock()
	key := c.KeyTypeA(domain, false, tcp)
	if e, ok := c.elemsMap[key]; ok {
		return e.msg.Copy()
	} else {
		return nil
	}
}
func (c *Cache) DeleteCacheDnsDomain(domain string, tcp bool) bool {
	//udp
	c.Lock()
	defer c.Unlock()
	key := c.KeyTypeA(domain, false, tcp)
	if _, ok := c.elemsMap[key]; ok {
		delete(c.elemsMap, key)
		return true
	} else {
		return false
	}
}

// the key in cache is diff from domain
func (c *Cache) keyExtendTypeA(name string, dnssec, tcp bool) string {
	h := sha1.New()
	t := []byte(name) // del skydns test.default.skydns.local.skydns. -->test.default.skydns.local. 6: sizeof(skydns.)
	i := append(t[:len(t)-6], keyPack(dns.TypeA)...)
	if dnssec {
		i = append(i, byte(255))
	}
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}

func (c *Cache) checkCacheExitst(r interface{}) (valueIdx int, keyExist bool, valExist bool, key string) {

	var nameR string = ""
	var valA *dns.A = nil
	var valCname *dns.CNAME = nil

	keyExist = false
	valExist = false
	valueIdx = -1
	key = ""
	switch r.(type) {
	case *dns.A:
		valA = r.(*dns.A)
		nameR = valA.Hdr.Name
	case *dns.CNAME:
		valCname = r.(*dns.CNAME)
		nameR = valCname.Hdr.Name
	default:
		return valueIdx, keyExist, valExist, key
	}
	valueIdx = 0
	key = c.KeyTypeA(nameR, false, false)
	if e, ok := c.elemsMap[key]; ok {
		keyExist = true
		// Cname match specal value -1
		if valCname != nil {
			return -1, keyExist, valExist, key
		}
		// type A  match ,we compare the value
		for _, r := range e.msg.Answer {
			valAnswerA, b := r.(*dns.A)
			if b {
				ret := bytes.Compare(valA.A, valAnswerA.A)
				if ret == 0 {
					valExist = true
					return valueIdx, keyExist, valExist, key
				}
			}
			valueIdx += 1
		}
	}
	// the key find but no value use uadateset
	return valueIdx, keyExist, valExist, key
}

//del the val from the l2 level cache
func (c *Cache) delValFromDictL2(valA *dns.A, l2Map map[string][]dns.RR) {
	for k, v := range l2Map {
		valAnswerA, b := v[0].(*dns.A)
		if b {
			ret := bytes.Compare(valA.A, valAnswerA.A)
			if ret == 0 {
				delete(l2Map, k)
			}
		}

	}
	return
}
/////////////////////////////////   Cname host  Map   >>>>> ///////////////////////////////////////////////////////////////////

func (c *Cache) InsertCachedDataCnameTypeAMap(host, alias string) {
	c.Lock()
	elem, ok := c.cnameMapTypeA[host]
	if !ok {
		e := new(cnametypeA)
		e.toDel = false
		e.updateTime = time.Now().Local()
		e.alians = append(e.alians,alias)
		c.cnameMapTypeA[host] = e
	}else{
		elem.updateTime = time.Now().Local()
		elem.alians = append(elem.alians,alias)
	}
	c.Unlock()
}

func (c *Cache) DelCachedDataCnameTypeAMap(host, alias string) {
	c.Lock()
	defer c.Unlock()
	if e, ok := c.cnameMapTypeA[host]; ok {
		if len(e.alians)==0{
			e.toDel = true
			return
		}
		for idx,name := range e.alians{
			if name == alias{
				e.alians = append(e.alians[:idx], e.alians[idx+1:]...)
				break
			}
		}
		if len(e.alians)==0{
			e.toDel = true
			return
		}
	}

}

// when the host changed we will del the canme record in query cache
func (c *Cache) updateCachedDataCnameMap(r interface{}) {
	val,ok := r.(*dns.A)
	if ok{
		if e, ok := c.cnameMapTypeA[val.Hdr.Name]; ok {
			glog.V(2).Infof("val.Hdr.Name = %s\n",val.Hdr.Name)
			if len(e.alians)==0{
				return
			}
			for _,name := range e.alians{
				key := c.KeyTypeA(name, false, false)
				glog.V(2).Infof("key = %s name =%s\n",key,name)
				if _,ok2 := c.elemsMap[key];ok2{
					delete(c.elemsMap, key)
				}
			}
		}
	}

}

//  records not so much ,we do it in one lock ops

func (c *Cache) SyncCachedDataCnameMap(records map[string][]string, timenow time.Time) {
	if len(records)==0 {
		return
	}
	c.Lock()
	timenowSync := time.Now().Local()
	for k,v := range(c.cnameMapTypeA){
		// new update
		if v.updateTime.After(timenow){
			if v.toDel{
				delete(c.cnameMapTypeA, k)
			}
			continue
		}
		// no new
		val, ok := records[k]
		if ok{
			v.alians = val[:]
			v.updateTime = timenowSync
		}else{
			delete(c.cnameMapTypeA, k)
		}
	}
	for k,v := range(records) {
		if _, ok := c.cnameMapTypeA[k];!ok {
			e := new(cnametypeA)
			e.toDel = false
			e.updateTime = timenowSync
			e.alians = v[:]
			c.cnameMapTypeA[k] = e
		}
	}
	c.Unlock()
}

/////////////////////////////////   <<<<<<< cname host  Map   ////////////////////////////////////////////////////////////////////

func (c *Cache) UpdateRcacheSet(val interface{}) {
	glog.V(2).Infof(" UpdateRcacheSet =%v\n", val)
	// type A we update the dict
	c.Lock()
	defer c.Unlock()
	c.updateCachedDataCnameMap(val)
	_, find, _, matchKey := c.checkCacheExitst(val)
	if find {
		//type A update the  Ansers
		e := c.elemsMap[matchKey]
		// pre nodata
		if len(e.msg.Answer) == 0 {
			delete(c.elemsMap, matchKey)
			return
		}
		valA, b := val.(*dns.A)
		if b != true {
			return
		}
		e.msg.Answer = append(e.msg.Answer, valA)
		e.Lock()
		e.mAnswer = make(map[string]int)
		e.Unlock()
	}
}

func (c *Cache) UpdateRcacheUpdate(valAOld interface{}, valANew interface{}) {
	glog.V(2).Infof(" UpdateRcacheUpdate valAOld=%v valANew =%v\n", valAOld, valANew)
	c.Lock()
	defer c.Unlock()
	c.updateCachedDataCnameMap(valAOld)
	idx, find, valExist, matchKey := c.checkCacheExitst(valAOld)
	//glog.Infof(" UpdateRcacheSet find =%v matchKey =%v \n",find,matchKey)
	if find {
		// cname match we del the key and return
		if !valExist {
			delete(c.elemsMap, matchKey)
			return
		}
		e := c.elemsMap[matchKey]
		e.msg.Answer[idx] = valANew.(*dns.A)
		//del the old val from dict
		e.Lock()
		e.mAnswer = make(map[string]int)
		e.Unlock()
	}
}
func (c *Cache) UpdateRcacheDelete(valA interface{}) {
	glog.V(2).Infof(" UpdateRcacheDelete =%v\n", valA)
	c.Lock()
	defer c.Unlock()
	c.updateCachedDataCnameMap(valA)
	idx, find, valExist, matchKey := c.checkCacheExitst(valA)
	if find {
		// cname match we del the key and return
		if !valExist {
			delete(c.elemsMap, matchKey)
			return
		}
		//del form Ansers
		e := c.elemsMap[matchKey]
		e.msg.Answer = append(e.msg.Answer[:idx], e.msg.Answer[idx+1:]...)
		if len(e.msg.Answer) == 0 {
			delete(c.elemsMap, matchKey)
			return
		}
		//del l2 dict
		e.Lock()
		e.mAnswer = make(map[string]int)
		e.Unlock()
	}
}

// cacheSizeFit removes a 100 member a the cache.
// Must be called under a write lock.
func (c *Cache) cacheSizeFit() {
	clen := len(c.elemsMap)
	if clen <= c.capacity {
		return
	}
	i := 100
	for k, _ := range c.elemsMap {
		delete(c.elemsMap, k)
		i--
		if i == 0 {
			break
		}
	}
}

func (c *Cache) Add2MsgCache(s string, msg *dns.Msg, remoteIp string, timeNow time.Time, forwarding bool) {
	c.Lock()
	if _, ok := c.elemsMap[s]; !ok {
		elm := &cacheElem{expiration: time.Now().UTC().Add(c.ttl), msg: msg.Copy()}
		elm.mAnswer = make(map[string]int)
		elm.requestCount = 1
		elm.requestLastTime = timeNow
		elm.requestFirstTime = timeNow
		elm.forwarding = forwarding
		c.elemsMap[s] = elm

		if len(msg.Answer) > 1 {
			minttl := c.minTtl
			for _, r := range msg.Answer {
				if r.Header().Ttl < c.minTtl {
					minttl = r.Header().Ttl
				}
			}
			for _, r := range msg.Answer {
				r.Header().Ttl = minttl
			}
		}
		if len(msg.Answer) > 0 {
			c.cacheMsgPack(elm, msg, remoteIp)
		}
	}
	c.cacheSizeFit()
	c.Unlock()
}

// pack the msg return the pre svc ip or the random one
func (c *Cache) pickRadomOneFun(msg *dns.Msg, remoteIp string, forwarding bool) ([]dns.RR, []dns.RR, int) {
	var ipsRecords []dns.RR
	var ips []int
	var cnamesRecords []dns.RR
	// when each ip is not avaliable retrun the fist one
	ensureOneIp := -1
	for i, r := range msg.Answer {
		switch r.(type) {
		case *dns.A:
			// choose the first one
			if ensureOneIp < 0 {
				ensureOneIp = i
			}
			valA := r.(*dns.A)
			key := valA.A.String()
			if !forwarding {
				if _, e := c.AvaliableIps[key]; e {
					ips = append(ips, i)
					ipsRecords = append(ipsRecords, r)
				}
			} else {
				ipsRecords = append(ipsRecords, r)
				ips = append(ips, i)
			}

		case *dns.CNAME:
			cnamesRecords = append(cnamesRecords, r)
			// other type return org val
		default:
			var recordNop []dns.RR
			return recordNop, recordNop, -1

		}
	}
	// no typeA result
	if ensureOneIp < 0 {
		return cnamesRecords, ipsRecords, -1
	}
	// no hosts avaluable choose one
	if len(ips) == 0 {
		ipsRecords = append(ipsRecords, msg.Answer[ensureOneIp])
		ips = append(ips, ensureOneIp)
	}

	h := fnv.New32a()
	h.Write([]byte(remoteIp))
	idx := int(h.Sum32()) % len(ips)
	return cnamesRecords, ipsRecords, idx
}
func (c *Cache) findNextActiveIp(ipData []dns.RR, ipIdx int) int {

	for i := ipIdx + 1; i < len(ipData); i++ {
		if valA, ok := ipData[i].(*dns.A); ok {
			key := valA.A.String()
			if _, e := c.AvaliableIps[key]; e {
				return i
			}
		}
	}
	for i := 0; i < ipIdx; i++ {
		if valA, ok := ipData[i].(*dns.A); ok {
			key := valA.A.String()
			if _, e := c.AvaliableIps[key]; e {
				return i
			}
		}
	}
	return ipIdx
}

func (c *Cache) doMsgPack(cnameData []dns.RR, ipData []dns.RR, ipIdx int, forwarding bool) ([]dns.RR, int) {
	var newAnswer []dns.RR
	if len(cnameData) > 0 {
		newAnswer = cnameData[:]
	}
	if len(ipData) > 0 {
		if c.pickRandomOne {
			idxNew := ipIdx
			if !forwarding {
				idxNew = c.findNextActiveIp(ipData, ipIdx)
			} else {
				idxNew = (ipIdx + 1) % len(ipData)
			}
			newAnswer = append(newAnswer, ipData[idxNew])
			return newAnswer, idxNew

		} else if c.ipHold {
			if valA, ok := ipData[ipIdx].(*dns.A); ok {
				// forward  not check the ip
				if forwarding {
					newAnswer = append(newAnswer, ipData[ipIdx])
					return newAnswer, ipIdx
				}

				key := valA.A.String()
				if _, e := c.AvaliableIps[key]; e {
					newAnswer = append(newAnswer, ipData[ipIdx])
					return newAnswer, ipIdx
				} else {
					idxNew := c.findNextActiveIp(ipData, ipIdx)
					newAnswer = append(newAnswer, ipData[idxNew])
					return newAnswer, idxNew
				}
			}

		} else {
			glog.Infof("doMsgPack callded must with pickRadomOne or c.ipHold  is ture\n")
		}
	}
	return newAnswer, ipIdx
}

func (c *Cache) cacheMsgPack(e *cacheElem, msg *dns.Msg, remoteIp string) {

	if !c.pickRandomOne && !c.ipHold {
		return
	}
	e.Lock()
	defer e.Unlock()
	if idx, ok := e.mAnswer[remoteIp]; ok {
		newAnswer, idxNew := c.doMsgPack(e.cnames, e.ips, idx, e.forwarding)
		if len(newAnswer) > 0 {
			e.mAnswer[remoteIp] = idxNew
			msg.Answer = newAnswer
		}
		return
	}
	var newAns []dns.RR
	cnameR, ipR, idx := c.pickRadomOneFun(msg, remoteIp, e.forwarding)
	if len(cnameR) > 0 {
		e.cnames = cnameR[:]
		newAns = cnameR
	}
	if len(ipR) > 0 {
		e.ips = ipR[:]
		e.mAnswer[remoteIp] = idx
		newAns = append(newAns, e.ips[idx])
	}
	if len(newAns) > 0 {
		msg.Answer = newAns
	}
	return
}

// Search returns a dns.Msg, the expiration time and a boolean indicating if we found something
// in the cache.
func (c *Cache) doSearch(s string, remoteIp string, queryNow time.Time) (*dns.Msg, time.Time, bool, bool) {
	c.RLock()
	if e, ok := c.elemsMap[s]; ok {
		e.requestLastTime = queryNow
		e.requestCount++
		//e1 := e.msg.Copy()
		var msg *dns.Msg
		msgP := MsgCachePool.DeQueue()

		if msgP == nil{
			msg = new(dns.Msg)
		}else{
			glog.V(4).Infof("odld msg =%p \n",msgP)
			msg, ok= msgP.(*dns.Msg)
			if !ok{
				glog.Infof("ERR　val msg =%v\n",msgP)
			}
		}
		e1 := e.msg.CopyTo(msg)
		if len(e1.Answer) > 0 {
			c.cacheMsgPack(e, e1, remoteIp)
		}
		c.RUnlock()
		return e1, e.expiration, e.forwarding, true

	}
	c.RUnlock()
	return nil, time.Time{}, false, false
}

// Key creates a hash key from a question section.

func CacheKey(q dns.Question, tcp bool) string {
	h := sha1.New()
	i := append([]byte(q.Name), keyPack(q.Qtype)...)
	if tcp {
		i = append(i, byte(254))
	}
	return string(h.Sum(i))
}

func (c *Cache) SearchRecordInCache(question dns.Question, tcp bool, msgid uint16, remoteIp string, queryNow time.Time) *dns.Msg {
	key := CacheKey(question, tcp)
	record, exp, forward, hit := c.doSearch(key, remoteIp, queryNow)
	if hit {
		record.Id = msgid
		record.Compress = true
		record.Truncated = false
		if !forward {
			return record
		} else {
			if time.Since(exp) < 0 {
				return record
			} else {
				MsgCachePool.EnQueue(record)
				c.Remove(key)
			}
		}
	}
	return nil
}


