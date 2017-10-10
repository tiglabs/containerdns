package dnsServer

import (
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

func (s *server) getRecordCnameMap(records []ServiceRecord) {
	for _, record := range records {
		if record.Dnstype == "CNAME"{
			s.doCreateRecordInCacheCname(&record)
		}
	}
}
func (s *server) GetDomainSize() int {
	EtcdCachesLock.Lock()
	defer EtcdCachesLock.Unlock()
	return len(EtcdRecordCaches)
}

func (s *server) GetEtcdCachedRecordsAfterStart(domain string) int64 {
	// get records form /skydns/local/skydns/
	glog.Infof("get etcd revision start \n")
	records, revision, err := s.backend.Get(domain)
	if err != nil {
		if strings.HasPrefix(err.Error(),"context deadline exceeded"){
			glog.Fatalf("err =%s \n", err.Error())
		}
		glog.Infof("err =%s \n", err.Error())
		return 0
	}
	glog.Infof("get etcd domain =%s  out \n",domain)
	preLen := len(EtcdRecordCaches)
	EtcdCachesLock.Lock()
	timeNow := time.Now().Local()
	for _, record := range records {
		switch record.Dnstype {
		case "SRV":
			name := s.getSvcDomainName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
			EtcdRecordUpdateTime[name] = timeNow
			glog.V(2).Infof("SRV record.Host: %s\n", record.DnsHost)
			hostRecord, _, err := s.backend.Get(record.DnsHost)
			if err == nil {
				if  len(hostRecord) >0{
					if len(EtcdRecordCaches[record.DnsHost]) >0 {
						EtcdRecordCaches[record.DnsHost][0] =  hostRecord[0]
					}else{
						EtcdRecordCaches[record.DnsHost] = append(EtcdRecordCaches[record.DnsHost], hostRecord[0])
					}
					EtcdRecordUpdateTime[record.DnsHost] = timeNow
				}

			} else {
				glog.Infof("err =%s \n", err.Error())
			}
		case "CNAME":
			name := s.getSvcCnameName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
			EtcdRecordUpdateTime[name] = timeNow
			s.doCreateRecordInCacheCname(&record)
		default:
			name := s.getSvcDomainName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
			EtcdRecordUpdateTime[name] = timeNow
		}
	}
	glog.Infof("len of domain(%s) =%d\n", domain,len(EtcdRecordCaches)-preLen)
	EtcdCachesLock.Unlock()
	return revision
}
func (s *server) SyncEtcdCachedRecords() {
	for range time.Tick(s.syncPeriod) {
		timeNow := time.Now().Local()
		lastUpdateTimeMap := s.GetEtcdRecordsLastUpdateTimeMap()

		glog.Infof(" 1  SyncEtcdCachedRecords start \n")
		recordCaches , recordCnameMapTypeA :=s.syncGetEtcdCachedRecords()
		// update
		glog.Infof(" 2  SyncCachedDataCnameMap start  domain =%d\n",len(recordCaches))
		s.rcache.SyncCachedDataCnameMap(recordCnameMapTypeA, timeNow)
		glog.Infof(" 3  syncCheckCachedRecords start  \n")
		//update cache
		s.syncCheckCachedRecords(recordCaches,lastUpdateTimeMap)
		glog.Infof(" 4 SyncEtcdCachedRecords over\n")
	}
}

func (s *server) syncCmpMsgSame (vals1[]ServiceRecord, vals2 []ServiceRecord)bool{
	if len(vals1) != len(vals2){
		return false
	}
	for _,val1 := range(vals1){
		i :=0
		for _,val2 := range(vals2){
			if val1.Key == val2.Key{
				if val1.DnsHost == val2.DnsHost{
					break
				}
			}
			i++
		}
		if i >=len(vals2){
			return false
		}
	}
        return true
}
func (s *server) syncCheckCachedRecords (recordCaches map[string][]ServiceRecord,lastUpdateTimeMap map[string]time.Time) {
	//syc real cache
	mAnswers := make(map[string][]dns.RR)
	for key,_ := range recordCaches{
		records, err := s.AddressRecordsCheck(key,recordCaches, false)
		if err != nil {
			continue
		}
		mkey := s.rcache.KeyTypeA(key,false,false)
		mAnswers[mkey] = append(mAnswers[key],records...)
	}
	// syc L1 cache
	cacheL1Need2Update := make(map[string]bool)
	cacheL1Need2Delete := make(map[string]bool)
	lastUpdateTimeMapNeed2Free := make(map[string]bool)

	EtcdCachesLock.RLock()
	for k,v := range(lastUpdateTimeMap){
		updateNew := s.GetEtcdRecordLastUpdateTime(k)
		// no change after get
		if updateNew.Equal(v){
			val1 , ok1:= EtcdRecordCaches[k]
			val2 , ok2 := recordCaches[k]

			if ok1 && ok2{
				if s.syncCmpMsgSame(val1,val2){
					continue
				}else{
					cacheL1Need2Update[k] = true
				}

			} else if ok1 && !ok2{
				cacheL1Need2Delete[k] = true
			}else if !ok1 && ok2{
				cacheL1Need2Update[k] = true

			}else{
				// no data record time one hour later will del
				exp := updateNew.Add( 1 * time.Hour)
				if time.Since(exp) > 0 {
					lastUpdateTimeMapNeed2Free[k] = true
				}
			}
		}
	}
	// add the new one
	for k,_ := range(recordCaches) {
		if _,ok := lastUpdateTimeMap[k]; !ok{
			cacheL1Need2Update[k] = true
		}
	}
	EtcdCachesLock.RUnlock()

	// do update

	timeNow := time.Now().Local()
	EtcdCachesLock.Lock()
	i :=0
        for key,_ := range(cacheL1Need2Update){

		updateNew := s.GetEtcdRecordLastUpdateTime(key)
		val, ok := lastUpdateTimeMap[key]
		// no new ,no old
		if !ok && updateNew.Equal(time.Time{}){
			EtcdRecordCaches[key] = recordCaches[key]
			s.rcache.syncUpdateCachedDataCnameMap(key)
			EtcdRecordUpdateTime[key] = timeNow
			i++

		}else{
			// no change
			if updateNew.Equal(val){
				EtcdRecordCaches[key] = recordCaches[key]
				s.rcache.syncUpdateCachedDataCnameMap(key)
				EtcdRecordUpdateTime[key] = timeNow
				i++
			}
		}
	}
	if i>0{
		glog.Infof("syncCheckCachedRecords: %d records updated \n",i)
		i =0
	}

	for key,_ := range(cacheL1Need2Delete){
		updateNew := s.GetEtcdRecordLastUpdateTime(key)
		if val,ok := lastUpdateTimeMap[key]; ok{
			if updateNew.Equal(val){
				delete (EtcdRecordCaches,key)
				s.rcache.syncUpdateCachedDataCnameMap(key)
				EtcdRecordUpdateTime[key] = timeNow
				i++
			}
		}
	}
	if i>0{
		glog.Infof("syncCheckCachedRecords: %d records del \n",i)
		i =0
	}

	for key,_ := range(lastUpdateTimeMapNeed2Free){
		delete (EtcdRecordUpdateTime,key)
	}
	EtcdCachesLock.Unlock()

	s.rcache.SyncCheckCachedRecords(mAnswers)
}
func (s *server) syncGetEtcdCachedRecords()(map[string][]ServiceRecord, map[string][]string){
	// get records form /skydns/local/skydns/
	recordCaches := make(map[string][]ServiceRecord)
	recordCnameMapTypeA := make(map[string][]string)
	for _,domain := range(s.dnsDomains){
		records, _, err := s.backend.Get(domain)
		if err != nil {
			glog.Infof("err =%s \n", err.Error())
			continue
		}
		for _, record := range records {
			switch record.Dnstype {
			case "SRV":
				name := s.getSvcDomainName(record.Key)
				recordCaches[name] = append(recordCaches[name], record)
				hostRecord, _, err := s.backend.Get(record.DnsHost)
				if err == nil {
					if  len(hostRecord) >0{
						// just one
						if len(recordCaches[record.DnsHost]) >0 {
							recordCaches[record.DnsHost][0] = hostRecord[0]
						}else{
							recordCaches[record.DnsHost]= append(recordCaches[record.DnsHost],hostRecord[0])
						}
					}

				} else {
					glog.Infof("err =%s \n", err.Error())
				}
			case "CNAME":
				name := s.getSvcCnameName(record.Key)
				recordCaches[name] = append(recordCaches[name], record)
				if ip := net.ParseIP(record.DnsHost); ip == nil{
					key := dns.Fqdn(record.DnsHost)
					glog.V(4).Infof("ecord.Host = %s key =%s\n",record.DnsHost, s.getSvcCnameName(record.Key))
					recordCnameMapTypeA[key] = append(recordCnameMapTypeA[key], s.getSvcCnameName(record.Key))
				}

			default:
				name := s.getSvcDomainName(record.Key)
				recordCaches[name] = append(recordCaches[name], record)
			}
		}
	}

	return  recordCaches , recordCnameMapTypeA
}


func (s *server) SetEtcdCachedRecord(kv *mvccpb.KeyValue) {
	record, err := s.ParseRecords(kv)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	glog.V(2).Infof("SetEtcdCachedRecord  %v\n", record)
	timeNow := time.Now().Local()
	EtcdCachesLock.Lock()
	switch record.Dnstype {
	case "SRV":
		name := s.getSvcDomainName(record.Key)
		EtcdRecordCaches[name] = append(EtcdRecordCaches[name], *record)
		glog.Infof("SRV record.Host: %s\n", record.DnsHost)
		EtcdRecordUpdateTime[name] = timeNow
		hostRecord, _, err := s.backend.Get(record.DnsHost)
		if err == nil {
			if  len(hostRecord) >0{
				if len(EtcdRecordCaches[record.DnsHost]) >0 {
					EtcdRecordCaches[record.DnsHost][0] =  hostRecord[0]
				}else{
					EtcdRecordCaches[record.DnsHost] = append(EtcdRecordCaches[record.DnsHost], hostRecord[0])
				}
				glog.V(2).Infof("SetEtcdCachedRecord    %v\n", EtcdRecordCaches[record.DnsHost])
				EtcdRecordUpdateTime[record.DnsHost] = timeNow
			}

		} else {
			glog.Infof("err =%s \n", err.Error())
		}
	case "CNAME":
		name := s.getSvcCnameName(record.Key)
		EtcdRecordCaches[name] = append(EtcdRecordCaches[name], *record)
		glog.V(2).Infof("SetEtcdCachedRecord    %v\n", EtcdRecordCaches[name])
		EtcdRecordUpdateTime[name] = timeNow
	default:
		name := s.getSvcDomainName(record.Key)
		EtcdRecordCaches[name] = append(EtcdRecordCaches[name], *record)
		EtcdRecordUpdateTime[name] = timeNow
		glog.V(2).Infof("SetEtcdCachedRecord    %v\n", EtcdRecordCaches[name])
	}

	EtcdCachesLock.Unlock()
}
func (s *server) DeleteEtcdCachedRecord(kv *mvccpb.KeyValue) {
	record, err := s.ParseRecords(kv)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	name := ""
	if record.Dnstype == "CNAME" {
		name = s.getSvcCnameName(record.Key)
	} else {
		name = s.getSvcDomainName(record.Key)
	}
	timeNow := time.Now().Local()

	EtcdCachesLock.Lock()
	defer EtcdCachesLock.Unlock()
	if vals, ok := EtcdRecordCaches[name]; ok {
		glog.V(2).Infof("DeleteEtcdCachedRecord  1111  %v\n", EtcdRecordCaches[name])
		for idx, val := range vals {
			if val == *record {
				EtcdRecordCaches[name] = append(EtcdRecordCaches[name][:idx], EtcdRecordCaches[name][idx+1:]...)
				EtcdRecordUpdateTime[name] = timeNow
				if len(EtcdRecordCaches[name]) == 0 {
					delete(EtcdRecordCaches, name)
				}
				return
			}
		}
	}
}

// the fun must be called with lock
func (s *server) GetEtcdRecordLastUpdateTime(name string)time.Time {
	if ti, e := EtcdRecordUpdateTime[name]; e {
		return  ti
	} else {
		return time.Time{}
	}
}
// the fun must be called with lock
func (s *server) GetEtcdRecordsLastUpdateTimeMap()(map[string]time.Time){
	updateTime := make(map[string]time.Time)
	EtcdCachesLock.RLock()
	for k, v := range EtcdRecordUpdateTime {
            updateTime[k] = v
        }
	EtcdCachesLock.RUnlock()
	return updateTime
}

func (s *server) UpdateEtcdCachedRecord(kvOld, kvNew *mvccpb.KeyValue) {
	rOld, err := s.ParseRecords(kvOld)
	if err != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	rNew, err1 := s.ParseRecords(kvNew)
	if err1 != nil {
		glog.Infof("ParseRecords err %s \n", err.Error())
		return
	}
	name := ""
	if rOld.Dnstype == "CNAME" {
		name = s.getSvcCnameName(rOld.Key)
	} else {
		name = s.getSvcDomainName(rOld.Key)
	}
	timeNow := time.Now().Local()
	EtcdCachesLock.Lock()
	defer EtcdCachesLock.Unlock()
	if vals, ok := EtcdRecordCaches[name]; ok {
		for idx, val := range vals {
			if val == *rOld {
				EtcdRecordUpdateTime[name] = timeNow
				EtcdRecordCaches[name][idx] = *rNew
				return
			}
		}
	}
}

func (s *server) ShowEtcdCacheDnsDomain(domain string) ([]ServiceRecord,time.Time) {
	EtcdCachesLock.RLock()
	defer EtcdCachesLock.RUnlock()
	if vals, ok := EtcdRecordCaches[domain]; ok {
		msgs := make([]ServiceRecord, len(vals))
		copy(msgs, vals)
		if ti, e := EtcdRecordUpdateTime[domain]; e{
			return msgs, ti
		}else{
			return msgs,time.Time{}
		}

	} else {
		return []ServiceRecord{},time.Time{}
	}
}
func (s *server) DeleteEtcdCacheDnsDomain(domain string) bool {
	EtcdCachesLock.Lock()
	defer EtcdCachesLock.Unlock()
	if _, ok := EtcdRecordCaches[domain]; ok {
		delete(EtcdRecordCaches, domain)
		EtcdRecordUpdateTime[domain] = time.Now().Local()
		return true
	} else {
		return false
	}
}

// get the domain from etcd

func (s *server) UpdateEtcdCacheDnsDomain(domain string) bool {
	records, _, err := s.backend.Get(domain)
	if err != nil {
		glog.Infof("err =%s \n", err.Error())
		return false
	}
	EtcdCachesLock.Lock()
	defer EtcdCachesLock.Unlock()
	if _, ok := EtcdRecordCaches[domain]; ok {
		delete(EtcdRecordCaches, domain)
	}

	glog.Infof("UpdateEtcdCacheDomain :%s \n", domain)
	for _, record := range records {
		switch record.Dnstype {
		case "SRV":
			name := s.getSvcDomainName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
			glog.V(2).Infof("SRV record.Host: %s\n", record.DnsHost)
			hostRecord, _, err := s.backend.Get(record.DnsHost)
			if err == nil {
				if len(hostRecord) > 0 {
					if len(EtcdRecordCaches[record.DnsHost]) >0 {
						EtcdRecordCaches[record.DnsHost][0] =  hostRecord[0]
					}else{
						EtcdRecordCaches[record.DnsHost] = append(EtcdRecordCaches[record.DnsHost], hostRecord[0])
					}
				}

			} else {
				glog.Infof("err =%s \n", err.Error())
			}
		case "CNAME":
			name := s.getSvcCnameName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
		default:
			name := s.getSvcDomainName(record.Key)
			EtcdRecordCaches[name] = append(EtcdRecordCaches[name], record)
		}
	}
	return true
}