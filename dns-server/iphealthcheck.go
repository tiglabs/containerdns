package dnsServer

import (
	"encoding/json"
	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"strings"
	"time"

)

type apiSkydnsIpMonitor struct {
	Status string   `json:"status,omitempty"`
	Ports  []string `json:"ports,omitempty"`
	Domains  []string `json:"domains,omitempty"`
}

func (s *server) GetSkydnsHostStatus() int64 {
	// get hosts form /skydns/monitor/status/

	monitorIps := make(map[string]bool)
	glog.Infof("SyncSkydnsHostStatus start get \n")
	records, err1 := s.backend.GetRaw(s.ipMonitorPath)
	var record apiSkydnsIpMonitor
	glog.Infof("SyncSkydnsHostStatus start out \n")
	if err1 != nil {
		if strings.HasPrefix(err1.Error(),"context deadline exceeded"){
			glog.Fatalf("err =%s \n", err1.Error())
		}
		glog.Infof("Err: %s\n", err1.Error())
		return 0
	}

	for _, item := range records.Kvs {
		if err := json.Unmarshal(item.Value, &record); err != nil {
			glog.Infof("Err: %s\n", err.Error())
			return 0
		}
		if record.Status == "UP" {
			key := string(item.Key)
			ip := key[len(s.ipMonitorPath):]
			monitorIps[ip] = true
		}
	}
	glog.Infof("len of ip monitirs =%d\n", len(monitorIps))
	s.rcache.Lock()
	s.rcache.AvaliableIps = monitorIps
	s.rcache.Unlock()

	return records.Header.Revision
}

func (s *server) SyncSkydnsHostStatus()  {
	// get hosts form /skydns/monitor/status/

	sycNow := time.Now().Local()
	monitorIps := make(map[string]bool)
	records, err1 := s.backend.GetRaw(s.ipMonitorPath)
	var record apiSkydnsIpMonitor
	if err1 != nil {
		glog.Infof("Err: %s\n", err1.Error())
		return
	}
	for _, item := range records.Kvs {
		if err := json.Unmarshal(item.Value, &record); err != nil {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
		if record.Status == "UP" {
			key := string(item.Key)
			ip := key[len(s.ipMonitorPath):]
			monitorIps[ip] = true
		}
	}
	glog.Infof("SyncSkydnsHostStatus  len : %d \n",len(monitorIps))
	s.rcache.Lock()
	// no change we update  the ips
	if s.rcache.AvaliableIpsUpdateTime.Before(sycNow){
		glog.Infof("SyncSkydnsHostStatus : exchanged \n")
		s.rcache.AvaliableIps = monitorIps
	}
	s.rcache.Unlock()

}
func (s *server) doUpdateHostStatus(kv, kvPre *mvccpb.KeyValue) {
	//chck val
	var valNew apiSkydnsIpMonitor
	var valPre apiSkydnsIpMonitor
	if kv != nil {
		if err := json.Unmarshal(kv.Value, &valNew); err != nil {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	if kvPre != nil {
		if err := json.Unmarshal(kvPre.Value, &valPre); err != nil {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	if valNew.Status != valPre.Status {
		key := string(kv.Key)
		key = key[len(s.ipMonitorPath):]

		if valNew.Status == "UP" {
			glog.V(2).Infof("UP key :%s\n", key)
			s.rcache.Lock()
			s.rcache.AvaliableIps[key] = true
			s.rcache.AvaliableIpsUpdateTime = time.Now().Local()
			s.rcache.Unlock()
		} else if valNew.Status == "DOWN" {
			glog.V(2).Infof("Down key :%s\n", key)
			s.rcache.Lock()
			if _, ok := s.rcache.AvaliableIps[key]; ok {
				delete(s.rcache.AvaliableIps, key)
				s.rcache.AvaliableIpsUpdateTime = time.Now().Local()
			}
			s.rcache.Unlock()

		}
	}
}

func (s *server)  WatchForHosts(watchidx int64,client clientv3.Client){

	var watcher clientv3.WatchChan
	var wres clientv3.WatchResponse
	recordCatched := false
reWatch:
        if recordCatched{
		watchidx = watchidx+1
		recordCatched = false
	}
	glog.Infof("WatchForHosts idx : %d ", watchidx)
	opts := []clientv3.OpOption{}
	if watchidx > 0 {
		opts = append(opts, clientv3.WithRev(watchidx))
	}
	opts = append(opts, clientv3.WithPrefix())
	opts = append(opts, clientv3.WithPrevKV())
	ctx, cancel := context.WithTimeout(context.Background(), 2*s.syncPeriod)
	defer cancel()

	watcher = client.Watch(ctx, s.ipMonitorPath, opts...)

	for wres = range watcher {
		if wres.Err() != nil {
			err := wres.Err()
			glog.Infof("###### watch chan error: %v ", err)
			watchidx = wres.Header.Revision
			goto reWatch
		}
		for _, e := range wres.Events {
			s.UpdateHostStatus(e)
			recordCatched = true
		}
	}

	if err := wres.Err(); err != nil {
		glog.Infof("WatchForHosts err =%s\n",err)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	if err := ctx.Err(); err != nil {
		glog.Infof("WatchForHosts err =%s\n",err)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	glog.Infof("WatchForHosts out : %d  watcher=%v", watchidx,watcher)
}

func (s *server) UpdateHostStatus(e *clientv3.Event) {
	glog.V(2).Infof("UpdateHostStatus: e = %v", e)
	switch e.Type {
	case clientv3.EventTypePut:
		s.doUpdateHostStatus(e.Kv, e.PrevKv)

	case clientv3.EventTypeDelete:
		if e.Kv != nil {
			key := string(e.Kv.Key)
			key = key[len(s.ipMonitorPath):]
			glog.V(2).Infof("delete key :%s\n", key)
			s.rcache.Lock()
			if _, ok := s.rcache.AvaliableIps[key]; ok {
				delete(s.rcache.AvaliableIps, key)
				s.rcache.AvaliableIpsUpdateTime = time.Now().Local()
			}
			s.rcache.Unlock()
		}
	default:
		glog.Infof("the action not monitored: Action =%d kv=%v", e.Type, e.Kv)

	}
}

func (ip *server) HostStatusSync() {
	// delay not the same time to query etcd
	syncPeriod := ip.syncPeriod + 1*time.Minute
	for range time.Tick(syncPeriod) {
		ip.SyncSkydnsHostStatus()
	}
}
