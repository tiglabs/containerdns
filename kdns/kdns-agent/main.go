package main

/*
const char* build_time(void)
{
    static const char* psz_build_time = "["__DATE__ "  " __TIME__ "]";
    return psz_build_time;

}
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	etcdv3 "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

type KdnsServerConf struct {
	KdnsCertfile  string `yaml:"dns-certfile"`
	KdnsKeyfile   string `yaml:"dns-keyfile"`
	KdnsCafile    string `yaml:"dns-cafile"`
	KdnsUrl       string `yaml:"kdns-url"`
	KdnsStatusUrl string `yaml:"kdns-status-url"`
}

type KdnsServerOps struct {
	KdnsUrl              string
	KdnsStatusUrl        string
	kdnsClient           *http.Client
	etcdRecordUpdateTime map[string]time.Time
	etcdCachesLock       sync.Mutex
}
type ConfigOps struct {
	LogDir   string `yaml:"log-dir"`
	LogLevel string `yaml:"log-level"`
	LogStdIo string `yaml:"log-to-stdio"`
	Addr     string `yaml:"addr"`

	EtcdServers  string `yaml:"etcd-servers"`
	EtcdCertfile string `yaml:"etcd-certfile"`
	PathPrefix   string `yaml:"path-prefix"`
	EtcdKeyfile  string `yaml:"etcd-keyfile"`
	EtcdCafile   string `yaml:"etcd-cafile"`
	EtcdTimeOut  int    `yaml:"etcd-timeout"`

	SyncPeriod  int              `yaml:"sync-period"`
	KdnsDomains string           `yaml:"dns-domains"`
	KdnsTimeOut int              `yaml:"kdns-timeout"`
	Servers     []KdnsServerConf `yaml:"kdns-servers"`
}

type KdnsRecord struct {
	DomainName  string `json:"domainName,omitempty"`
	Host        string `json:"host,omitempty"`
	ZoneName    string `json:"zoneName,omitempty"`
	DnsPort     int    `json:"port,omitempty"`
	DnsTtl      int    `json:"ttl,omitempty"`
	DnsPriority int    `json:"priority,omitempty"`
	DnsWeight   int    `json:"weight,omitempty"`
	Type        string `json:"type,omitempty"`
	MaxAnswer   int    `json:"maxAnswer,omitempty"`
}
type ServiceRecord struct {
	Dnstype      string `json:"type,omitempty"`
	RecordSource string `json:"source,omitempty"`
	DnsHost      string `json:"host,omitempty"`
	DnsTtl       uint32 `json:"ttl,omitempty"`

	DnsPort     int    `json:"port,omitempty"`
	DnsPriority int    `json:"priority,omitempty"`
	DnsWeight   int    `json:"weight,omitempty"`
	MaxAnswer   int    `json:"maxAnswer,omitempty"`
	DnsText     string `json:"text,omitempty"`
	DnsMail     bool   `json:"mail,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
	// Etcd key
	Key string `json:"-"`
}

var (
	gConfig       *ConfigOps
	configFile    = ""
	version       = false
	versionInfo   = "0.3"
	DnsPathPrefix = "kdns"
	clientv3      etcdv3.Client
	kdnsOps       []*KdnsServerOps
	dnsZones      []string
)

func init() {
	flag.StringVar(&configFile, "config-file", "/etc/kdns/kdns-agent.yaml", "read config from the file")
	flag.BoolVar(&version, "version", false, "Print version information and quit")
	flag.Parse()
	var e error
	if gConfig, e = getYamlConfigInfo(configFile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(gConfig.LogDir)
	flag.Lookup("v").Value.Set(gConfig.LogLevel)
	flag.Lookup("logtostderr").Value.Set(gConfig.LogStdIo)
}
func getYamlConfigInfo(configFile string) (*ConfigOps, error) {
	cfg := new(ConfigOps)
	data, err := ioutil.ReadFile(configFile)

	if err != nil {
		glog.Infof("error: %v", err)
	}
	err = yaml.Unmarshal([]byte(data), cfg)
	return cfg, err
}

func glogFlush(period time.Duration) {
	for range time.Tick(period) {
		glog.Flush()
	}
}

func newEtcdV3Client(machines []string) (*etcdv3.Client, error) {
	info := transport.TLSInfo{
		CertFile: gConfig.EtcdCertfile,
		KeyFile:  gConfig.EtcdKeyfile,
		CAFile:   gConfig.EtcdCafile,
	}
	cfg, err := info.ClientConfig()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     cfg,
	}
	if err != nil {
		return nil, err
	}
	etcdCfg := etcdv3.Config{
		Endpoints: machines,
		TLS:       tr.TLSClientConfig,
	}
	cli, err := etcdv3.New(etcdCfg)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func DnsPath(s string) string {
	l := dns.SplitDomainName(s)
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	pathOrg := path.Join(append([]string{"/" + DnsPathPrefix + "/"}, l...)...)
	//add
	return pathOrg + "/"
}

func getSvcDomainName(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[2:], ".") // ingoore the first
	return domainKey[:len(domainKey)-len(DnsPathPrefix)-1]
}

func getSvcCnameName(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[1:], ".")
	// ignore the head kdns.
	return domainKey[:len(domainKey)-len(DnsPathPrefix)-1]
}

func LoopNodes(kv []*mvccpb.KeyValue) (sx []ServiceRecord, err error) {
	for _, item := range kv {
		serv := new(ServiceRecord)
		if err := json.Unmarshal(item.Value, serv); err != nil {
			return nil, err
		}
		serv.Key = string(item.Key)
		if serv.DnsPriority == 0 {
			serv.DnsPriority = int(10)
		}

		sx = append(sx, *serv)
	}
	return sx, nil
}

func Get(name string) ([]ServiceRecord, int64, error) {

	path := DnsPath(name)
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(gConfig.EtcdTimeOut)*time.Second)
	defer cancel()
	r, err := clientv3.Get(ctx, path, etcdv3.WithPrefix())
	if err != nil {
		return nil, 0, err
	}
	msgs, err := LoopNodes(r.Kvs)
	return msgs, r.Header.Revision, nil

}

func kdnsHttpClientInit(dns KdnsServerConf) *http.Client {
	info := transport.TLSInfo{
		CertFile: dns.KdnsCertfile,
		KeyFile:  dns.KdnsKeyfile,
		CAFile:   dns.KdnsCafile,
	}
	cfg, err := info.ClientConfig()
	if err != nil {
		glog.Fatalf("err =%s\n", err.Error())
		return nil
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   time.Duration(gConfig.KdnsTimeOut) * time.Second,
			KeepAlive: time.Duration(gConfig.KdnsTimeOut) * time.Second,
		}).Dial,
		TLSHandshakeTimeout: time.Duration(gConfig.KdnsTimeOut) * time.Second,
		TLSClientConfig:     cfg,
	}
	if err != nil {
		glog.Fatalf("err =%s\n", err.Error())
		return nil
	}

	kdnsClient := http.Client{Transport: tr}
	return &kdnsClient
}

func findZoneNameFromDomain(domain string) string {
	for _, zone := range dnsZones {
		if strings.Compare(domain, zone) == 0 || strings.HasSuffix(domain, "." + zone) {
			return zone
		}
	}
	return ""
}

func syncKdnsDomainDel(ops *KdnsServerOps, record *KdnsRecord) error {

	glog.V(2).Infof("syncKdnsDomainDel: url = %s del  record = %v\n", ops.KdnsUrl, record)
	b, err := json.Marshal(&record)
	if err != nil {
		glog.Infof("json err:", err)
		return err
	}
	body := bytes.NewBuffer([]byte(b))
	req, err := http.NewRequest("DELETE", ops.KdnsUrl, body)

	if err != nil {
		glog.Info(err.Error())
		return err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := ops.kdnsClient.Do(req)
	if err != nil {
		glog.Info(err.Error())
		return err
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Info(err.Error())
		return err
	}
	ret := string(rbody)
	if !strings.Contains(ret, "OK") {
		glog.Infof("delete %v err\n", record)
	}
	return nil

}

func kdnsDomainOperation(ops *KdnsServerOps, zone string, record *ServiceRecord, operation string, srvHost bool) error {
	glog.V(2).Infof("kdnsDomainOperation: record = %v operation = %s\n", record, operation)
	if operation != "POST" && operation != "DELETE" {
		glog.Infof("Wrong operation:%s\n", operation)
		return nil
	}
	var s KdnsRecord
	if record.Dnstype != "A" && record.Dnstype != "PTR" && record.Dnstype != "CNAME" && record.Dnstype != "SRV" {
		glog.Infof("Wrong type :%s\n", record.Dnstype)
		return nil
	}
	if record.Dnstype == "CNAME" {
		s.DomainName = getSvcCnameName(record.Key)
	} else {
		s.DomainName = getSvcDomainName(record.Key)
	}
	// srv host recored 全部结果
	if srvHost {
		s.DomainName = getSvcCnameName(record.Key)
	}

	if zone == "" {
		zone = findZoneNameFromDomain(s.DomainName)
	}
	if zone == "" {
		glog.Infof("kdnsDomainOperation err can not find zoneInfo for domain (%s)\n", s.DomainName)
		return nil
	}
	s.Host = record.DnsHost
	s.ZoneName = zone
	s.Type = record.Dnstype
	s.DnsPriority = record.DnsPriority
	s.DnsPort = record.DnsPort
	s.DnsWeight = record.DnsWeight
	s.MaxAnswer = record.MaxAnswer
	s.DnsTtl = int(record.DnsTtl)

	b, err := json.Marshal(&s)
	if err != nil {
		glog.Infof("json err:", err)
		return err
	}
	body := bytes.NewBuffer([]byte(b))
	req, err := http.NewRequest(operation, ops.KdnsUrl, body)

	if err != nil {
		glog.Info(err.Error())
		return err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := ops.kdnsClient.Do(req)
	if err != nil {
		glog.Info(err.Error())
		return err
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Info(err.Error())
		return err
	}
	ret := string(rbody)
	if !strings.Contains(ret, "OK") {
		glog.Infof("post %v err\n", s)
	}
	return nil
}

func Fqdn(s string) string {
	l := len(s)
	if s[l-1] == '.' {
		return s
	}
	return s + "."
}

func GetEtcdCachedRecordsAfterStart(domain string, ops *KdnsServerOps) int64 {
	glog.Infof("get etcd revision start \n")
	records, revision, err := Get(domain)
	if err != nil {
		if strings.HasPrefix(err.Error(), "context deadline exceeded") {
			glog.Fatalf("err =%s \n", err.Error())
		}
		glog.Infof("err =%s \n", err.Error())
		return 0
	}
	glog.Infof("get etcd domain =%s  out \n", domain)
	// skip sync data
	if ops == nil {
		glog.Infof("skip sync data for start\n")
		return revision
	}

	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()

	for _, record := range records {
		switch record.Dnstype {
		case "SRV":
			name := getSvcDomainName(record.Key)
			ops.etcdRecordUpdateTime[name] = timeNow
			glog.V(2).Infof("SRV record.Host: %s\n", record.DnsHost)
			hostRecord, _, err := Get(record.DnsHost)
			if err == nil {
				if len(hostRecord) > 0 {
					kdnsDomainOperation(ops, domain, &hostRecord[0], "POST", true)
					ops.etcdRecordUpdateTime[record.DnsHost] = timeNow
				}

			} else {
				glog.Infof("err =%s \n", err.Error())
			}
		case "CNAME":
			name := getSvcCnameName(record.Key)
			ops.etcdRecordUpdateTime[name] = timeNow
		default:
			name := getSvcDomainName(record.Key)
			ops.etcdRecordUpdateTime[name] = timeNow
		}
		kdnsDomainOperation(ops, domain, &record, "POST", false)
		//time.Sleep(20*time.Millisecond)
	}
	ops.etcdCachesLock.Unlock()
	glog.Infof("len of domain(%s) =%d\n", domain, len(records))
	return revision
}

func syncGetEtcdCachedRecords() (map[string][]ServiceRecord, error) {
	recordCaches := make(map[string][]ServiceRecord)

	for _, domain := range dnsZones {
		records, _, err := Get(domain)
		if err != nil {
			glog.Infof("err =%s \n", err.Error())
			return recordCaches, err
		}
		for _, record := range records {
			switch record.Dnstype {
			case "SRV":
				name := getSvcDomainName(record.Key)
				recordCaches[name] = append(recordCaches[name], record)
				hostRecord, _, err := Get(record.DnsHost)
				if err == nil {
					if len(hostRecord) > 0 {
						// just one
						if len(recordCaches[record.DnsHost]) > 0 {
							recordCaches[record.DnsHost][0] = hostRecord[0]
						} else {
							recordCaches[record.DnsHost] = append(recordCaches[record.DnsHost], hostRecord[0])
						}
					}

				} else {
					glog.Infof("err =%s \n", err.Error())
				}
			case "CNAME":
				name := getSvcCnameName(record.Key)
				recordCaches[name] = append(recordCaches[name], record)
			default:
				name := getSvcDomainName(record.Key)
				// for pod name == svc name just one
				find := false
				for _, k := range recordCaches[name] {
					if k.Dnstype == record.Dnstype && k.DnsHost == record.DnsHost && k.DnsTtl == record.DnsTtl {
						find = true
						break
					}
				}
				if !find {
					recordCaches[name] = append(recordCaches[name], record)
				}
			}
		}
	}
	return recordCaches, nil
}
func ParseDomainRecords(kv *mvccpb.KeyValue) *ServiceRecord {
	record := new(ServiceRecord)
	if err := json.Unmarshal(kv.Value, record); err != nil {
		return nil
	}
	record.Key = string(kv.Key)
	if record.DnsPriority == 0 {
		record.DnsPriority = int(10)
	}
	return record
}

func UpdateDomian(e *etcdv3.Event, zone string) {
	glog.V(2).Infof("UpdateRcache: e = %+v", e)
	for _, ops := range kdnsOps {
		doUpdateDomian(e, zone, ops)
	}
}

func doUpdateDomian(e *etcdv3.Event, zone string, ops *KdnsServerOps) {

	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()
	defer ops.etcdCachesLock.Unlock()
	switch e.Type {
	case etcdv3.EventTypePut:
		if e.IsCreate() {
			valNew := ParseDomainRecords(e.Kv)
			if valNew != nil {
				name := ""
				if valNew.Dnstype == "CNAME" {
					name = getSvcCnameName(valNew.Key)
				} else {
					name = getSvcDomainName(valNew.Key)
				}
				ops.etcdRecordUpdateTime[name] = timeNow
				kdnsDomainOperation(ops, zone, valNew, "POST", false)
				if valNew.Dnstype == "SRV" {
					hostRecord, _, err := Get(valNew.DnsHost)
					if err == nil {
						if len(hostRecord) > 0 {
							kdnsDomainOperation(ops, zone, &hostRecord[0], "POST", true)
							ops.etcdRecordUpdateTime[valNew.DnsHost] = timeNow
						}

					} else {
						glog.Infof("err =%s \n", err.Error())
					}
				}
			}
		} else {
			glog.Infof("todo \n")
		}

	case etcdv3.EventTypeDelete:
		valDel := ParseDomainRecords(e.PrevKv)
		if valDel != nil {
			name := ""
			if valDel.Dnstype == "CNAME" {
				name = getSvcCnameName(valDel.Key)
			} else {
				name = getSvcDomainName(valDel.Key)
			}
			ops.etcdRecordUpdateTime[name] = timeNow
			kdnsDomainOperation(ops, zone, valDel, "DELETE", false)

			if valDel.Dnstype == "SRV" {
				hostRecord, _, err := Get(valDel.DnsHost)
				if err == nil {
					if len(hostRecord) > 0 {
						kdnsDomainOperation(ops, zone, &hostRecord[0], "DELETE", true)
						ops.etcdRecordUpdateTime[valDel.DnsHost] = timeNow
					}
				} else {
					glog.Infof("err =%s \n", err.Error())
				}
			}
		}
	default:
		glog.Infof("the action not monitored: Action =%d kv=%v", e.Type, e.Kv)

	}
}
func WatchForDnsDomain(zone string, watchidx int64, client etcdv3.Client) {

	var watcher etcdv3.WatchChan
	recordCatched := false

reWatch:
	if recordCatched {
		watchidx = watchidx + 1
		recordCatched = false
	}
	glog.Infof("WatchForDomain idx : %d ", watchidx)
	opts := []etcdv3.OpOption{}
	if watchidx > 0 {
		opts = append(opts, etcdv3.WithRev(watchidx))
	}
	opts = append(opts, etcdv3.WithPrefix())
	opts = append(opts, etcdv3.WithPrevKV())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	watcher = client.Watch(ctx, DnsPath(zone), opts...)
	var wres etcdv3.WatchResponse

	for wres = range watcher {
		if wres.Err() != nil {
			err := wres.Err()
			glog.Infof("err : %s ", err)
			watchidx = wres.Header.Revision
			goto reWatch
		}
		for _, e := range wres.Events {
			UpdateDomian(e, zone)
			recordCatched = true
		}

	}
	if err := wres.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err =%s\n", err)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	if err := ctx.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err =%s\n", err)
		watchidx = wres.Header.Revision
		goto reWatch
	}

	glog.Infof("WatchForDomain out : %d  watcher=%v zone =%s\n", watchidx, watcher, zone)
}

func getDnsServerStatus(ops *KdnsServerOps) string {

	req, err := http.NewRequest("GET", ops.KdnsStatusUrl, nil)
	if err != nil {
		glog.Info(err.Error())
		return ""
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := ops.kdnsClient.Do(req)
	if err != nil {
		glog.Info(err.Error())
		return ""
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Info(err.Error())
		return ""
	}
	return string(rbody)
}
func postDnsServerStatus(ops *KdnsServerOps) bool {
	req, err := http.NewRequest("POST", ops.KdnsStatusUrl, nil)
	if err != nil {
		glog.Info(err.Error())
		return false
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := ops.kdnsClient.Do(req)
	if err != nil {
		glog.Info(err.Error())
		return false
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Info(err.Error())
		return false
	}
	ret := string(rbody)
	if strings.Contains(ret, "OK") {
		return true
	}
	return false
}
func dnsStatusSync(ops *KdnsServerOps) {
	for range time.Tick(30 * time.Second) {
		status := getDnsServerStatus(ops)
		if status == "init" {
			for _, domain := range dnsZones {
				GetEtcdCachedRecordsAfterStart(domain, ops)
			}
			postDnsServerStatus(ops)
		}
		glog.Infof("get status :%s\n", status)
	}
}

func getDnsServerDomians(ops *KdnsServerOps) (map[string][]KdnsRecord, error) {
	req, err := http.NewRequest("GET", ops.KdnsUrl, nil)
	if err != nil {
		glog.Info(err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := ops.kdnsClient.Do(req)
	if err != nil {
		glog.Info(err.Error())
		return nil, err
	}
	rbody, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		glog.Info(err.Error())
		return nil, err
	}
	var records []KdnsRecord
	if err := json.Unmarshal(rbody, &records); err != nil {
		return nil, err
	}
	reMap := make(map[string][]KdnsRecord)
	for _, r := range records {
		glog.V(4).Infof("%+v\n", r)
		reMap[r.DomainName] = append(reMap[r.DomainName], r)
	}
	return reMap, nil
}

func syncRecordEqual(etcd []ServiceRecord, kdns []KdnsRecord) ([]int, []int) {
	/*	if len(etcd) != len(kdns){
		return false
	}*/
	var delKndsRecord []int
	var addKndsRecord []int
	for idx, e := range etcd {
		found := false
		for _, k := range kdns {
			if k.Type == e.Dnstype && k.Host == e.DnsHost && k.DnsTtl == int(e.DnsTtl) {
				if k.Type == "SRV" {
					if k.DnsPort == e.DnsPort && k.DnsPriority == e.DnsPriority && k.DnsWeight == e.DnsWeight {
						found = true
						break
					}
				} else {
					found = true
					break
				}
			}
		}
		if !found {
			addKndsRecord = append(addKndsRecord, idx)
		}
	}

	for idx, k := range kdns {
		found := false
		for _, e := range etcd {
			if k.Type == e.Dnstype && k.Host == e.DnsHost && k.DnsTtl == int(e.DnsTtl) {
				if k.Type == "SRV" {
					if k.DnsPort == e.DnsPort && k.DnsPriority == e.DnsPriority && k.DnsWeight == e.DnsWeight {
						found = true
						break
					}
				} else {
					found = true
					break
				}
			}
		}
		if !found {
			delKndsRecord = append(delKndsRecord, idx)
		}
	}
	return addKndsRecord, delKndsRecord
}
func doDnsDomainsSync(ops *KdnsServerOps, etcdValesOrg map[string][]ServiceRecord) {

	timeNow := time.Now().Local()
	kdnsVals, err := getDnsServerDomians(ops)
	if err != nil {
		glog.Infof("get err kdns:%s   we ingore the syc\n")
		return
	}
	etcdVales := make(map[string][]ServiceRecord)
	// copy
	for k, v := range etcdValesOrg {
		etcdVales[k] = v
	}
	ops.etcdCachesLock.Lock()
	defer ops.etcdCachesLock.Unlock()
	var record2add []int
	var record2del []int
	for key, kvals := range kdnsVals {
		lastUptime, ok := ops.etcdRecordUpdateTime[key]
		// changed
		if ok && lastUptime.After(timeNow) {
			continue
		}
		evals, exist := etcdVales[key]

		if exist {
			record2add, record2del = syncRecordEqual(evals, kvals)
			if len(record2add) == 0 && len(record2del) == 0 {
				delete(etcdVales, key)
				continue
			}
		} else {
			//del pre
			glog.Infof("ddd key = %s\n", key)
			for _, v := range kvals {
				syncKdnsDomainDel(ops, &v)
			}
			continue
		}
		glog.Infof(" key = %s len(record2add) = %d  len(record2del) = %d \n", key, len(record2add), len(record2del))
		//del pre
		for _, idx := range record2del {
			syncKdnsDomainDel(ops, &kvals[idx])
		}
		// etcd new value

		for _, idx := range record2add {
			kdnsDomainOperation(ops, "", &evals[idx], "POST", false)
		}
	}

	for key, evals := range etcdVales {
		_, exist := kdnsVals[key]
		if !exist {
			lastUptime, ok := ops.etcdRecordUpdateTime[key]
			// changed
			if ok && lastUptime.After(timeNow) {
				continue
			}
			for _, v := range evals {
				kdnsDomainOperation(ops, "", &v, "POST", false)
			}
		}
	}

	for key, vTime := range ops.etcdRecordUpdateTime {
		_, exist := etcdVales[key]
		// del old values
		if !exist && vTime.Before(timeNow) {
			delete(ops.etcdRecordUpdateTime, key)
		}
	}

}

func dnsDomainsSync() {
	for range time.Tick(time.Duration(gConfig.SyncPeriod) * time.Second) {
		etcdVales, err := syncGetEtcdCachedRecords()
		if err != nil {
			glog.Infof("get data from etcd err continue\n")
			continue
		}
		for _, ops := range kdnsOps {
			doDnsDomainsSync(ops, etcdVales)
		}
	}
}

func main() {
	flag.Parse()
	if version {
		s := versionInfo + ": " + C.GoString(C.build_time())
		fmt.Printf("%s\n", s)
		return
	}
	defer glog.Flush()
	glog.Infof("cfg = %+v\n", gConfig)
	go glogFlush(5 * time.Second)

	machines := strings.Split(gConfig.EtcdServers, ",")

	clientv3P, err := newEtcdV3Client(machines)
	if err != nil {
		glog.Fatalf("kdns:newEtcdClient: %s", err)
	}
	clientv3 = *clientv3P
	for _, v := range gConfig.Servers {
		ops := new(KdnsServerOps)
		ops.kdnsClient = kdnsHttpClientInit(v)
		if ops.kdnsClient == nil {
			glog.Fatalf(" can not get kdnsClient \n")
		}
		ops.KdnsStatusUrl = v.KdnsStatusUrl
		ops.KdnsUrl = v.KdnsUrl
		ops.etcdRecordUpdateTime = make(map[string]time.Time)
		kdnsOps = append(kdnsOps, ops)
	}
	if gConfig.PathPrefix != "" {
		DnsPathPrefix = gConfig.PathPrefix
	}

	if gConfig.KdnsDomains != "" {
		for _, domain := range strings.Split(gConfig.KdnsDomains, "%") {
			domain = Fqdn(strings.ToLower(domain))
			dnsZones = append(dnsZones, domain)
		}
	} else {
		glog.Fatalf("kdns: config domain is nil \n")
	}
	glog.Infof("dnsDomains = %v\n", dnsZones)
	for _, domain := range dnsZones {
		domainWatchIdx := int64(0)
		for _, ops := range kdnsOps {
			// read etcd many times todo
			idx := GetEtcdCachedRecordsAfterStart(domain, ops)
			if idx < domainWatchIdx {
				domainWatchIdx = idx
			}
		}
		// watch domains
		go WatchForDnsDomain(domain, domainWatchIdx+1, clientv3)
	}
	for _, ops := range kdnsOps {
		go dnsStatusSync(ops)
	}

	go dnsDomainsSync()

	_, err = net.Dial("tcp", gConfig.Addr)
	if err == nil {
		glog.Fatalf("the addr is used:%s\n", gConfig.Addr)
	}
	go http.ListenAndServe(gConfig.Addr, nil)
	select {}
}
