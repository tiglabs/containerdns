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

const (
	kdnsDomainUrl    = "/kdns/domain"
	kdnsDomainAllUrl = "/kdns/alldomains"
	kdnsViewUrl      = "/kdns/view"
	kdnsViewAllUrl   = "/kdns/allview"
	kdnsStatusUrl    = "/kdns/status"
)

type KdnsServerConf struct {
	KdnsCertfile string `yaml:"dns-certfile"`
	KdnsKeyfile  string `yaml:"dns-keyfile"`
	KdnsCafile   string `yaml:"dns-cafile"`
	KdnsUrl      string `yaml:"kdns-url"`
}

type KdnsServerOps struct {
	KdnsUrl              string
	kdnsClient           *http.Client
	etcdRecordUpdateTime map[string]time.Time
	etcdViewUpdateTime   map[string]time.Time
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
	View        string `json:"viewName,omitempty"`
	LBMode      int    `json:"lbMode,omitempty"`
	LBWeight    int    `json:"lbWeight,omitempty"`
}

type ServiceRecord struct {
	Dnstype      string `json:"type,omitempty"`
	RecordSource string `json:"source,omitempty"`
	DnsHost      string `json:"host,omitempty"`
	DnsTtl       int    `json:"ttl,omitempty"`

	DnsPort     int    `json:"port,omitempty"`
	DnsPriority int    `json:"priority,omitempty"`
	DnsWeight   int    `json:"weight,omitempty"`
	MaxAnswer   int    `json:"maxAnswer,omitempty"`
	View        string `json:"viewName,omitempty"`
	LBMode      int    `json:"lbMode,omitempty"`
	LBWeight    int    `json:"lbWeight,omitempty"`
	DnsText     string `json:"text,omitempty"`
	DnsMail     bool   `json:"mail,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
	// Etcd key
	Key string `json:"-"`
}

type KdnsView struct {
	Cidr     string `json:"cidrs,omitempty"`
	ViewName string `json:"viewName,omitempty"`
}

type ServiceView struct {
	IpCIDRs  []string `json:"cidrs,omitempty"`
	ViewName string   `json:"viewName,omitempty"`
	Source   string   `json:"source,omitempty"`
}

var (
	gConfig       *ConfigOps
	configFile    = ""
	version       = false
	versionInfo   = "0.4"
	DnsPathPrefix = "kdns"
	DnsPathViews  = "dnsviews"
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

func GetViews() (map[string]ServiceView, int64, error) {
	viewCaches := make(map[string]ServiceView)
	path := DnsPath(DnsPathViews)
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(gConfig.EtcdTimeOut)*time.Second)
	defer cancel()
	r, err := clientv3.Get(ctx, path, etcdv3.WithPrefix())
	if err != nil {
		return viewCaches, 0, err
	}
	for _, item := range r.Kvs {
		serv := new(ServiceView)
		if err := json.Unmarshal(item.Value, serv); err != nil {
			glog.Errorf("err: %s, view wrong fmt: %s\n", err.Error(), item.String())
			continue
		}
		viewCaches[serv.ViewName] = *serv
	}
	return viewCaches, r.Header.Revision, nil
}

func LoopNodes(kv []*mvccpb.KeyValue) (sx []ServiceRecord, err error) {
	for _, item := range kv {
		serv := new(ServiceRecord)
		if err := json.Unmarshal(item.Value, serv); err != nil {
			glog.Errorf("err: %s, record wrong fmt: %s\n", err.Error(), item.String())
			continue
		}
		serv.Key = string(item.Key)
		if serv.DnsPriority == 0 {
			serv.DnsPriority = int(10)
		}
		if serv.View == "" {
			serv.View = "no_info"
		}

		sx = append(sx, *serv)
	}
	return sx, nil
}

func GetRecords(name string) ([]ServiceRecord, int64, error) {
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

func doKdnsViewOperation(ops *KdnsServerOps, viewName string, cidr string, operation string) error {
	glog.V(2).Infof("doKdnsViewOperation, operation = %s: viewName = %s, cidr = %s\n", operation, viewName, cidr)
	if operation != "POST" && operation != "DELETE" {
		glog.Infof("Wrong operation:%s\n", operation)
		return nil
	}

	var s KdnsView
	s.Cidr = cidr
	s.ViewName = viewName
	b, err := json.Marshal(&s)
	if err != nil {
		glog.Infof("json err:", err)
		return err
	}
	body := bytes.NewBuffer([]byte(b))
	req, err := http.NewRequest(operation, ops.KdnsUrl+kdnsViewUrl, body)
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
		glog.Infof("%s view: %s -- %s err\n", operation, viewName, cidr)
	}
	return nil
}

func kdnsViewOperation(ops *KdnsServerOps, view *ServiceView, operation string) error {
	glog.V(2).Infof("kdnsViewOperation: view = %v operation = %s\n", view, operation)
	for _, cidr := range view.IpCIDRs {
		err := doKdnsViewOperation(ops, view.ViewName, cidr, operation)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetEtcdCachedViewsAfterStart(ops *KdnsServerOps) int64 {
	glog.Infof("get etcd views start\n")
	views, revision, err := GetViews()
	if err != nil {
		if strings.HasPrefix(err.Error(), "context deadline exceeded") {
			glog.Fatalf("get views err = %s\n", err.Error())
		}
		glog.Infof("get views err = %s\n", err.Error())
		return 0
	}
	glog.Infof("get etcd views out\n")
	// skip sync data
	if ops == nil {
		glog.Infof("skip sync data for start\n")
		return revision
	}

	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()
	for _, view := range views {
		ops.etcdViewUpdateTime[view.ViewName] = timeNow
		kdnsViewOperation(ops, &view, "POST")
		//time.Sleep(20*time.Millisecond)
	}
	ops.etcdCachesLock.Unlock()
	return revision
}

func ParseView(kv *mvccpb.KeyValue) *ServiceView {
	view := new(ServiceView)
	if err := json.Unmarshal(kv.Value, view); err != nil {
		glog.Errorf("err: %s, view wrong fmt: %s\n", err.Error(), kv.String())
		return nil
	}
	return view
}

func doUpdateView(e *etcdv3.Event, ops *KdnsServerOps) {
	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()
	defer ops.etcdCachesLock.Unlock()
	switch e.Type {
	case etcdv3.EventTypePut:
		if e.IsCreate() {
			valNew := ParseView(e.Kv)
			if valNew != nil {
				ops.etcdViewUpdateTime[valNew.ViewName] = timeNow
				kdnsViewOperation(ops, valNew, "POST")
			}
		} else {
			glog.Infof("todo\n")
		}
	case etcdv3.EventTypeDelete:
		valDel := ParseView(e.PrevKv)
		if valDel != nil {
			ops.etcdViewUpdateTime[valDel.ViewName] = timeNow
			kdnsViewOperation(ops, valDel, "DELETE")
		}
	default:
		glog.Infof("the action not monitored: Action =%d kv=%v", e.Type, e.Kv)
	}
}

func UpdateView(e *etcdv3.Event) {
	glog.V(2).Infof("UpdateView: e = %+v", e)
	for _, ops := range kdnsOps {
		doUpdateView(e, ops)
	}
}

func WatchForDnsView(watchidx int64, client etcdv3.Client) {
	var watcher etcdv3.WatchChan
	viewCatched := false

reWatch:
	if viewCatched {
		watchidx = watchidx + 1
		viewCatched = false
	}
	glog.Infof("WatchForDnsView idx: %d\n", watchidx)
	opts := []etcdv3.OpOption{}
	if watchidx > 0 {
		opts = append(opts, etcdv3.WithRev(watchidx))
	}
	opts = append(opts, etcdv3.WithPrefix())
	opts = append(opts, etcdv3.WithPrevKV())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	watcher = client.Watch(ctx, DnsPath(DnsPathViews), opts...)
	var wres etcdv3.WatchResponse

	for wres = range watcher {
		if wres.Err() != nil {
			err := wres.Err()
			glog.Infof("err : %s ", err)
			watchidx = wres.Header.Revision
			goto reWatch
		}
		for _, e := range wres.Events {
			UpdateView(e)
			viewCatched = true
		}
	}
	if err := wres.Err(); err != nil {
		glog.Infof("WatchForDnsView err = %s\n", err)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	if err := ctx.Err(); err != nil {
		glog.Infof("WatchForDnsView err = %s\n", err)
		watchidx = wres.Header.Revision
		goto reWatch
	}

	glog.Infof("WatchForDnsView out: %d, watcher = %v, DnsPathViews = %s\n", watchidx, watcher, DnsPathViews)
}

func getDnsServerViews(ops *KdnsServerOps) (map[string]ServiceView, error) {
	req, err := http.NewRequest("GET", ops.KdnsUrl+kdnsViewUrl, nil)
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
	var views []KdnsView
	if err := json.Unmarshal(rbody, &views); err != nil {
		return nil, err
	}
	glog.V(4).Infof("views %+v\n", views)
	reMap := make(map[string]ServiceView)
	var pView *ServiceView
	for _, v := range views {
		datas, ok := reMap[v.ViewName]
		if ok {
			pView = &datas
		} else {
			pView = new(ServiceView)
		}
		pView.ViewName = v.ViewName
		pView.IpCIDRs = append(pView.IpCIDRs, v.Cidr)
		reMap[v.ViewName] = *pView
	}
	glog.V(4).Infof("reMap %+v\n", reMap)
	return reMap, nil
}

func syncViewEqual(etcd ServiceView, kdns ServiceView) ([]int, []int) {
	var delKndsCidr []int
	var addKndsCidr []int
	for idx, e := range etcd.IpCIDRs {
		found := false
		for _, k := range kdns.IpCIDRs {
			if k == e {
				found = true
				break
			}
		}
		if !found {
			addKndsCidr = append(addKndsCidr, idx)
		}
	}

	for idx, k := range kdns.IpCIDRs {
		found := false
		for _, e := range etcd.IpCIDRs {
			if k == e {
				found = true
				break
			}
		}
		if !found {
			delKndsCidr = append(delKndsCidr, idx)
		}
	}
	return addKndsCidr, delKndsCidr
}

func doDnsViewsSync(ops *KdnsServerOps, etcdValesOrg map[string]ServiceView) {
	timeNow := time.Now().Local()
	kdnsVals, err := getDnsServerViews(ops)
	if err != nil {
		glog.Infof("get views form kdns err: %s, we ingore the sync\n", err)
		return
	}
	etcdVales := make(map[string]ServiceView)
	// copy
	for k, v := range etcdValesOrg {
		etcdVales[k] = v
	}
	ops.etcdCachesLock.Lock()
	defer ops.etcdCachesLock.Unlock()
	var cidr2add []int
	var cidr2del []int
	for key, kval := range kdnsVals {
		lastUptime, ok := ops.etcdViewUpdateTime[key]
		// changed
		if ok && lastUptime.After(timeNow) {
			continue
		}

		eval, exist := etcdVales[key]
		if exist {
			cidr2add, cidr2del = syncViewEqual(eval, kval)
			if len(cidr2add) == 0 && len(cidr2del) == 0 {
				delete(etcdVales, key)
				continue
			}
		} else {
			//del pre
			glog.Infof("ddd key = %s, value = %s\n", key, kval)
			kdnsViewOperation(ops, &kval, "DELETE")
			continue
		}
		glog.Infof(" key = %s, len(cidr2add) = %d,  len(cidr2del) = %d\n", key, len(cidr2add), len(cidr2del))
		//del pre
		for _, idx := range cidr2del {
			doKdnsViewOperation(ops, kval.ViewName, kval.IpCIDRs[idx], "DELETE")
		}
		// etcd new value
		for _, idx := range cidr2add {
			doKdnsViewOperation(ops, eval.ViewName, eval.IpCIDRs[idx], "POST")
		}
		delete(etcdVales, key)
	}

	for key, eval := range etcdVales {
		_, exist := kdnsVals[key]
		if !exist {
			lastUptime, ok := ops.etcdViewUpdateTime[key]
			// changed
			if ok && lastUptime.After(timeNow) {
				continue
			}
			kdnsViewOperation(ops, &eval, "POST")
		}
	}

	for key, vTime := range ops.etcdViewUpdateTime {
		_, exist := etcdVales[key]
		// del old values
		if !exist && vTime.Before(timeNow) {
			delete(ops.etcdViewUpdateTime, key)
		}
	}
}

func dnsViewsSync() {
	for range time.Tick(time.Duration(gConfig.SyncPeriod) * time.Second) {
		etcdVales, _, err := GetViews()
		if err != nil {
			glog.Infof("get view from etcd err, continue\n")
			continue
		}
		for _, ops := range kdnsOps {
			doDnsViewsSync(ops, etcdVales)
		}
	}
}

func findZoneNameFromDomain(domain string) string {
	for _, zone := range dnsZones {
		if strings.Compare(domain, zone) == 0 || strings.HasSuffix(domain, "."+zone) {
			return zone
		}
	}
	return ""
}

func doKdnsDomainOperation(ops *KdnsServerOps, record *KdnsRecord, operation string) error {
	glog.V(2).Infof("doKdnsDomainOperation, operation = %s: record = %v\n", operation, record)
	if operation != "POST" && operation != "DELETE" {
		glog.Infof("Wrong operation: %s\n", operation)
		return nil
	}
	b, err := json.Marshal(&record)
	if err != nil {
		glog.Infof("json err:", err)
		return err
	}
	body := bytes.NewBuffer([]byte(b))
	req, err := http.NewRequest(operation, ops.KdnsUrl+kdnsDomainUrl, body)
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
		glog.Infof("%s %v err\n", operation, record)
	}
	return nil
}

func kdnsDomainOperation(ops *KdnsServerOps, zone string, record *ServiceRecord, operation string, srvHost bool) error {
	var s KdnsRecord
	if record.Dnstype != "A" && record.Dnstype != "PTR" && record.Dnstype != "CNAME" && record.Dnstype != "SRV" {
		glog.Infof("Wrong type: record = %v\n", record)
		return nil
	}
	if record.Dnstype == "CNAME" {
		s.DomainName = getSvcCnameName(record.Key)
	} else {
		s.DomainName = getSvcDomainName(record.Key)
	}
	if zone == "" {
		zone = findZoneNameFromDomain(s.DomainName)
	}
	if zone == "" {
		glog.Infof("kdnsDomainOperation err can not find zoneInfo for domain (%s), record(%v)\n", s.DomainName, record)
		return nil
	}
	s.Host = record.DnsHost
	s.ZoneName = zone
	s.Type = record.Dnstype
	s.DnsPriority = record.DnsPriority
	s.DnsPort = record.DnsPort
	s.DnsWeight = record.DnsWeight
	s.MaxAnswer = record.MaxAnswer
	s.DnsTtl = record.DnsTtl
	s.View = record.View
	s.LBMode = record.LBMode
	s.LBWeight = record.LBWeight

	return doKdnsDomainOperation(ops, &s, operation)
}

func Fqdn(s string) string {
	l := len(s)
	if s[l-1] == '.' {
		return s
	}
	return s + "."
}

func GetEtcdCachedRecordsAfterStart(domain string, ops *KdnsServerOps) int64 {
	glog.Infof("get etcd records(zone:%s) start\n", domain)
	records, revision, err := GetRecords(domain)
	if err != nil {
		if strings.HasPrefix(err.Error(), "context deadline exceeded") {
			glog.Fatalf("get records(zone:%s) err = %s\n", domain, err.Error())
		}
		glog.Infof("get records(zone:%s) err = %s\n", domain, err.Error())
		return 0
	}
	glog.Infof("get etcd records(zone:%s) out\n", domain)
	// skip sync data
	if ops == nil {
		glog.Infof("skip sync data for start\n")
		return revision
	}

	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()
	for _, record := range records {
		switch record.Dnstype {
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
	glog.Infof("len of domain(%s) = %d\n", domain, len(records))
	return revision
}

func syncGetEtcdCachedRecords() (map[string][]ServiceRecord, error) {
	recordCaches := make(map[string][]ServiceRecord)

	for _, domain := range dnsZones {
		records, _, err := GetRecords(domain)
		if err != nil {
			glog.Infof("ger records(zone:%s) err = %s\n", domain, err.Error())
			return recordCaches, err
		}
		for _, record := range records {
			name := ""
			if record.Dnstype == "CNAME" {
				name = getSvcCnameName(record.Key)
			} else {
				name = getSvcDomainName(record.Key)
			}
			find := false
			for _, k := range recordCaches[name] {
				if k.Dnstype == record.Dnstype && k.DnsHost == record.DnsHost && k.View == record.View {
					if record.Dnstype == "SRV" {
						if  k.DnsPriority == record.DnsPriority && k.DnsWeight == record.DnsWeight && k.DnsPort == record.DnsPort {
							find = true
							break
						}
					} else {
						find = true
						break
					}
				}
			}
			if !find {
				recordCaches[name] = append(recordCaches[name], record)
			}
		}
	}
	return recordCaches, nil
}

func ParseRecord(kv *mvccpb.KeyValue) *ServiceRecord {
	record := new(ServiceRecord)
	if err := json.Unmarshal(kv.Value, record); err != nil {
		glog.Errorf("err: %s, record wrong fmt: %s\n", err.Error(), kv.String())
		return nil
	}
	record.Key = string(kv.Key)
	if record.DnsPriority == 0 {
		record.DnsPriority = int(10)
	}
	if record.View == "" {
		record.View = "no_info"
	}
	return record
}

func doUpdateDomain(e *etcdv3.Event, zone string, ops *KdnsServerOps) {
	timeNow := time.Now().Local()
	ops.etcdCachesLock.Lock()
	defer ops.etcdCachesLock.Unlock()
	switch e.Type {
	case etcdv3.EventTypePut:
		if e.IsCreate() {
			valNew := ParseRecord(e.Kv)
			if valNew != nil {
				name := ""
				if valNew.Dnstype == "CNAME" {
					name = getSvcCnameName(valNew.Key)
				} else {
					name = getSvcDomainName(valNew.Key)
				}
				ops.etcdRecordUpdateTime[name] = timeNow
				kdnsDomainOperation(ops, zone, valNew, "POST", false)
			}
		} else {
			glog.Infof("todo\n")
		}
	case etcdv3.EventTypeDelete:
		valDel := ParseRecord(e.PrevKv)
		if valDel != nil {
			name := ""
			if valDel.Dnstype == "CNAME" {
				name = getSvcCnameName(valDel.Key)
			} else {
				name = getSvcDomainName(valDel.Key)
			}
			ops.etcdRecordUpdateTime[name] = timeNow
			kdnsDomainOperation(ops, zone, valDel, "DELETE", false)
		}
	default:
		glog.Infof("the action not monitored: Action =%d kv=%v", e.Type, e.Kv)
	}
}

func UpdateDomain(e *etcdv3.Event, zone string) {
	glog.V(2).Infof("UpdateDomain: e = %+v", e)
	for _, ops := range kdnsOps {
		doUpdateDomain(e, zone, ops)
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
	glog.Infof("WatchForDnsDomain idx: %d, zone = %s\n", watchidx, zone)
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
			UpdateDomain(e, zone)
			recordCatched = true
		}

	}
	if err := wres.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err = %s, zone = %s\n", err, zone)
		watchidx = wres.Header.Revision
		goto reWatch
	}
	if err := ctx.Err(); err != nil {
		glog.Infof("WatchForDnsDomain err = %s, zone = %s\n", err, zone)
		watchidx = wres.Header.Revision
		goto reWatch
	}

	glog.Infof("WatchForDnsDomain out: %d, watcher = %v, zone = %s\n", watchidx, watcher, zone)
}

func getDnsServerStatus(ops *KdnsServerOps) string {
	req, err := http.NewRequest("GET", ops.KdnsUrl+kdnsStatusUrl, nil)
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
	req, err := http.NewRequest("POST", ops.KdnsUrl+kdnsStatusUrl, nil)
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
			GetEtcdCachedViewsAfterStart(ops)
			postDnsServerStatus(ops)
		}
		glog.Infof("get status :%s\n", status)
	}
}

func getDnsServerDomains(ops *KdnsServerOps) (map[string][]KdnsRecord, error) {
	req, err := http.NewRequest("GET", ops.KdnsUrl+kdnsDomainUrl, nil)
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
			if k.Type == e.Dnstype && k.Host == e.DnsHost && k.DnsTtl == e.DnsTtl && k.View == e.View {
				if k.Type == "SRV" {
					if k.DnsPriority == e.DnsPriority && k.DnsWeight == e.DnsWeight && k.DnsPort == e.DnsPort {
						found = true
						break
					}
				} else if k.Type == "A" {
					if k.LBMode == e.LBMode && k.LBWeight == e.LBWeight {
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
			if k.Type == e.Dnstype && k.Host == e.DnsHost && k.DnsTtl == e.DnsTtl && k.View == e.View {
				if k.Type == "SRV" {
					if k.DnsPriority == e.DnsPriority && k.DnsWeight == e.DnsWeight && k.DnsPort == e.DnsPort {
						found = true
						break
					}
				} else if k.Type == "A" {
					if k.LBMode == e.LBMode && k.LBWeight == e.LBWeight {
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
	kdnsVals, err := getDnsServerDomains(ops)
	if err != nil {
		glog.Infof("get domains form kdns err: %s, we ingore the sync\n", err)
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
				doKdnsDomainOperation(ops, &v, "DELETE")
			}
			continue
		}
		glog.Infof(" key = %s, len(record2add) = %d,  len(record2del) = %d\n", key, len(record2add), len(record2del))
		//del pre
		for _, idx := range record2del {
			doKdnsDomainOperation(ops, &kvals[idx], "DELETE")
		}
		// etcd new value

		for _, idx := range record2add {
			kdnsDomainOperation(ops, "", &evals[idx], "POST", false)
		}
		delete(etcdVales, key)
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
			glog.Infof("get domains from etcd err, continue\n")
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
			glog.Fatalf(" can not get kdnsClient\n")
		}
		ops.KdnsUrl = v.KdnsUrl
		ops.etcdRecordUpdateTime = make(map[string]time.Time)
		ops.etcdViewUpdateTime = make(map[string]time.Time)
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
		glog.Fatalf("kdns: config domain is nil\n")
	}
	glog.Infof("dnsDomains = %v\n", dnsZones)
	for _, domain := range dnsZones {
		domainWatchIdx := int64(0)
		for _, ops := range kdnsOps {
			// read etcd many times todo
			idx := GetEtcdCachedRecordsAfterStart(domain, ops)
			if idx > domainWatchIdx {
				domainWatchIdx = idx
			}
		}
		// watch domains
		go WatchForDnsDomain(domain, domainWatchIdx+1, clientv3)
	}

	viewWatchIdx := int64(0)
	for _, ops := range kdnsOps {
		// read etcd many times todo
		idx := GetEtcdCachedViewsAfterStart(ops)
		if idx > viewWatchIdx {
			viewWatchIdx = idx
		}
	}
	// watch views
	go WatchForDnsView(viewWatchIdx+1, clientv3)

	for _, ops := range kdnsOps {
		go dnsStatusSync(ops)
	}

	go dnsDomainsSync()
	go dnsViewsSync()

	_, err = net.Dial("tcp", gConfig.Addr)
	if err == nil {
		glog.Fatalf("the addr is used:%s\n", gConfig.Addr)
	}
	go http.ListenAndServe(gConfig.Addr, nil)
	select {}
}
