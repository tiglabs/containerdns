// Copyright (c) 2017 The skydns Authors. All rights reserved.

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
	"flag"
	"fmt"
	etcdv3 "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/golang/glog"
	backendetcdCached "github.com/ipdcode/skydns/backends/etcd-cached"
	server "github.com/ipdcode/skydns/dns-server"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"os"
	"gopkg.in/gcfg.v1"

)

const (
	glogFlushPeriod = 5 * time.Second
)

var (
	gConfig        *ConfigOps
	configFile     = ""
	version        = false
)

type LogOps struct {
	LogDir        string `gcfg:"log-dir"`
	LogLevel      string `gcfg:"log-level"`
	LogStdIo      string `gcfg:"log-to-stdio"`
}
type EtcdOps struct {
	EtcdServers     string `gcfg:"etcd-servers"`
	EtcdCertfile    string `gcfg:"etcd-certfile"`
	EtcdKeyfile     string `gcfg:"etcd-keyfile"`
	EtcdCafile      string `gcfg:"etcd-cafile"`

}
type DnsOps struct {
	SkydnsDomains      string `gcfg:"dns-domains"`
	SkydnsAddr        string `gcfg:"dns-addr"`
	Nameservers       string `gcfg:"ex-nameservers"`
	InDomainServers  string `gcfg:"inDomainServers"`
	CacheSize         int  `gcfg:"cacheSize"`
	IpMonitorPath    string `gcfg:"ip-monitor-path"`
	SkipDomain      bool `gcfg:"skipDomain"`
}
type  FunFeature struct {
	RandomOne   bool `gcfg:"random-one"`
	IpHold      bool `gcfg:"hone-one"`
}

type  StatsServer struct {
	StatsServer  		 string `gcfg:"statsServer"`
	StatsServerAuthToken      string `gcfg:"statsServerAuthToken"`
}

type ConfigOps struct {
	Dns       DnsOps
	Log       LogOps
	Etcd      EtcdOps
	Fun       FunFeature
	Stats     StatsServer
}


func readConfig(configPath string) (*ConfigOps, error) {

	cfg := new(ConfigOps)
	var config *os.File
	config, err := os.Open(configPath)
	if err != nil {
		glog.Fatalf("Couldn't open cloud provider configuration %s: %#v",
			configPath, err)
	}

	defer config.Close()
	err = gcfg.ReadInto(cfg, config)
	return cfg, err
}

func configSetDefaults(config *ConfigOps)  {

	if config.Dns.SkydnsAddr == "" {
		config.Dns.SkydnsAddr = "127.0.0.1:53"
	}
	if config.Dns.SkydnsDomains == "" {
		config.Dns.SkydnsDomains  = "skydns.local."
	}
	if config.Dns.IpMonitorPath ==""{
		config.Dns.IpMonitorPath = "/skydns/monitor/status/"
	}

	if config.Dns.CacheSize  < 100000 {
		config.Dns.CacheSize = 100000
	}

	if !strings.HasSuffix(config.Dns.IpMonitorPath, "/") {
		config.Dns.IpMonitorPath = fmt.Sprintf("%s/", config.Dns.IpMonitorPath)
	}

}

func init() {
	flag.StringVar(&configFile, "config-file", "/etc/skydns/skydns.conf", "read config from the file")
	flag.BoolVar(&version, "version", false, "Print version information and quit")
	flag.Parse()
	var e error
	if gConfig, e = readConfig(configFile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(gConfig.Log.LogDir)
	flag.Lookup("v").Value.Set(gConfig.Log.LogLevel)
	flag.Lookup("logtostderr").Value.Set(gConfig.Log.LogStdIo)

}

func glogFlush(period time.Duration) {
	for range time.Tick(period) {
		glog.Flush()
	}
}

func checkHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("bad IP address: %s", host)
	}

	if p, _ := strconv.Atoi(port); p < 1 || p > 65535 {
		return fmt.Errorf("bad port number %s", port)
	}
	return nil
}

func newEtcdV3Client(machines []string) (*etcdv3.Client, error) {
	info := transport.TLSInfo{
		CertFile: gConfig.Etcd.EtcdCertfile,
		KeyFile:   gConfig.Etcd.EtcdKeyfile,
		CAFile:   gConfig.Etcd.EtcdCafile,
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
		TLS: tr.TLSClientConfig,
	}
	cli, err := etcdv3.New(etcdCfg)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func main() {
	flag.Parse()
	if version {
		s := server.Version + ": "+ C.GoString(C.build_time())
		fmt.Printf("%s\n", s)
		return
	}
	go glogFlush(glogFlushPeriod)
	defer glog.Flush()

	var clientv3 etcdv3.Client
	machines := strings.Split(gConfig.Etcd.EtcdServers, ",")

	clientv3P, err := newEtcdV3Client(machines)
	if err != nil {
		glog.Fatalf("skydns:newEtcdClient: %s", err)
	}
	clientv3 = *clientv3P

	configSetDefaults(gConfig)

	var dnsDomains []string
	if gConfig.Dns.SkydnsDomains != "" {
		for _, domain := range strings.Split(gConfig.Dns.SkydnsDomains, "%") {
			domain = dns.Fqdn(strings.ToLower(domain))
			dnsDomains = append(dnsDomains, domain)
		}
	} else {
		glog.Fatalf("skydns: config domain is nil \n")
	}
	var forwardNameServers []string
	if gConfig.Dns.Nameservers != "" {
		for _, hostPort := range strings.Split(gConfig.Dns.Nameservers, ",") {
			if err := checkHostPort(hostPort); err != nil {
				glog.Fatalf("skydns: nameserver is invalid: %s", err)
			}
			forwardNameServers = append(forwardNameServers, hostPort)
		}
	} else {
		c, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if !os.IsNotExist(err) {
			if err != nil {
				glog.Fatalf("err = %s\n", err)
			}
			for _, s := range c.Servers {
				forwardNameServers = append(forwardNameServers, net.JoinHostPort(s, c.Port))
			}
		}
	}

	subDomainServers := make(map[string][]string)

	if gConfig.Dns.InDomainServers != "" {
		for _, item := range strings.Split(gConfig.Dns.InDomainServers, "%") {
			// item :   a.skydns.local->8.8.8.8:53,8.8.4.4:53
			val := strings.Split(item, "@")
			if len(val) != 2 {
				glog.Fatalf("subDomainServers is invalid: %s", item)
			}
			subDomian := dns.Fqdn(val[0])
			if subDomian[0] != '.' {
				subDomian = "." + subDomian
			}

			for _, hostPort := range strings.Split(val[1], ",") {
				if err := checkHostPort(hostPort); err != nil {
					glog.Fatalf("skydns: nameserver is invalid: %s", err)
				}
				subDomainServers[subDomian] = append(subDomainServers[subDomian], hostPort)
			}
		}

	}

	for subKey, subVal := range subDomainServers {
		glog.Infof("  subDomain : %s  subServers :%s ", subKey, subVal)
	}

	if err := checkHostPort(gConfig.Dns.SkydnsAddr); err != nil {
		glog.Fatalf("skydns: addr is invalid: %s", err)
	}

	if gConfig.Fun.IpHold && gConfig.Fun.RandomOne {
		glog.Fatalf("skydns: ipHold and radom-one you must chose one or neither, check config file !! \n")
	}

	var ctx = context.TODO()
	var backend server.Backend

	backend = backendetcdCached.NewBackend(clientv3, ctx, 60, 3600, 10)

	s := server.New(backend, dnsDomains, gConfig.Dns.SkydnsAddr, gConfig.Dns.IpMonitorPath,
		forwardNameServers, subDomainServers, gConfig.Dns.CacheSize, gConfig.Fun.RandomOne, gConfig.Fun.IpHold,gConfig.Dns.SkipDomain)
        glog.Infof("dnsDomains = %v\n",dnsDomains)
	for _, domain := range (dnsDomains) {
		domainWatchIdx := int64(0)
		domainWatchIdx = s.GetEtcdCachedRecordsAfterStart(domain)
		glog.Infof("domainWatchIdx =%v  dir =%s \n", domainWatchIdx, server.DnsPath(domain))
		// watch domains
		go s.WatchForDnsDomain(domain,domainWatchIdx + 1, clientv3)
	}
	// before server run we get the active ips
	ipWatchIdx := s.GetSkydnsHostStatus()
	glog.Infof("ipWatchIdx =%v   dir =%s\n", ipWatchIdx, gConfig.Dns.IpMonitorPath)
        go s.WatchForHosts(ipWatchIdx +1,clientv3)

	// syc tasks
	go s.SyncEtcdCachedRecords()
	go s.HostStatusSync()

	go s.Statistics(gConfig.Stats.StatsServer, gConfig.Stats.StatsServerAuthToken) //

	s.RunToEnd()
}


