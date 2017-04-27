// kube2skydns is a bridge between Kubernetes and Skydns.  It watches the
// Kubernetes master for changes in Services and manifests them into etcd for
//Hedes to serve as DNS records.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang/glog"
	skydnsmsg "github.com/ipdcode/skydns/dns-server"
	"github.com/ipdcode/skydns/utils"
	"gopkg.in/gcfg.v1"
	"hash/fnv"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/mvcc/mvccpb"
	kapi "k8s.io/kubernetes/pkg/api"
	kcache "k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/util/logs"
	"k8s.io/kubernetes/pkg/util/wait"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	kclientcmd "k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	k8sruntime "k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
	k8sflag "k8s.io/kubernetes/pkg/util/flag"
)

const (
	// Resync period for the kube controller loop.
	resyncPeriod  = 20 * time.Second
	syncAllPeriod = 60 * time.Second
	// A subdomain added to the user specified domain for all services.
	serviceSubdomain = "svc"

	argEtcdMutationTimeout = 10 * time.Second

	etcdKeyNotFound      = "key not found"
	etcdKeyalReadyExists = "key exists"

	SkydnsKubeApiVersion = "1.0"
)

var (
	gConfig        *ConfigOps
	configFile     = ""
	version        = false
	monitorIpPotrs map[string][]string
)
type GeneralOps struct {
	SkydnsDomain   string `gcfg:"domain"`
	Host   	      string `gcfg:"host"`
	EtcdServer    string `gcfg:"etcd-server"`
	EtcdCertfile    string `gcfg:"etcd-certfile"`
	EtcdKeyfile    string `gcfg:"etcd-keyfile"`
	EtcdCafile    string `gcfg:"etcd-cafile"`

	IpMonitorPath string `gcfg:"ip-monitor-path"`
	LogDir        string `gcfg:"log-dir"`
	LogLevel      string `gcfg:"log-level"`
	LogStdIo      string `gcfg:"log-to-stdio"`
}
type Kube2SkydnsOps struct {
	KubeEnable         string   `gcfg:"kube-enable"`
	KubeConfigFile      string   `gcfg:"kube-config-file"`
}
type SkydnsApiOps struct {
	ApiAuth   string `gcfg:"skydns-auth"`
	ApiAddr   string `gcfg:"api-address"`
	ApiEnable string `gcfg:"api-enable"`
}

type ConfigOps struct {
	General    GeneralOps
	Kube2Skydns Kube2SkydnsOps
	SkydnsApi   SkydnsApiOps
}

type nameNamespace struct {
	name      string
	namespace string
}

type kube2skydns struct {
	// Etcd client.
	etcdClient *tools.EtcdV3
	// DNS domain name.
	domain string
	// Etcd mutation timeout.
	etcdMutationTimeout time.Duration
	// A cache that contains all the services in the system.
	servicesStore  kcache.Store
	endpointsStore kcache.Store

	// Lock for controlling access to headless services.
	mlock sync.Mutex
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

// Removes 'subdomain' from etcd.
func (ks *kube2skydns) removeDNS(subdomain string) error {
	glog.V(2).Infof("Removing %s from DNS", subdomain)
	key := skydnsmsg.DnsPath(subdomain)
	res, err := ks.etcdClient.Get(key, true)
	if err != nil {
		goto errCheck
	}

	err = ks.etcdClient.Delete(res)

errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
			return nil
		} else {
			return err
		}
	}
	return err
}

func (ks *kube2skydns) writeSkydnsRecord(subdomain string, data string) error {
	// Set with no TTL, and hope that kubernetes events are accurate.
	res, err := ks.etcdClient.Get(skydnsmsg.DnsPath(subdomain), true)
	// the key exist
	if err == nil {
		if string(res.Kvs[0].Value) == data {
			glog.V(2).Infof(" writeSkydnsRecord value equal:%s", data)
			return nil
		} else {
			err = ks.etcdClient.Update(skydnsmsg.DnsPath(subdomain), data)
			goto errCheck
		}
	}
	//set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
		err = ks.etcdClient.Set(skydnsmsg.DnsPath(subdomain), data)
	}

errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyalReadyExists) {
			return nil
		} else {
			return err
		}
	}
	return err
}

func (ks *kube2skydns) deleteIpMonitorRecord(ip string) error {
	key := gConfig.General.IpMonitorPath + ip
	res, err := ks.etcdClient.Get(key, false)
	if err != nil {
		goto errCheck
	}
	glog.V(2).Infof("deleteIpMonitorRecord :%s", key)
	err = ks.etcdClient.Delete(res)
errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
			return nil
		} else {
			return err
		}
	}
	return err
}
func (ks *kube2skydns) writeIpMonitorRecord(ip string, ports []string) error {
	var status apiSkydnsIpMonitor
	status.Status = "UP"
	status.Ports = ports[:]
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	recordValue := string(b)
	key := gConfig.General.IpMonitorPath + ip
	glog.V(2).Infof("writeIpMonitorRecord:%s", key)

	res, err := ks.etcdClient.Get(key, true)
	// the key exist
	if err == nil {
		glog.V(2).Infof(" writeIpMonitorRecord key:%s exist,val: res.Node.Value:%s", key, string(res.Kvs[0].Value))
		return nil
	}
	//set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
		err = ks.etcdClient.Set(key, recordValue)
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyalReadyExists) {
			glog.V(4).Infof(" %s \n ", etcdKeyalReadyExists)
			return nil
		} else {
			return err
		}
	}
	return err
}
func getSkydnsMsg(ip string, port int, dnstype string) *skydnsmsg.ServiceRecord {
	return &skydnsmsg.ServiceRecord{
		DnsHost:     ip,
		DnsPort:     port,
		DnsPriority: 10,
		DnsWeight:   10,
		DnsTtl:      30,
		Dnstype:  dnstype,
	}
}

func buildPortSegmentString(portName string, portProtocol kapi.Protocol) string {
	if portName == "" {
		// we don't create a random name
		return ""
	}

	if portProtocol == "" {
		glog.Errorf("Port Protocol not set. port segment string cannot be created.")
		return ""
	}

	return fmt.Sprintf("_%s._%s", portName, strings.ToLower(string(portProtocol)))
}

func (ks *kube2skydns) generateSRVRecord(subdomain, portSegment, recordName, cName string, portNumber int32) error {
	recordKey := buildDNSNameString(subdomain, portSegment, recordName)
	srv_rec, err := json.Marshal(getSkydnsMsg(cName, int(portNumber), "SRV"))
	if err != nil {
		return err
	}
	glog.Infof(" srv recordKey =%s\n", recordKey)
	if err := ks.writeSkydnsRecord(recordKey, string(srv_rec)); err != nil {
		return err
	}
	return nil
}

func (ks *kube2skydns) generateOneRecordForPortalService(subdomain string, ip string, service *kapi.Service) error {

	b, err := json.Marshal(getSkydnsMsg(ip, 0, "A"))
	if err != nil {
		return err
	}
	recordValue := string(b)
	recordLabel := getHash(recordValue)
	recordKey := buildDNSNameString(subdomain, recordLabel)

	glog.V(2).Infof("Setting DNS record: %v -> %q, with recordKey: %v\n", subdomain, recordValue, recordKey)
	if err := ks.writeSkydnsRecord(recordKey, recordValue); err != nil {
		return err
	}
	var ports []string
	for i := range service.Spec.Ports {
		port := &service.Spec.Ports[i]
		ports = append(ports, fmt.Sprintf("%d", port.Port))
	}
	ks.writeIpMonitorRecord(ip, ports)
	return nil
}
func (ks *kube2skydns) generateRecordsForPortalService(subdomain string, service *kapi.Service) error {

	for _, ip := range service.Spec.ExternalIPs {
		ks.generateOneRecordForPortalService(subdomain, ip, service)
	}
	return nil
}

func (ks *kube2skydns) IsServiceVIPSet(service *kapi.Service) bool {
	if len(service.Spec.ExternalIPs) == 0 || service.Spec.ExternalIPs[0] == "" {
		return false
	}
	return true
}

func (ks *kube2skydns) IsServiceVIPDiff(oldsvc *kapi.Service, newsvc *kapi.Service) bool {
	i := len(oldsvc.Spec.ExternalIPs)
	j := len(newsvc.Spec.ExternalIPs)
	if i != j {
		return true
	}
	// no vip
	if i == 0 {
		return false
	}
	if reflect.DeepEqual(oldsvc.Spec.ExternalIPs, newsvc.Spec.ExternalIPs) {
		return false
	}
	return true
}

func (ks *kube2skydns) isServiceSrv(service *kapi.Service) bool {
	return service.Spec.ClusterIP == "None"
}
func (ks *kube2skydns) addDNS(subdomain string, service *kapi.Service) error {
	// if ClusterVIP is not set, a DNS entry should not be created
	if !ks.IsServiceVIPSet(service) {
		glog.V(2).Infof("ignore the svc for cluster LB VIP is nil : %s", service.Name)
		return nil
	}
	// SRV
	if ks.isServiceSrv(service) {
		return nil
	}
	return ks.generateRecordsForPortalService(subdomain, service)
}

func buildDNSNameString(labels ...string) string {
	var res string
	for _, label := range labels {
		if res == "" {
			res = label
		} else {
			res = fmt.Sprintf("%s.%s", label, res)
		}
	}
	return res
}

func (ks *kube2skydns) newService(obj interface{}) {
	if s, ok := obj.(*kapi.Service); ok {
		name := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name)
		ks.addDNS(name, s)
	}
}
func (ks *kube2skydns) checkEndpointUpdate(objNew interface{}, objOld interface{}) bool {
	olde, ok1 := objOld.(*kapi.Endpoints)
	newe, ok2 := objNew.(*kapi.Endpoints)
	if ok1 && ok2 {
		if olde.Name != newe.Name || olde.Namespace != newe.Namespace || len(olde.Subsets) != len(newe.Subsets) {
			return true
		}
		return false
	}
	return false
}

func (ks *kube2skydns) handleEndpointAdd(obj interface{}) {
	if e, ok := obj.(*kapi.Endpoints); ok {
		name := buildDNSNameString(ks.domain, serviceSubdomain, e.Namespace, e.Name)
		ks.addDNSUsingEndpoints(name, e)
	}
}
func (ks *kube2skydns) getServiceFromEndpoints(e *kapi.Endpoints) (*kapi.Service, error) {
	key, err := kcache.MetaNamespaceKeyFunc(e)
	if err != nil {
		return nil, err
	}
	obj, exists, err := ks.servicesStore.GetByKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get service object from services store - %v", err)
	}
	if !exists {
		glog.V(1).Infof("could not find service for endpoint %q in namespace %q", e.Name, e.Namespace)
		return nil, nil
	}
	if svc, ok := obj.(*kapi.Service); ok {
		return svc, nil
	}
	return nil, fmt.Errorf("got a non service object in services store %v", obj)
}

func (ks *kube2skydns) addDNSUsingEndpoints(subdomain string, e *kapi.Endpoints) error {
	ks.mlock.Lock()
	defer ks.mlock.Unlock()
	svc, err := ks.getServiceFromEndpoints(e)
	if err != nil {
		return err
	}
	if svc == nil || !ks.isServiceSrv(svc) {
		// No headless service found corresponding to endpoints object.
		return nil
	}
	// Remove existing DNS entry.
	if err := ks.removeDNS(subdomain); err != nil {
		return err
	}
	return ks.generateRecordsForHeadlessService(subdomain, e, svc)
}

func (ks *kube2skydns) generateRecordsForHeadlessService(subdomain string, e *kapi.Endpoints, svc *kapi.Service) error {
	for idx := range e.Subsets {
		for subIdx := range e.Subsets[idx].Addresses {
			endpointIP := e.Subsets[idx].Addresses[subIdx].IP
			b, err := json.Marshal(getSkydnsMsg(endpointIP, 0, "A"))
			if err != nil {
				return err
			}
			recordValue := string(b)
			recordLabel := getHash(recordValue)

			recordKey := buildDNSNameString(subdomain, recordLabel)

			glog.V(2).Infof("Setting DNS record: %v -> %q\n", recordKey, recordValue)
			if err := ks.writeSkydnsRecord(recordKey, recordValue); err != nil {
				return err
			}

			var ports []string

			for portIdx := range e.Subsets[idx].Ports {
				endpointPort := &e.Subsets[idx].Ports[portIdx]
				portSegment := buildPortSegmentString(endpointPort.Name, endpointPort.Protocol)
				if portSegment != "" {
					err := ks.generateSRVRecord(subdomain, portSegment, recordLabel, recordKey, endpointPort.Port)
					if err != nil {
						return err
					}
					ports = append(ports, fmt.Sprintf("%d", endpointPort.Port))
				}
			}
			// write monitor
			ks.writeIpMonitorRecord(endpointIP, ports)
		}
	}

	return nil
}
func (ks *kube2skydns) removeService(obj interface{}) {
	if s, ok := obj.(*kapi.Service); ok {
		// no vip return
		if !ks.IsServiceVIPSet(s) {
			glog.V(2).Info("ignore the svc for cluster LB VIP is nil : %s", s.Name)
			return
		}
		name := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name)
		err := ks.removeDNS(name)
		if err != nil {
			glog.Infof("removeService err: %s", err.Error())
		}
		for _, ip := range s.Spec.ExternalIPs {
			err = ks.deleteIpMonitorRecord(ip)
			if err != nil {
				glog.Infof("deleteIpMonitorRecord err: %s", err.Error())
			}
		}

	}
}

func (ks *kube2skydns) updateService(oldObj, newObj interface{}) {
	oldsvc, ok1 := oldObj.(*kapi.Service)
	newsvc, ok2 := newObj.(*kapi.Service)
	if ok1 && ok2 {
		// name or namespace or ip change
		if oldsvc.Name != newsvc.Name || oldsvc.Namespace != newsvc.Namespace || ks.IsServiceVIPDiff(oldsvc, newsvc) {
			glog.V(2).Infof("#####　updateService  new =%s  old: =%s \n", newsvc.Spec.ExternalIPs,oldsvc.Spec.ExternalIPs)
			ks.removeService(oldObj)
			ks.newService(newObj)
			return
		}
		glog.V(4).Infof("ignore updateService this time \n")
	}
}

func newEtcdClient(etcdServer,etcdCertfile,etcdKeyile,etcdCafile string) *tools.EtcdV3 {
	etcdcli := tools.EtcdV3{}
	err := etcdcli.InitEtcd(strings.Split(etcdServer, ","),etcdCertfile,etcdKeyile,etcdCafile)
	if err != nil {
		glog.Fatalf("Failed to create etcd client - %v", err)
	}
	return &etcdcli
}

func newKubeClient() (clientset.Interface, error) {
	var (
		config *restclient.Config
		err    error
	)

	overrides := &kclientcmd.ConfigOverrides{}
	kubeConfig := k8sflag.NewStringFlag(gConfig.Kube2Skydns.KubeConfigFile)
	rules := &kclientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfig.Value()}
	if config, err = kclientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig(); err != nil {
		return nil, err
	}

	return clientset.NewForConfig(config)
}

func watchForServices(kubeClient clientset.Interface, ks *kube2skydns) kcache.Store {
	serviceStore, serviceController := kcache.NewInformer(
		&kcache.ListWatch{
			ListFunc: func(options kapi.ListOptions) (k8sruntime.Object, error) {
				return kubeClient.Core().Services(kapi.NamespaceAll).List(options)
			},
			WatchFunc: func(options kapi.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Services(kapi.NamespaceAll).Watch(options)
			},
		},
		&kapi.Service{},
		resyncPeriod,
		kcache.ResourceEventHandlerFuncs{
			AddFunc:    ks.newService,
			DeleteFunc: ks.removeService,
			UpdateFunc: ks.updateService,
		},
	)
	go serviceController.Run(wait.NeverStop)
	return serviceStore
}


func watchEndpoints(kubeClient clientset.Interface, ks *kube2skydns) kcache.Store {
	eStore, eController := kcache.NewInformer(
		&kcache.ListWatch{
			ListFunc: func(options kapi.ListOptions) (k8sruntime.Object, error) {
				return kubeClient.Core().Endpoints(kapi.NamespaceAll).List(options)
			},
			WatchFunc: func(options kapi.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Endpoints(kapi.NamespaceAll).Watch(options)
			},
		},
		&kapi.Endpoints{},
		resyncPeriod,
		kcache.ResourceEventHandlerFuncs{
			AddFunc: ks.handleEndpointAdd,
			UpdateFunc: func(oldObj, newObj interface{}) {
				if ks.checkEndpointUpdate(newObj, oldObj) {
					ks.handleEndpointAdd(newObj)
				}

			},
		},
	)

	go eController.Run(wait.NeverStop)
	return eStore
}

func getHash(text string) string {
	h := fnv.New32a()
	h.Write([]byte(text))
	return fmt.Sprintf("%x", h.Sum32())
}

func checkConfigOps() {
	// domain
	if gConfig.General.SkydnsDomain == "" {
		gConfig.General.SkydnsDomain = "skydns.local."
	}
	if gConfig.General.Host == "" {
		glog.Fatal("General Host is nil, check config file : ", configFile)
	}
	// ip monitor path
	if gConfig.General.IpMonitorPath == "" {
		gConfig.General.IpMonitorPath = "/skydns/monitor/status/"
	}

	if !strings.HasSuffix(gConfig.General.SkydnsDomain, ".") {
		gConfig.General.SkydnsDomain = fmt.Sprintf("%s.", gConfig.General.SkydnsDomain)
	}
	if !strings.HasSuffix(gConfig.General.IpMonitorPath, "/") {
		gConfig.General.IpMonitorPath = fmt.Sprintf("%s/", gConfig.General.IpMonitorPath)
	}
	//etcd
	if gConfig.General.EtcdServer == "" {
		glog.Fatal("EtcdServer is nil, check config file : ", configFile)
	}

	// kube
	if strings.ToUpper(gConfig.Kube2Skydns.KubeEnable) == "YES" {
		gConfig.Kube2Skydns.KubeEnable = "YES"
		if gConfig.Kube2Skydns.KubeConfigFile == ""{
			glog.Fatal("KubeConfigFile is nil, check config file : ",configFile)
		}
	}
	// api
	if strings.ToUpper(gConfig.SkydnsApi.ApiEnable) == "YES" {
		gConfig.SkydnsApi.ApiEnable = "YES"
		if gConfig.SkydnsApi.ApiAddr == "" {
			glog.Fatal("ApiAddr is nil, check config file : ", configFile)
		}
		if gConfig.SkydnsApi.ApiAuth == "" {
			glog.Fatal("ApiAuth is nil, check config file :", configFile)
		}
	}

	// nor
	if gConfig.SkydnsApi.ApiEnable != "YES" && gConfig.Kube2Skydns.KubeEnable != "YES" {
		glog.Fatal("both kube-enable and api-enable are nil , check config file : ", configFile)
	}
}
func (ks *kube2skydns) getServicesSRVRecords(s *kapi.Service, svcMap map[string]string, srvSvcMap map[string]string,ipPorts map[string][]string) {
	// get endpoint
	var e *kapi.Endpoints = nil
	for _, m := range ks.endpointsStore.List() {
		ep := m.(*kapi.Endpoints)
		if s.Name == ep.Name && s.Namespace == ep.Namespace {
			e = ep
			break
		}
	}
	if e == nil {
		return
	}
	subdomain := buildDNSNameString(ks.domain, serviceSubdomain, e.Namespace, e.Name)

	// get the key val
	for idx := range e.Subsets {
		for subIdx := range e.Subsets[idx].Addresses {
			endpointIP := e.Subsets[idx].Addresses[subIdx].IP
			b, err := json.Marshal(getSkydnsMsg(endpointIP, 0, "A"))
			if err != nil {
				return
			}
			recordValue := string(b)
			recordLabel := getHash(recordValue)
			recordKey := buildDNSNameString(subdomain, recordLabel)

			//svcMap[skydnsmsg.DnsPath(recordKey)] = recordValue
			srvSvcMap[skydnsmsg.DnsPath(recordKey)] = recordValue

			//srv
			for portIdx := range e.Subsets[idx].Ports {
				endpointPort := &e.Subsets[idx].Ports[portIdx]
				portSegment := buildPortSegmentString(endpointPort.Name, endpointPort.Protocol)
				if portSegment != "" {
					recordKeyReal := buildDNSNameString(subdomain, portSegment, recordLabel)
					srv_rec, err := json.Marshal(getSkydnsMsg(recordKey, int(endpointPort.Port), "SRV"))
					if err != nil {
						return
					}
					svcMap[skydnsmsg.DnsPath(recordKeyReal)] = string(srv_rec)
					ipPorts[endpointIP] = append(ipPorts[endpointIP], fmt.Sprintf("%d", endpointPort.Port))
				}
			}
		}
	}
	return
}
func (ks *kube2skydns) getServicesFromKube() (map[string]string, map[string]string,map[string][]string, bool) {
	svcMap := make(map[string]string)
	srvSvcMap := make(map[string]string)
	ipPorts := make(map[string][]string)
	services := ks.servicesStore.List()

	if len(services) == 0 {
		glog.Infof("getServices : list no svcs found\n")
		return svcMap, srvSvcMap,ipPorts, false
	}
	for _, s := range services {
		if s, ok := s.(*kapi.Service); ok {

			// SDR record
			if ks.isServiceSrv(s) {
				ks.getServicesSRVRecords(s, svcMap,srvSvcMap, ipPorts)
				continue
			}

			if !ks.IsServiceVIPSet(s) {
				glog.V(2).Infof("ignore the svc for cluster LB VIP is nil : %s", s.Name)
				continue
			}
			for _, ip := range s.Spec.ExternalIPs {
				b, err := json.Marshal(getSkydnsMsg(ip, 0, "A"))
				if err != nil {
					continue
				}
				recordValue := string(b)
				recordLabel := getHash(recordValue)
				recordKey := buildDNSNameString(ks.domain, serviceSubdomain, s.Namespace, s.Name, recordLabel)
				svcMap[skydnsmsg.DnsPath(recordKey)] = recordValue

				// get ports
				for i := range s.Spec.Ports {
					port := &s.Spec.Ports[i]
					ipPorts[ip] = append(ipPorts[ip], fmt.Sprintf("%d", port.Port))
				}
			}

		}
		continue
	}
	return svcMap, srvSvcMap,ipPorts, true
}

func (ks *kube2skydns) kubeLoopNodes(kv []*mvccpb.KeyValue, sx map[string]string, hosts map[string]bool) error {
	var record apiSkydnsRecord

	for _, item := range kv {

		if err := json.Unmarshal([]byte(item.Value), &record); err != nil {
			return err
		}
		key := string(item.Key)
		val := string(item.Value)
		switch record.Dnstype {
		case "A":
			sx[key] = val
			hosts[record.Host] = true
		// no use etcd get cannot find _tcp
		case "SRV":
			sx[key] = val
		default:
			continue
		}
	}
	return nil
}
func (ks *kube2skydns) getServicesFromSkydns(name string, sx map[string]string, hosts map[string]bool) error {
	subdomain := buildDNSNameString(name)

	r, err := ks.etcdClient.Get(skydnsmsg.DnsPath(subdomain), true)
	if err != nil {
		return err
	}

	return ks.kubeLoopNodes(r.Kvs, sx, hosts)

}

func (ks *kube2skydns) syncKube2Skydns() {
	glog.V(2).Info("Begin syncKube2Skydns...")
	var kubeServices ,srvSvcMap map[string]string
	var ok bool
	kubeServices,srvSvcMap, monitorIpPotrs, ok = ks.getServicesFromKube()
	if ok != true {
		return
	}
	svcSkydns := make(map[string]string)
	hostSkydns := make(map[string]bool)
	// just get svc.
	err := ks.getServicesFromSkydns(serviceSubdomain + "." + gConfig.General.SkydnsDomain, svcSkydns, hostSkydns)
	if err != nil {
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr, etcdKeyNotFound) {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	// srvSvcMap must be set before srv record for all skydns-allcached
	for key, val := range srvSvcMap {
		glog.V(4).Infof("svc in Kube:: key :%s  val =%s\n", key, val)
		valSkydns, exists := svcSkydns[key]
		if exists {
			if strings.Compare(valSkydns, val) != 0 {
				glog.V(3).Infof("key =%s  kubeval =%s skydnsVal =%s\n", key, val, valSkydns)
				ks.etcdClient.Update(key, val)
			}
			continue
		}
		//we add new one
		ks.etcdClient.Set(key, val)
	}

	for key, val := range kubeServices {
		glog.V(4).Infof("svc in Kube:: key :%s  val =%s\n", key, val)
		valSkydns, exists := svcSkydns[key]
		if exists {
			if strings.Compare(valSkydns, val) != 0 {
				glog.V(3).Infof("key =%s  kubeval =%s skydnsVal =%s\n", key, val, valSkydns)
				ks.etcdClient.Update(key, val)
			}
			continue
		}
		//we add new one
		ks.etcdClient.Set(key, val)
	}
	// Remove services missing from the update.
	for name, valSkydns := range svcSkydns {
		glog.V(4).Infof("svc in Skydns:: key :%s  val =%s\n", name, valSkydns)
		_, exists1 := kubeServices[name]
		_, exists2 := srvSvcMap[name]
		if !exists1 && !exists2 {

			glog.V(3).Infof("del from skydns key :%s  val =%s\n", name, valSkydns)
			ks.etcdClient.DoDelete(name)
		}
	}
}

func (ks *kube2skydns) syncSkydnsHostStatus() {
	glog.V(2).Info("Begin syncSkydnsHostStatus...")
	// just get svc + user define
	svcSkydns := make(map[string]string)
	hostsSkydns := make(map[string]bool)
	err := ks.getServicesFromSkydns(gConfig.General.SkydnsDomain, svcSkydns, hostsSkydns)
	if err != nil {
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr, etcdKeyNotFound) {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	// get hosts form /skydns/monitor/status/
	monitorIps := make(map[string]bool)
	r, err1 := ks.etcdClient.Get(gConfig.General.IpMonitorPath, true)
	if err1 != nil {
		retStr := err1.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr, etcdKeyNotFound) {
			glog.Infof("Err: %s\n", err1.Error())
			return
		}
	} else {
		for _, item := range r.Kvs {
			key := string(item.Key)
			ip := key[len(gConfig.General.IpMonitorPath):]
			monitorIps[ip] = true
		}

	}

	//update the diffs
	for key, _ := range hostsSkydns {
		glog.V(4).Infof("svcHosts key: %s\n", key)

		_, exists := monitorIps[key]
		if !exists {
			var status apiSkydnsIpMonitor
			status.Status = "UP"

			// check ports
			_, exists = monitorIpPotrs[key]
			if exists {
				status.Ports = monitorIpPotrs[key][:]
			}

			b, err := json.Marshal(status)
			if err != nil {
				glog.Infof("json.Marshal err: %s\n", err.Error())
				return
			}
			recordValue := string(b)
			ks.etcdClient.Set(gConfig.General.IpMonitorPath+key, recordValue)
		}
	}

	for key, _ := range monitorIps {
		glog.V(4).Infof("monitorIps key: %s\n", key)
		_, exists := hostsSkydns[key]
		if !exists {
			ks.etcdClient.DoDelete(gConfig.General.IpMonitorPath + key)
		}
	}

}
func (ks *kube2skydns) svcSyncLoop(period time.Duration) {
	for range time.Tick(period) {
		glog.Infof("svcSyncLoop \n")
		ks.syncKube2Skydns()
		ks.syncSkydnsHostStatus()
	}
}

func init() {
	flag.StringVar(&configFile, "config-file", "/etc/skydns/skydns-api.conf", "read config from the file")
	flag.BoolVar(&version, "version", false, "Print version information and quit")
	flag.Parse()
	var e error
	if gConfig, e = readConfig(configFile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(gConfig.General.LogDir)
	flag.Lookup("v").Value.Set(gConfig.General.LogLevel)
	flag.Lookup("logtostderr").Value.Set(gConfig.General.LogStdIo)

}

type kubeApiReg struct {
	Version  string     `json:"version,omitempty"`
	LastTime time.Time `json:"lastTime,omitempty"`
}
func kubeapiRegister(client *tools.EtcdV3){
	var data kubeApiReg
	data.Version = SkydnsKubeApiVersion
	for range time.Tick(60 * time.Second) {
		data.LastTime = time.Now().Local()
		b, err := json.Marshal(data)
		if err != nil {
			glog.Infof("%s\n", err.Error())
		}
		recordValue := string(b)
		name := skydnsmsg.DnsPath(gConfig.General.SkydnsDomain)
		name = name[:len(name)-1] + "-kubeapi-reg/"+ gConfig.General.Host
		glog.V(2).Infof("Heartbeat reg key=%s val =%s\n",name,recordValue)
		_,err = client.Get(name,false)
		if err != nil{
			err = client.Set(name, recordValue)
			if err != nil {
				glog.Infof("%s\n", err.Error())
			}
		}else{
			err = client.Update(name, recordValue)
			if err != nil {
				glog.Infof("%s\n", err.Error())
			}
		}

	}
}

func main() {
	if version {
		fmt.Printf("%s\n", SkydnsKubeApiVersion)
		return
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	logs.InitLogs()
	defer logs.FlushLogs()

	checkConfigOps()

	ks := kube2skydns{
		domain:              gConfig.General.SkydnsDomain,
		etcdMutationTimeout: argEtcdMutationTimeout,
	}

	ks.etcdClient = newEtcdClient(gConfig.General.EtcdServer,gConfig.General.EtcdCertfile,gConfig.General.EtcdKeyfile,gConfig.General.EtcdCafile)

	go kubeapiRegister(ks.etcdClient)

	if gConfig.Kube2Skydns.KubeEnable == "YES" {
		glog.Infof("kubernetes serverce to dns enable ")
		kubeClient, err := newKubeClient()
		if err != nil {
			glog.Fatalf("Failed to create a kubernetes client: %v", err)
		}
		ks.servicesStore = watchForServices(kubeClient, &ks)
		ks.endpointsStore = watchEndpoints(kubeClient, &ks)

		go ks.svcSyncLoop(syncAllPeriod)
	}
	if gConfig.SkydnsApi.ApiEnable == "YES" {
		glog.Infof("hedes  dns api enable ")
		RunApi(ks.etcdClient, gConfig.SkydnsApi.ApiAddr, gConfig.General.SkydnsDomain, gConfig.SkydnsApi.ApiAuth, gConfig.General.IpMonitorPath)
	}
	// wait here
	select {}

}
