// kube2skydns is a bridge between Kubernetes and containerdns.  It watches the
// Kubernetes master for changes in Services and manifests them into etcd for
//Hedes to serve as DNS records.
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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang/glog"
	skydnsmsg "github.com/tigcode/containerdns/dns-server"
	"github.com/tigcode/containerdns/utils/etcdv3"
	"gopkg.in/gcfg.v1"
	"hash/fnv"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/miekg/dns"
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
	// A subdomain added to the user specified domain for all services.
	serviceSubdomain = "svc"
	podRecordSpec  = "pod"

	argEtcdMutationTimeout = 10 * time.Second

	etcdKeyNotFound      = "key not found"
	etcdKeyalReadyExists = "key exists"

	SkydnsKubeApiVersion = "1.3"
)

var (
	gConfig        *ConfigOps
	configFile     = ""
	gClusterName    = ""
	version        = false
	monitorIpPotrs map[string][]string

	monitorIpUpdate map[string]time.Time
	updateTimeLock sync.Mutex

	syncAllPeriod  time.Duration = 60 * time.Second
        // check 3 times  to del
	syncNeedToDelFromEtcd map[string]int
)
type GeneralOps struct {
	Host   	      string `gcfg:"host"`
	EtcdServer    string `gcfg:"etcd-server"`
	EtcdCertfile    string `gcfg:"etcd-certfile"`
	EtcdKeyfile    string `gcfg:"etcd-keyfile"`
	EtcdCafile    string `gcfg:"etcd-cafile"`
	SyncTime      uint64  `gcfg:"sync-time"`
	IpMonitorPath string `gcfg:"ip-monitor-path"`
	LogDir        string `gcfg:"log-dir"`
	LogLevel      string `gcfg:"log-level"`
	LogStdIo      string `gcfg:"log-to-stdio"`
	ClusterName   string   `gcfg:"cluster-name"`
}
type Kube2DNSOps struct {
	KubeDomain           string `gcfg:"kube-domain"`
	PodEnable            bool   `gcfg:"pod-enable"`
	KubeEnable           bool   `gcfg:"kube-enable"`
	KubeConfigFile       string   `gcfg:"kube-config-file"`
}
type DNSApiOps struct {
	ApiDomains  string `gcfg:"api-domains"`
	ApiAuth   string `gcfg:"containerdns-auth"`
	ApiAddr   string `gcfg:"api-address"`
	ApiEnable bool `gcfg:"api-enable"`
}

type ConfigOps struct {
	General    GeneralOps
	Kube2DNS   Kube2DNSOps
	DNSApi     DNSApiOps
}

type nameNamespace struct {
	name      string
	namespace string
}

type kube2skydns struct {
	// Etcd client.
	etcdClient *etcdv3.EtcdV3
	// DNS domain name.
	domain string
	// Etcd mutation timeout.
	etcdMutationTimeout time.Duration
	// A cache that contains all the services in the system.
	servicesStore  kcache.Store
	endpointsStore kcache.Store
	podsStore kcache.Store
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
			return nil
		} else {
			err = ks.etcdClient.Update(skydnsmsg.DnsPath(subdomain), data,string(res.Kvs[0].Value))
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
	}else{
		glog.V(2).Infof(" writeSkydnsRecord subdomain=%s data:%s\n",subdomain, data)
	}
	return err
}

func (ks *kube2skydns) deleteIpMonitorRecord(ip string, domain string) error {
	var status apiSkydnsIpMonitor
	key := gConfig.General.IpMonitorPath + ip
	res, err := ks.etcdClient.Get(key, false)
	i :=0
	if err != nil {
		goto errCheck
	}
	err = json.Unmarshal(res.Kvs[0].Value,&status)
	if err != nil {
		glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
		return err
	}

	for _, d := range(status.Domains){
		if d == domain{
			break
		}
		i++
	}
	if i >= len(status.Domains){
		glog.V(2).Infof(" del ip :%s  not find  domain =%s status.Domains = %s\n ",ip,domain,status.Domains)
		return nil
	}
	status.Domains = append(status.Domains[:i],status.Domains[i+1:]...)
	if len(status.Domains)>0 {
		b, err := json.Marshal(status)
		if err != nil {
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}
		recordValue := string(b)
		err = ks.etcdClient.Update(key, recordValue,string(res.Kvs[0].Value))
		if err != nil{
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}else{
			setMonitorIpUpdateTime(ip)
		}

	}else{
		glog.V(2).Infof("deleteIpMonitorRecord :%s", key)
		err = ks.etcdClient.Delete(res)
	}
errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
			return nil
		} else {
			return err
		}
	}
	setMonitorIpUpdateTime(ip)
	return err
}
func (ks *kube2skydns) writeIpMonitorRecord(ip string, ports []string,domain string) error {
	key := gConfig.General.IpMonitorPath + ip
	glog.V(4).Infof("writeIpMonitorRecord:%s", key)
	res, err := ks.etcdClient.Get(key, true)
	// the key exist
	if err == nil {
		if strings.Contains(string(res.Kvs[0].Value),domain){
			glog.V(4).Infof(" writeIpMonitorRecord key:%s exist,val: res.Node.Value:%s", key, string(res.Kvs[0].Value))
			return nil
		}
		var status apiSkydnsIpMonitor
		err := json.Unmarshal(res.Kvs[0].Value,&status)
		if err != nil {
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}
		status.Domains = append(status.Domains,domain)
		if len (ports) >0 {
			status.Ports = append(status.Ports,ports...)
		}
		b, err := json.Marshal(status)
		if err != nil {
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}
		recordValue := string(b)
		err = ks.etcdClient.Update(key, recordValue,string(res.Kvs[0].Value))
		if err != nil{
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
		}else{
			glog.V(2).Infof(" writeIpMonitorRecord key:%s val: %s   preValue:%s", key,recordValue, string(res.Kvs[0].Value))
			setMonitorIpUpdateTime(ip)
		}
                return err
	}
	//set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
		var status apiSkydnsIpMonitor
		status.Status = "UP"
		status.Cluster = gClusterName
		status.Ports = ports[:]
		status.Domains = append(status.Domains,domain)
		b, err1 := json.Marshal(status)
		if err1 != nil {
			return err1
		}
		recordValue := string(b)
		err = ks.etcdClient.Set(key, recordValue)
		if err != nil{
			glog.V(2).Infof(" writeIpMonitorRecord key:%s val: %s \n", key,recordValue)
		}
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyalReadyExists) {
			glog.V(4).Infof(" %s \n ", etcdKeyalReadyExists)
			return nil
		} else {
			return err
		}
	}

	setMonitorIpUpdateTime(ip)
	return err
}
func setMonitorIpUpdateTime(ip string){
	updateTimeLock.Lock()
	monitorIpUpdate[ip] = time.Now().Local()
	updateTimeLock.Unlock()
}
func delMonitorIpUpdateTime(ip string,last time.Time){
	updateTimeLock.Lock()
	if val, e := monitorIpUpdate[ip]; e {
		if val.Equal(last){
			delete(monitorIpUpdate,ip)
		}
	}
	updateTimeLock.Unlock()
}
func getMonitorIpUpdateTimes()map[string]time.Time{
	updateTime := make(map[string]time.Time)
	updateTimeLock.Lock()
	for k, v := range monitorIpUpdate {
            updateTime[k] = v
        }
	updateTimeLock.Unlock()
	return updateTime
}
func checkMonitorIpChanged(ip string ,last map[string]time.Time )bool{
	// new add
/*	if _, e := last[ip]; !e {
		return true
	}*/
	updateTimeLock.Lock()
	defer updateTimeLock.Unlock()
	if ti, e := monitorIpUpdate[ip]; e {
		if ti.Equal(last[ip]){
			return false
		}else{
			return true
		}
	}
	return true
}

func getSkydnsMsg(ip string, port int, dnstype string,source string) *skydnsmsg.ServiceRecord {
	return &skydnsmsg.ServiceRecord{
		DnsHost:     ip,
		DnsPort:     port,
		DnsPriority: 10,
		DnsWeight:   10,
		DnsTtl:      30,
		Dnstype:  dnstype,
		RecordSource: source,
		Cluster:     gClusterName,
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
	srv_rec, err := json.Marshal(getSkydnsMsg(cName, int(portNumber), "SRV",serviceSubdomain))
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

	b, err := json.Marshal(getSkydnsMsg(ip, 0, "A",serviceSubdomain))
	if err != nil {
		return err
	}
	recordValue := string(b)
	recordLabel := getHash(recordValue)
	recordKey := buildDNSNameString(subdomain, recordLabel)

	//glog.V(2).Infof("Setting DNS record: %v -> %q, with recordKey: %v\n", subdomain, recordValue, recordKey)
	if err := ks.writeSkydnsRecord(recordKey, recordValue); err != nil {
		return err
	}
	var ports []string
	for i := range service.Spec.Ports {
		port := &service.Spec.Ports[i]
		ports = append(ports, fmt.Sprintf("%d", port.Port))
	}
	ks.writeIpMonitorRecord(ip, ports,subdomain)
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
/*	// Remove existing DNS entry.
	if err := ks.removeDNS(subdomain); err != nil {
		return err
	}*/
	return ks.generateRecordsForHeadlessService(subdomain, e, svc)
}

func (ks *kube2skydns) generateRecordsForHeadlessService(subdomain string, e *kapi.Endpoints, svc *kapi.Service) error {
	for idx := range e.Subsets {
		for subIdx := range e.Subsets[idx].Addresses {
			endpointIP := e.Subsets[idx].Addresses[subIdx].IP
			podHost := e.Subsets[idx].Addresses[subIdx].Hostname
			b, err := json.Marshal(getSkydnsMsg(endpointIP, 0, "A",serviceSubdomain))
			if err != nil {
				return err
			}
			recordValue := string(b)
			recordLabel := ""
			if podHost != ""{
				recordLabel = podHost
			}else{
				recordLabel = getHash(recordValue)
			}

			recordKey := buildDNSNameString(subdomain, recordLabel)

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
			ks.writeIpMonitorRecord(endpointIP, ports,subdomain)
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
			err = ks.deleteIpMonitorRecord(ip,skydnsmsg.DnsPath(name))
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
			glog.V(2).Infof("#####  updateService  new =%s  old: =%s \n", newsvc.Spec.ExternalIPs,oldsvc.Spec.ExternalIPs)
			ks.removeService(oldObj)
			ks.newService(newObj)
			return
		}
		glog.V(4).Infof("ignore updateService this time \n")
	}
}

func newEtcdClient(etcdServer,etcdCertfile,etcdKeyile,etcdCafile string) *etcdv3.EtcdV3 {
	etcdcli := etcdv3.EtcdV3{}
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
	kubeConfig := k8sflag.NewStringFlag(gConfig.Kube2DNS.KubeConfigFile)
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
func (ks *kube2skydns) newPodDomain(obj interface{}) {
	if p, ok := obj.(*kapi.Pod); ok {
		if p.Status.PodIP == ""{
			glog.V(2).Infof("ignore the pod for PodIP is nil : %s\n", p.Name)
			return
		}

		recordKey := ks.genPodrecordNameExt(p)
		b, err := json.Marshal(getSkydnsMsg(p.Status.PodIP, 0, "A",podRecordSpec))
		if err != nil {
			glog.Infof("newPodDomain Marshal err : %s\n  ", recordKey)
			return
		}
		recordValue := string(b)
		if err := ks.writeSkydnsRecord(recordKey, recordValue); err != nil {
			glog.Infof("newPodDomain writeSkydnsRecord %s  err : %s\n  ", recordKey,err)
			return
		}
		ks.writeIpMonitorRecord(p.Status.PodIP,[]string{},ks.genPodrecordName(p))
	}
}
func (ks *kube2skydns) delPodDomain(obj interface{}) {
	if p, ok := obj.(*kapi.Pod); ok {
		if p.Status.PodIP == ""{
			glog.V(2).Infof("ignore the pod for PodIP is nil : %s", p.Name)
			return
		}
		recordKey := ks.genPodrecordNameExt(p)
		if err := ks.removeDNS(recordKey); err != nil {
			glog.Infof("delPodDomain :%s  err: %s\n  ",recordKey, err.Error())
			return
		}
		ks.deleteIpMonitorRecord(p.Status.PodIP,ks.genPodrecordName(p))
	}
}

func (ks *kube2skydns) updatePodDomain(oldObj, newObj interface{}) {
	oldPod, ok1 := oldObj.(*kapi.Pod)
	newPod, ok2 := newObj.(*kapi.Pod)
	if ok1 && ok2 {
		// name or namespace or ip change
		if  oldPod.Status.PodIP != newPod.Status.PodIP || oldPod.Name != newPod.Name || oldPod.Namespace != newPod.Namespace {
			glog.V(2).Infof("#### updatePodDomain  new: %s.%s[%s]  old: %s.%s[%s] \n", newPod.Name,newPod.Namespace,newPod.Status.PodIP,
				oldPod.Name,oldPod.Namespace,oldPod.Status.PodIP)
			ks.delPodDomain(oldObj)
			ks.newPodDomain(newObj)
			return
		}
		glog.V(4).Infof("ignore updateService this time \n")
	}
}

func watchForPods(kubeClient clientset.Interface, ks *kube2skydns) kcache.Store {
	podStore, podController := kcache.NewInformer(
		&kcache.ListWatch{
			ListFunc: func(options kapi.ListOptions) (k8sruntime.Object, error) {
				return kubeClient.Core().Pods(kapi.NamespaceAll).List(options)
			},
			WatchFunc: func(options kapi.ListOptions) (watch.Interface, error) {
				return kubeClient.Core().Pods(kapi.NamespaceAll).Watch(options)
			},
		},
		&kapi.Pod{},
		resyncPeriod,
		kcache.ResourceEventHandlerFuncs{
			AddFunc:    ks.newPodDomain,
			DeleteFunc: ks.delPodDomain,
			UpdateFunc: ks.updatePodDomain,
		},
	)
	go podController.Run(wait.NeverStop)
	return podStore
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

	if gConfig.General.SyncTime > 60  {
		syncAllPeriod = time.Duration(gConfig.General.SyncTime)* time.Second
	}

	// domain
	if gConfig.Kube2DNS.KubeDomain == "" {
		gConfig.Kube2DNS.KubeDomain = "containerdns.local."
	}
	if gConfig.General.Host == "" {
		glog.Fatal("General Host is nil, check config file : ", configFile)
	}
	// ip monitor path
	if gConfig.General.IpMonitorPath == "" {
		gConfig.General.IpMonitorPath = "/containerdns/monitor/status/"
	}

	if !strings.HasSuffix(gConfig.Kube2DNS.KubeDomain, ".") {
		gConfig.Kube2DNS.KubeDomain = fmt.Sprintf("%s.", gConfig.Kube2DNS.KubeDomain)
	}
	if !strings.HasSuffix(gConfig.General.IpMonitorPath, "/") {
		gConfig.General.IpMonitorPath = fmt.Sprintf("%s/", gConfig.General.IpMonitorPath)
	}
	//etcd
	if gConfig.General.EtcdServer == "" {
		glog.Fatal("EtcdServer is nil, check config file : ", configFile)
	}

	// kube
	if gConfig.Kube2DNS.KubeEnable {
		if gConfig.Kube2DNS.KubeConfigFile == ""{
			glog.Fatal("KubeConfigFile is nil, check config file : ",configFile)
		}
	}
	// api
	if gConfig.DNSApi.ApiEnable {

		if gConfig.DNSApi.ApiAddr == "" {
			glog.Fatal("ApiAddr is nil, check config file : ", configFile)
		}
		if gConfig.DNSApi.ApiAuth == "" {
			glog.Fatal("ApiAuth is nil, check config file :", configFile)
		}
	}

	// nor
	if !gConfig.DNSApi.ApiEnable  && !gConfig.Kube2DNS.KubeEnable {
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
			podHost := e.Subsets[idx].Addresses[subIdx].Hostname
			b, err := json.Marshal(getSkydnsMsg(endpointIP, 0, "A",serviceSubdomain))
			if err != nil {
				return
			}
			recordValue := string(b)
			recordLabel := ""
			if podHost != ""{
				recordLabel = podHost
			}else{
				recordLabel = getHash(recordValue)
			}
			recordKey := buildDNSNameString(subdomain, recordLabel)

			//svcMap[skydnsmsg.DnsPath(recordKey)] = recordValue
			srvSvcMap[skydnsmsg.DnsPath(recordKey)] = recordValue

			//srv
			for portIdx := range e.Subsets[idx].Ports {
				endpointPort := &e.Subsets[idx].Ports[portIdx]
				portSegment := buildPortSegmentString(endpointPort.Name, endpointPort.Protocol)
				if portSegment != "" {
					recordKeyReal := buildDNSNameString(subdomain, portSegment, recordLabel)
					srv_rec, err := json.Marshal(getSkydnsMsg(recordKey, int(endpointPort.Port), "SRV",serviceSubdomain))
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
				b, err := json.Marshal(getSkydnsMsg(ip, 0, "A",serviceSubdomain))
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

func (ks *kube2skydns) genPodrecordName(s *kapi.Pod) string {
	return buildDNSNameString(ks.domain,"svc",s.Namespace,s.Name)
}
func (ks *kube2skydns) genPodrecordNameExt(s *kapi.Pod) string {
	return buildDNSNameString(ks.domain,"svc",s.Namespace,s.Name,"ip")
}


func (ks *kube2skydns) getPodsFromKube() (map[string]string, bool) {
	svcMap := make(map[string]string)
	services := ks.podsStore.List()
	if len(services) == 0 {
		glog.Infof("getServices : list no svcs found\n")
		return svcMap, false
	}
	for _, s := range services {
		if s, ok := s.(*kapi.Pod); ok {
			if s.Status.PodIP =="" {
				continue
			}
			recordKey := ks.genPodrecordNameExt(s)
			b, err := json.Marshal(getSkydnsMsg(s.Status.PodIP, 0, "A",podRecordSpec))
			if err != nil {
				glog.Infof("newPodDomain Marshal err : %s\n  ", recordKey)
				continue
			}
			svcMap[skydnsmsg.DnsPath(recordKey)] = string(b)
		}
	}
	return svcMap,true
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

func (ks *kube2skydns) kubeLoopNodes(choose string,kv []*mvccpb.KeyValue, sx map[string]string, hosts map[string][]string) error {
	var record apiSkydnsRecord
	for _, item := range kv {
		if err := json.Unmarshal([]byte(item.Value), &record); err != nil {
			return err
		}
		if choose != "" && record.RecordSource != choose {
			continue
		}
		if record.Cluster != gClusterName{
			continue
		}
		key := string(item.Key)
		val := string(item.Value)
		switch record.Dnstype {
		case "A":
			sx[key] = val
			hosts[record.Host] = append(hosts[record.Host],getSvcDomainName(key))
		// no use etcd get cannot find _tcp
		case "SRV":
			sx[key] = val
		default:
			continue
		}
	}
	return nil
}
func (ks *kube2skydns) getServicesFromSkydns(name string,choose string, sx map[string]string, hosts map[string][]string) error {
	subdomain := buildDNSNameString(name)

	r, err := ks.etcdClient.Get(skydnsmsg.DnsPath(subdomain), true)
	if err != nil {
		return err
	}

	return ks.kubeLoopNodes(choose,r.Kvs, sx, hosts)

}

func (ks *kube2skydns) ckeckAndDeleteEtcdRecord(name string,valSkydns string){
	num, ckeck := syncNeedToDelFromEtcd[name]
	if !ckeck{
		syncNeedToDelFromEtcd[name] = 2
		return
	}
	num = num -1
	if num ==0{
		glog.V(2).Infof("#### svc  del from containerdns key :%s  val =%s\n", name, valSkydns)
		ks.etcdClient.DoDelete(name)
		delete(syncNeedToDelFromEtcd,name)
	}else{
		syncNeedToDelFromEtcd[name] = num
	}
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
	hostSkydns := make(map[string][]string)
	// just get svc.
	err := ks.getServicesFromSkydns(serviceSubdomain + "." + gConfig.Kube2DNS.KubeDomain,serviceSubdomain, svcSkydns, hostSkydns)
	if err != nil {
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr, etcdKeyNotFound) {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	// srvSvcMap must be set before srv record for all containerdns-allcached
	for key, val := range srvSvcMap {
		glog.V(4).Infof("svc in Kube:: key :%s  val =%s\n", key, val)
		valSkydns, exists := svcSkydns[key]
		if exists {
			if strings.Compare(valSkydns, val) != 0 {
				glog.V(2).Infof("#### svc  key =%s  kubeval =%s skydnsVal =%s\n", key, val, valSkydns)
				ks.etcdClient.Update(key, val, valSkydns)
				//Del record
				if _,exist := syncNeedToDelFromEtcd[key]; exist{
					delete(syncNeedToDelFromEtcd,key)
				}
			}
			continue
		}
		//we add new one
		glog.V(2).Infof("#### svc  set  key :%s  val =%s\n", key, val)
		ks.etcdClient.Set(key, val)
	}

	for key, val := range kubeServices {
		glog.V(4).Infof("svc in Kube:: key :%s  val =%s\n", key, val)
		valSkydns, exists := svcSkydns[key]
		if exists {
			if strings.Compare(valSkydns, val) != 0 {
				glog.V(2).Infof("#### svc  key =%s  kubeval =%s skydnsVal =%s\n", key, val, valSkydns)
				ks.etcdClient.Update(key, val, valSkydns)
				//Del record
				if _,exist := syncNeedToDelFromEtcd[key]; exist{
					delete(syncNeedToDelFromEtcd,key)
				}
			}
			continue
		}
		//we add new one
		glog.V(2).Infof("#### svc  set  key :%s  val =%s\n", key, val)
		ks.etcdClient.Set(key, val)
	}
	// Remove services missing from the update.
	for name, valSkydns := range svcSkydns {
		glog.V(4).Infof("svc in containerdns:: key :%s  val =%s\n", name, valSkydns)
		_, exists1 := kubeServices[name]
		_, exists2 := srvSvcMap[name]
		if !exists1 && !exists2 {
			ks.ckeckAndDeleteEtcdRecord(name,valSkydns)
		}
	}
}


func (ks *kube2skydns) syncPod2Skydns() {
	glog.V(2).Info("Begin syncKube2Skydns...")
	var kubePods map[string]string
	var ok bool
	kubePods, ok = ks.getPodsFromKube()
	if ok != true {
		return
	}
	svcSkydns := make(map[string]string)
	hostSkydns := make(map[string][]string)
	// just get svc.
	err := ks.getServicesFromSkydns(serviceSubdomain + "." + gConfig.Kube2DNS.KubeDomain, podRecordSpec, svcSkydns, hostSkydns)
	if err != nil {
		retStr := err.Error()
		// if key not fond, keep going
		if !strings.HasPrefix(retStr, etcdKeyNotFound) {
			glog.Infof("Err: %s\n", err.Error())
			return
		}
	}
	// srvSvcMap must be set before srv record for all containerdns-allcached
	for key, val := range kubePods {
		glog.V(3).Infof("pod in Kube:: key :%s  val =%s\n", key, val)
		valSkydns, exists := svcSkydns[key]
		if exists {
			if strings.Compare(valSkydns, val) != 0 {
				glog.V(2).Infof("#### pod key =%s  kubeval =%s skydnsVal =%s\n", key, val, valSkydns)
				ks.etcdClient.Update(key, val, valSkydns)
				//Del record
				if _,exist := syncNeedToDelFromEtcd[key]; exist{
					delete(syncNeedToDelFromEtcd,key)
				}
			}
			continue
		}
		//we add new one
		glog.V(2).Infof("#### pod  set  key :%s  val =%s\n", key, val)
		ks.etcdClient.Set(key, val)
	}

	// Remove services missing from the update.
	for name, valSkydns := range svcSkydns {
		glog.V(3).Infof("svc in containerdns:: key :%s  val =%s\n", name, valSkydns)
		_, exists := kubePods[name]
		if !exists {
			ks.ckeckAndDeleteEtcdRecord(name,valSkydns)
		}
	}
}



func checkDomainsSame(domains1,domains2 [] string)bool{
	if len(domains1) != len(domains2){
		return false
	}
	i := 0
	for _,d1:= range(domains1){
		i =0
		for _,d2 := range(domains2){
			if d1== d2{
				break
			}
			i++
		}
		if i >=len(domains2){
			return false
		}
	}
	return true
}

func (ks *kube2skydns) syncSkydnsHostStatus(hostDomins []string) {
	glog.V(2).Info("Begin syncSkydnsHostStatus...")
	// just get svc + user define
	svcSkydns := make(map[string]string)
	hostsSkydns := make(map[string][]string)

	ipUpdateTime := getMonitorIpUpdateTimes()

	for _,domain := range(hostDomins){
		err := ks.getServicesFromSkydns(domain,"", svcSkydns, hostsSkydns)
		if err != nil {
			retStr := err.Error()
			// if key not fond, keep going
			if !strings.HasPrefix(retStr, etcdKeyNotFound) {
				glog.Infof("Err: %s\n", err.Error())
				return
			}
		}
	}

	// get hosts form /containerdns/monitor/status/
	monitorIps := make(map[string] *apiSkydnsIpMonitor)

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
			status := new(apiSkydnsIpMonitor)
			if err := json.Unmarshal([]byte(item.Value), status); err != nil {
				continue
			}
			if status.Cluster != gClusterName{
				continue
			}
			monitorIps[ip] = status
		}
	}

	//update the diffs
	for key, domains := range hostsSkydns {
		glog.V(4).Infof("svcHosts key: %s\n", key)
		if _, e := ipUpdateTime[key]; e {
			if checkMonitorIpChanged(key,ipUpdateTime) {
				continue
			}
		}
		_, exists := monitorIps[key]
		if !exists {
			var status apiSkydnsIpMonitor
			status.Status = "UP"
			status.Cluster = gClusterName
			status.Domains = domains[:]
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
			err = ks.etcdClient.Set(gConfig.General.IpMonitorPath+key, recordValue)
			if err == nil{
				setMonitorIpUpdateTime(key)
			}
		}else{
			if ! checkDomainsSame(domains, monitorIps[key].Domains){
				var status apiSkydnsIpMonitor
				status.Status = monitorIps[key].Status
				status.Cluster = gClusterName
				status.Ports = monitorIps[key].Ports
				status.Domains = domains[:]
				b, err := json.Marshal(status)
				if err != nil {
					glog.Infof("json.Marshal err: %s\n", err.Error())
					return
				}
				preVal, err := json.Marshal(monitorIps[key])
				if err != nil {
					glog.Infof("json.Marshal err: %s\n", err.Error())
					return
				}

				err = ks.etcdClient.Update(gConfig.General.IpMonitorPath+key, string(b),string(preVal))
				if err == nil{
					setMonitorIpUpdateTime(key)
				}
			}
		}
	}

	for key, _ := range monitorIps {
		glog.V(4).Infof("monitorIps key: %s\n", key)
		_, e := ipUpdateTime[key]
		if !e {
			if _, exists := hostsSkydns[key];exists{
				continue
			}
		}else{
			if checkMonitorIpChanged(key,ipUpdateTime){
				continue
			}
		}
		_, exists := hostsSkydns[key]
		if !exists {
			err := ks.etcdClient.DoDelete(gConfig.General.IpMonitorPath + key)
			if err == nil{
				delMonitorIpUpdateTime(key,ipUpdateTime[key])
			}
		}
	}

	for key, val := range ipUpdateTime {
		_, exists := monitorIps[key]
		if !exists {
			delMonitorIpUpdateTime(key,val)
		}
	}

}
func (ks *kube2skydns) svcSyncLoop(period time.Duration) {
	for range time.Tick(period) {
		glog.Infof("svcSyncLoop \n")
		ks.syncKube2Skydns()
	}
}
func (ks *kube2skydns) hostSyncLoop(domains []string,period time.Duration) {

	for range time.Tick(period) {
		glog.Infof("svcSyncLoop \n")
		ks.syncSkydnsHostStatus(domains)
	}
}
func (ks *kube2skydns) podSyncLoop(period time.Duration) {
	for range time.Tick(period) {
		glog.Infof("svcSyncLoop \n")
		ks.syncPod2Skydns()
	}
}
func init() {
	flag.StringVar(&configFile, "config-file", "/etc/containerdns/containerdns-api.conf", "read config from the file")
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
	gClusterName = gConfig.General.ClusterName

}

type kubeApiReg struct {
	Version  string     `json:"version,omitempty"`
	ApiDomains    [] string `json:"api-domains,omitempty"`
	K8sDomain         string `json:"k8s-domain,omitempty"`
	MonitorPath       string     `json:"monitor-path,omitempty"`
	LastTime time.Time `json:"lastTime,omitempty"`
}
func kubeapiRegister(client *etcdv3.EtcdV3){
	var data kubeApiReg
	data.Version = SkydnsKubeApiVersion + ": " + C.GoString(C.build_time())
	data.MonitorPath = gConfig.General.IpMonitorPath

	if  gConfig.Kube2DNS.KubeEnable {
		data.K8sDomain = dns.Fqdn(strings.ToLower(gConfig.Kube2DNS.KubeDomain))

	}
	if  gConfig.DNSApi.ApiEnable {
		for _, domain := range strings.Split(gConfig.DNSApi.ApiDomains, "%") {
			domain = dns.Fqdn(strings.ToLower(domain))
			data.ApiDomains = append(data.ApiDomains, domain)
		}
	}
	for range time.Tick(60 * time.Second) {
		data.LastTime = time.Now().Local()
		b, err := json.Marshal(data)
		if err != nil {
			glog.Infof("%s\n", err.Error())
		}
		recordValue := string(b)

		name := skydnsmsg.DnsPath("apiHost") + gConfig.General.Host
		glog.V(2).Infof("Heartbeat reg key=%s val =%s\n",name,recordValue)
		res,err := client.Get(name,false)
		if err != nil{
			err = client.Set(name, recordValue)
			if err != nil {
				glog.Infof("%s\n", err.Error())
			}
		}else{
			err = client.Update(name, recordValue, string(res.Kvs[0].Value))
			if err != nil {
				glog.Infof("%s\n", err.Error())
			}
		}

	}
}

var VERSION string
func main() {
	if version {
		fmt.Printf("%s\n", SkydnsKubeApiVersion+ ": " + VERSION）
		return
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	logs.InitLogs()
	defer logs.FlushLogs()

	checkConfigOps()

	monitorIpUpdate = make(map[string]time.Time)
	syncNeedToDelFromEtcd = make(map[string]int)

	ks := kube2skydns{
		domain:              gConfig.Kube2DNS.KubeDomain,
		etcdMutationTimeout: argEtcdMutationTimeout,
	}

	ks.etcdClient = newEtcdClient(gConfig.General.EtcdServer,gConfig.General.EtcdCertfile,gConfig.General.EtcdKeyfile,gConfig.General.EtcdCafile)

	if gConfig.Kube2DNS.KubeEnable  {
		glog.Infof("kubernetes serverce to dns enable ")
		kubeClient, err := newKubeClient()
		if err != nil {
			glog.Fatalf("Failed to create a kubernetes client: %v", err)
		}
		ks.servicesStore = watchForServices(kubeClient, &ks)
		time.Sleep(5*time.Second)
		ks.endpointsStore = watchEndpoints(kubeClient, &ks)
		if gConfig.Kube2DNS.PodEnable{
			ks.podsStore = watchForPods(kubeClient, &ks)
		}
		go ks.svcSyncLoop(syncAllPeriod)
		if gConfig.Kube2DNS.PodEnable{
			go ks.podSyncLoop(syncAllPeriod)
		}
	}
	var domains []string
	doMap := make(map[string]bool)
	if  gConfig.Kube2DNS.KubeEnable{
		domain := dns.Fqdn(strings.ToLower(gConfig.Kube2DNS.KubeDomain))
		doMap[domain] = true
	}
	if  gConfig.DNSApi.ApiEnable {
		for _, domain := range strings.Split(gConfig.DNSApi.ApiDomains, "%") {
			domain = dns.Fqdn(strings.ToLower(domain))
			doMap[domain] = true
		}
	}
	for key,_:= range(doMap){
		domains = append(domains,key)
	}
	if gConfig.DNSApi.ApiEnable {
		glog.Infof("containerdns  dns api enable ")
		RunApi(ks.etcdClient, gConfig.DNSApi.ApiAddr, domains, gConfig.DNSApi.ApiAuth, gConfig.General.IpMonitorPath)
	}
	go ks.hostSyncLoop(domains,syncAllPeriod)
	go kubeapiRegister(ks.etcdClient)
	// wait here
	select {}

}
