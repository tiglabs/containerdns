package main

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	skydnsmsg "github.com/ipdcode/skydns/dns-server"
	"github.com/ipdcode/skydns/utils/etcdv3"
	"github.com/miekg/dns"
	"hash/fnv"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/coreos/etcd/clientv3"
)

const (
	// A subdomain added to the user specified domain for user definded.
	DnsPathPrefix  = "skydns"
	userSubdomain = "user"
	svcSubdomain  = "svc"

	noDomainName           = "ERR, no domain name input "
	noTypeInput            = "ERR, type input "
	notSubDomain           = "ERR, the api not support this domain  "
	userNameNotMatch       = "ERR, user name not match  "
	//errDomainContainDot    = "ERR,  domain name cant not contain dot "
	noFindDomainName       = "ERR, no find  domain name "
	noFindDomainIp         = "ERR, no find  domain ip "
	errDeleteDomainName    = "ERR, delete domain name error"
	errK8sSvc              = "ERR, can not ops k8s svc "
	errSetDomainName       = "ERR, set domain name error "
	errSetDomainNameExists = "ERR, set domain name error  domain exists "
	errPutTooManyItems     = "ERR, put just support  one update one time"
	errSetAliasNameExists  = "ERR, set domain name error  alias exists "
	noFindAliasName        = "ERR, not find   alias name "
	noMatchAliasName       = "ERR, alias name and domain not match "
	errUpdateDomainName    = "ERR, update domain name error "
	errGetDomainName       = "ERR, get domain name error "
	noAuthorization        = "ERR, no Authorization "
	errAuthorization       = "ERR, Authorization error "
	noDomainIps            = "ERR, no domain ips "
	noDomainPorts            = "ERR, no domain ports "
	errIPPortMatch         = "ERR, ips and ports not match "
	notIpAddr              = "ERR, it is not  IP addr "
	notSupportIpv6         = "ERR, ipv6 tbd "
	notSupportOpsType      = "ERR,type not support "
	noOpsType              = "ERR, no type offered "
	errBodyUpdate          = "ERR, no body update "
	apiSucess              = "OK"
)

type apiService struct {
	AliasDomain  string            `json:"alias-domain,omitempty"`
	OpsType      string            `json:"type,omitempty"`
	DomainIps    []string          `json:"ips,omitempty"`
	Ports        []int          `json:"ports,omitempty"`
	DomainAlias  string            `json:"alias,omitempty"`
	UpdateMap    map[string]string `json:"update,omitempty"`
	NsHost       string            `json:"nsHost,omitempty"`
	MailHost     string            `json:"mailHost,omitempty"`
	MailPriority int               `json:"mailPriority,omitempty"`
	TxtRecord    string            `json:"text,omitempty"`
	User    string            `json:"user,omitempty"`
}

// a record to etcd
type apiSkydnsRecord struct {
	Host         string `json:"host,omitempty"`
	Dnstype      string `json:"type,omitempty"`
	RecordSource string `json:"source,omitempty"`
	Ttl          uint32 `json:"ttl,omitempty"`
	Mail         bool   `json:"mail,omitempty"`

	Text string `json:"text,omitempty"`
	//SRV
	Port int `json:"port,omitempty"`
	Priority int `json:"priority,omitempty"`
	Weight int `json:"weight,omitempty"`
	Cluster  string   `json:"cluster,omitempty"`
	User   string `json:"user,omitempty"`
}

// a record to etcd for ip monitor
type apiSkydnsIpMonitor struct {
	Status string   `json:"status,omitempty"`
	Ports  []string `json:"ports,omitempty"`
	Domains  []string `json:"domains,omitempty"`
	Cluster string `json:"cluster,omitempty"`
}

type skydnsApi struct {
	etcdClient    *etcdv3.EtcdV3
	domains     []   string
	auth          string
	ipMonitorPath string
	domainLock[32] sync.Mutex
}

var hapi skydnsApi = skydnsApi{}

func (a *skydnsApi) getHashIp(text string) string {
	h := fnv.New32a()
	h.Write([]byte(text))
	return fmt.Sprintf("%x", h.Sum32())
}

func (a *skydnsApi) buildDNSNameString(labels ...string) string {
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

func isEtcdNameNotFound(err error) bool {
	if err != nil {
		if strings.HasPrefix(err.Error(),"key not found" ) {
			return true
		}
	}
	return false
}
func (a *skydnsApi) setSkydnsRecordHost(name string,user string, ipaddr string, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Host = ipaddr
	svc.Cluster = gClusterName
	svc.Ttl = 30
	svc.User    = user
	svc.Dnstype = dnsType
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s  ## domain = %s\n", err.Error(),name)
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setSkydnsRecordHost:%s", skydnsmsg.DnsPath(name))

	err = a.etcdClient.Set(skydnsmsg.DnsPath(name), recordValue)
	time.Sleep(20 * time.Microsecond)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr, etcdKeyalReadyExists) {
			glog.Infof("domain : %s  #### Err: %s\n",skydnsmsg.DnsPath(name), retStr)
			return errSetDomainNameExists + ipaddr
		}
		glog.Infof("Err: %s  ## domain =%s \n", retStr ,name)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) setSkydnsRecordMail(name string,user string, host string, priority int, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Host = host
	svc.Cluster = gClusterName
	svc.Dnstype = dnsType
	svc.Mail = true
	svc.User    = user
	svc.Priority = priority
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s  ## domain =%s\n", err.Error(),name)
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setSkydnsRecordHost:%s", skydnsmsg.DnsPath(name))

	err = a.etcdClient.Set(skydnsmsg.DnsPath(name), recordValue)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr, etcdKeyalReadyExists) {
			glog.Infof("name :%s ### Err: %s\n", skydnsmsg.DnsPath(name),retStr)
			return errSetDomainNameExists
		}
		glog.Infof("Err: %s ## domain =%s\n", retStr,name)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) setSkydnsRecordText(name string, user string, text string, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Text = text
	svc.Cluster = gClusterName
	svc.Dnstype = dnsType
	svc.User    = user

	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s ## domain =%s\n", err.Error(),name)
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setSkydnsRecordHost:%s", skydnsmsg.DnsPath(name))

	err = a.etcdClient.Set(skydnsmsg.DnsPath(name), recordValue)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr, etcdKeyalReadyExists) {
			glog.Infof("name : %s ##### Err: %s\n", skydnsmsg.DnsPath(name),retStr)
			return errSetDomainNameExists
		}
		glog.Infof("Err: %s domain =%s\n", retStr,name)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) checkDomainUserInfoOk(res *clientv3.GetResponse, user,domain string) bool {
	var record apiSkydnsRecord
	name := ""
	for _, item := range res.Kvs {
		if err := json.Unmarshal([]byte(item.Value), &record); err != nil {
			return false
		}
		switch record.Dnstype{
		case "A","SRV": name = a.getDomainNameFromKeyA(string(item.Key))
		default :       name = a.getDomainNameFromKey(string(item.Key))
		}
		if name == domain && user != record.User {
			return false
		}
	}
	return true
}
func (a *skydnsApi) deleteSkydnsRecord(name ,user string) string {
	res, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
	if err != nil {
		glog.Infof("%s  #####  domain =%s\n", err.Error(),skydnsmsg.DnsPath(name))
		if isEtcdNameNotFound(err){
			return noFindDomainName
		}else{
			return errDeleteDomainName
		}
	}
	glog.V(2).Infof("deleteSkydnsRecord :%s", skydnsmsg.DnsPath(name))
        if !a.checkDomainUserInfoOk(res, user,name){
		return userNameNotMatch
	}
	err = a.etcdClient.Delete(res)
	if err != nil {
		glog.Infof("%s ## domain =%s \n", err.Error(),name)
		return errDeleteDomainName
	}

	return apiSucess
}

func (a *skydnsApi) deleteIpMonitorRecord(ip string, domain string) error {
	var status apiSkydnsIpMonitor
	key := gConfig.General.IpMonitorPath + ip
	i :=0
	res, err := a.etcdClient.Get(key, false)
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
		err = a.etcdClient.Update(key, recordValue,string(res.Kvs[0].Value))
		if err != nil{
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}else{
			setMonitorIpUpdateTime(ip)
		}

	}else{
		glog.V(2).Infof("deleteIpMonitorRecord :%s", key)
		err = a.etcdClient.Delete(res)
	}

errCheck:
	if err != nil {
		if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
			return nil
		} else {
			return err
		}
	}
	time.Sleep(20 * time.Microsecond)
	setMonitorIpUpdateTime(ip)
	return err
}


func (a *skydnsApi) writeIpMonitorRecord(ip string,domain string) error {
	key := gConfig.General.IpMonitorPath + ip
	glog.V(2).Infof("writeIpMonitorRecord:%s", key)

	res, err := a.etcdClient.Get(key, true)
	// the key exist
	if err == nil {
		glog.V(2).Infof(" writeIpMonitorRecord key:%s exist,val: res.Node.Value:%s", key, string(res.Kvs[0].Value))
		if strings.Contains(string(res.Kvs[0].Value),domain){
			return nil
		}
		var status apiSkydnsIpMonitor
		err := json.Unmarshal(res.Kvs[0].Value,&status)
		if err != nil {
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
			return err
		}
		status.Domains = append(status.Domains,domain)

		b, err1 := json.Marshal(status)
		if err1 != nil {
			glog.V(2).Infof(" err =%s  domain =%s\n ",err1,domain)
			return err1
		}
		recordValue := string(b)
		err = a.etcdClient.Update(key, recordValue,string(res.Kvs[0].Value))
		if err != nil{
			glog.V(2).Infof(" err =%s  domain =%s\n ",err,domain)
		}else{
			setMonitorIpUpdateTime(ip)
		}
		return err
	}
	//set
	if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
		var status apiSkydnsIpMonitor
		status.Status = "UP"
		status.Cluster = gClusterName
		status.Domains = append(status.Domains,domain)
		b, err1 := json.Marshal(status)
		if err1 != nil {
			return err1
		}
		recordValue := string(b)
		err = a.etcdClient.Set(key, recordValue)
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
	time.Sleep(20 * time.Microsecond)
	return err
}

func (a *skydnsApi) apiLoopNodes(user string ,kv []*mvccpb.KeyValue, sx map[string]apiService) error {

	var record apiSkydnsRecord
	for _, item := range kv {
		// clear the value
		record = apiSkydnsRecord{}
		if err := json.Unmarshal([]byte(item.Value), &record); err != nil {
			return err
		}
		if user != record.User && user != "k8sSvc"{
			continue
		}
		switch record.Dnstype {
		case "A":
			key := a.getDomainNameFromKeyA(string(item.Key))
			if svc, ok := sx[key]; ok {
				svc.DomainIps = append(svc.DomainIps, record.Host)
				sx[key] = svc
				continue
			}
			serv := new(apiService)
			serv.User = record.User
			serv.DomainIps = append(serv.DomainIps, record.Host)
			serv.OpsType = "A"
			sx[key] = *serv
		case "CNAME":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.User = record.User
			serv.OpsType = "CNAME"
			serv.AliasDomain = record.Host
			sx[key] = *serv
		case "NS":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.User = record.User
			serv.OpsType = "NS"
			serv.NsHost = record.Host
			sx[key] = *serv

		case "MX":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.User = record.User
			serv.OpsType = "MX"
			serv.MailHost = record.Host
			serv.MailPriority = record.Priority
			sx[key] = *serv

		case "TXT":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.User = record.User
			serv.OpsType = "TXT"
			serv.TxtRecord = record.Text
			sx[key] = *serv

		case "SRV":
			key := a.getDomainNameFromKeyA(string(item.Key))
			if svc, ok := sx[key]; ok {
				svc.DomainIps = append(svc.DomainIps, record.Host)
				svc.Ports    = append(svc.Ports, record.Port)
				sx[key] = svc
				continue
			}
			serv := new(apiService)
			serv.User = record.User
			serv.DomainIps = append(serv.DomainIps, record.Host)
			serv.Ports    = append(serv.Ports, record.Port)
			serv.OpsType = "SRV"
			sx[key] = *serv

		default:
			glog.Infof("unknowm type: %s\n", record.Dnstype)
			continue
		}
	}
	return nil
}

func (a *skydnsApi) getDomainNameFromKey(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[1:domLen-1], ".")
	return dns.Fqdn(domainKey)
}

func (a *skydnsApi) getDomainNameFromKeyA(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[2:domLen-1], ".") // ingoore the first
	return dns.Fqdn(domainKey)
}

func (a *skydnsApi) doGetSkydnsRecords(n ,user string, sx map[string]apiService) error {
	r, err := a.etcdClient.Get(skydnsmsg.DnsPath(n), true)
	if err != nil {
		return err
	}
	return a.apiLoopNodes(user,r.Kvs, sx)
}

func (a *skydnsApi) getSkydnsRecords(name ,user string, opstype string, sx map[string]apiService) error {

	switch strings.ToUpper(opstype) {
	case "NS":
		name = a.buildDNSNameString(name, "ns.dns")
	case "MX":
		name = a.buildDNSNameString(name, "mail")
	case "TXT":
		name = a.buildDNSNameString(name, "txt")
	default:
		name = a.buildDNSNameString(name)
	}
	return a.doGetSkydnsRecords(name,user, sx)
}

func (a *skydnsApi) processTypeAPost(s *apiService, domain ,user string) string {
	if len(s.DomainIps) == 0 {
		return noDomainIps
	}
	var keys [] string
	var vals [] string
	for _, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name := a.buildDNSNameString(domain, a.getHashIp(ipaddr))
			keys = append(keys, skydnsmsg.DnsPath(name))
			var svc apiSkydnsRecord
			svc.Host = ipaddr
			svc.Cluster = gClusterName
			svc.Ttl = 30
			svc.Dnstype = "A"
			svc.User    = user
			b, err := json.Marshal(svc)
			if err != nil {
				glog.Infof("%s ## domian =%s \n", err.Error(),name)
				return errSetDomainName
			}
			vals = append(vals, string(b))

		default:
			return notSupportIpv6
		}
	}
	err := a.etcdClient.SetKeys(keys,vals)
	if err != nil{
		glog.Infof("%s ## domain =%s\n", err.Error(),domain)
		return errSetDomainName
	}
	for _, ipaddr := range s.DomainIps {
		a.writeIpMonitorRecord(ipaddr,domain)
	}
	return apiSucess
}

func (a *skydnsApi) processTypeSRVPost(s *apiService, domain ,user string) string {
	if len(s.DomainIps) == 0 {
		return noDomainIps
	}
	if len(s.Ports) == 0 {
		return noDomainPorts
	}
	if len(s.DomainIps) != len(s.Ports){
		return errIPPortMatch
	}
	var keys [] string
	var vals [] string

	for idx, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name := a.buildDNSNameString(domain, a.getHashIp(ipaddr))
			keys = append(keys, skydnsmsg.DnsPath(name))

			var svc apiSkydnsRecord
			svc.Host = ipaddr
			svc.Cluster = gClusterName
			svc.Ttl = 30
			svc.Port = s.Ports[idx]
			svc.Priority =10
			svc.Weight   =10
			svc.Dnstype = "SRV"
			svc.User    = user
			b, err := json.Marshal(svc)
			if err != nil {
				glog.Infof("%s ## domina =%s \n", err.Error(),name)
				return errSetDomainName
			}
			vals = append(vals, string(b))
		default:
			return notSupportIpv6
		}
	}
	err := a.etcdClient.SetKeys(keys,vals)
	if err != nil{
		glog.Infof("%s ## domain =%s\n", err.Error(),domain)
		return errSetDomainName
	}
	for _, ipaddr := range s.DomainIps {
		a.writeIpMonitorRecord(ipaddr,domain)
	}
	return apiSucess
}

func (a *skydnsApi) doProcessTypeADelete(s *apiService, domain, user string) string{
	name := ""
	var keys []string
	for _, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name = a.buildDNSNameString(domain, a.getHashIp(ipaddr))
			keys = append(keys, skydnsmsg.DnsPath(name))
		default:
			return notSupportIpv6
		}
	}
	err := a.etcdClient.DeleteKeys(keys)
	if err != nil {
		glog.Infof("%s  ## domain =%s\n", err.Error(), domain)
		return errDeleteDomainName
	}
	for _, ipaddr := range s.DomainIps {
		a.deleteIpMonitorRecord(ipaddr, domain)
	}
	return apiSucess
}

func (a *skydnsApi) processTypeADelete(s *apiService, domain, user string) string {
	// no ips del all
	var DomainIpsOps     []string
	if len(s.DomainIps) == 0  || s.OpsType == ""{
		svc := make(map[string]apiService)
		err := a.getSkydnsRecords(domain, user, "A", svc)
		if err != nil {
			glog.V(2).Infof("processTypeADelete :%s\n",  err.Error())
			return  err.Error()
		}
		if value, ok :=  svc[domain]; ok {
			if value.User != user{
				glog.V(2).Infof("processTypeADelete %s :%s\n", domain,userNameNotMatch)
				return userNameNotMatch
			}
			DomainIpsOps  = value.DomainIps[:]
		}else{
			glog.V(2).Infof("processTypeADelete %s :%s\n", domain, noFindDomainName)
			return noFindDomainName
		}

	}else{
		res, err := a.etcdClient.Get(skydnsmsg.DnsPath(domain), true)
		if err != nil {
			glog.Infof("domain :%s   %s\n", domain, err.Error())
			if isEtcdNameNotFound(err) {
				return noFindDomainName
			} else {
				return errDeleteDomainName
			}
		}
		if !a.checkDomainUserInfoOk(res, user,domain) {
			return userNameNotMatch
		}
		DomainIpsOps  = s.DomainIps[:]
	}

	// the max is 128 by etcd, so we use for
	for i:=0; i < len(DomainIpsOps); {
		seg := 100
		if i+ 100 > len(DomainIpsOps){
			seg = 	len(DomainIpsOps) - i
		}
		s.DomainIps = DomainIpsOps[i:seg+i]
		i = i + seg
		ret := a.doProcessTypeADelete(s,domain,user)
		if ret != apiSucess{
			return ret
		}
	}
	return apiSucess
}

func (a *skydnsApi) processTypeAPut(s *apiService, domain string, user string) string {
	if len(s.UpdateMap) != 1 {
		return errPutTooManyItems
	}

	res, err := a.etcdClient.Get(skydnsmsg.DnsPath(domain), true)
	if err != nil {
		glog.Infof("domain :%s   %s\n",skydnsmsg.DnsPath(domain), err.Error())
		if isEtcdNameNotFound(err){
			return noFindDomainName
		}else{
			return errUpdateDomainName
		}
	}
	if !a.checkDomainUserInfoOk(res, user,domain){
		return userNameNotMatch
	}

	var keyOld ,keyNew ,valNew string
	var oldIp,newIp string
	for key, val := range s.UpdateMap {
		oldIp = key
		newIp = val
		ipPre := net.ParseIP(key)
		ipNew := net.ParseIP(val)
		if ipPre.To4() != nil && ipNew.To4() != nil {
			// check val exist
			name := a.buildDNSNameString(domain, a.getHashIp(key))
			keyOld = skydnsmsg.DnsPath(name)
			name   =  a.buildDNSNameString(domain, a.getHashIp(val))
			keyNew = skydnsmsg.DnsPath(name)
			var svc apiSkydnsRecord
			svc.Host = val
			svc.Cluster = gClusterName
			svc.Ttl = 30
			svc.Dnstype = "A"
			svc.User  = user
			b, err := json.Marshal(svc)
			if err != nil {
				glog.Infof("%s ## domian =%s\n", err.Error(),name)
				return errSetDomainName
			}
			valNew = string(b)
		} else {
			return notIpAddr
		}
	}
	err = a.etcdClient.DeleteAndSetKey(keyOld ,keyNew ,valNew)
	if err == nil{
		a.deleteIpMonitorRecord(oldIp,domain)
		a.writeIpMonitorRecord(newIp,domain)
		return apiSucess
	}
	return err.Error()
}

func (a *skydnsApi) processTypeCnamePut(s *apiService, domain,user string) string {
	if len(s.UpdateMap) != 1 {
		return errPutTooManyItems
	}
	for key, val := range s.UpdateMap {
		val := dns.Fqdn(val)
		supDomain := a.getSupDomain(val)
		if supDomain == ""{
			return "alias "+notSubDomain
		}
		// check key exist
		name := a.buildDNSNameString(key)
		svc := make(map[string]apiService)
		a.doGetSkydnsRecords(name,user, svc)
		if len(svc) == 0 {
			return noFindAliasName + key
		}
		for _, v := range svc {
			if v.OpsType == "CNAME" && v.AliasDomain != domain {
				return noMatchAliasName + key
			}
		}
		var record apiSkydnsRecord
		record.Host = domain
		record.Ttl = 30
		record.User = user
		record.Cluster = gClusterName
		record.Dnstype = "CNAME"
		b, err := json.Marshal(record)
		if err != nil {
			glog.Infof("%s ## domain =%s \n", err.Error(),domain)
			return errSetDomainName
		}
		err = a.etcdClient.DeleteAndSetKey(skydnsmsg.DnsPath(key) ,skydnsmsg.DnsPath(val) ,string(b))
		if err == nil{
			return apiSucess
		}else{
			return err.Error()

		}

	}
	return apiSucess
}
func (a *skydnsApi) checkKeyEtcdExist(name string) bool {
	_, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
	if err == nil {
		return true
	}
	return false
}

func (a *skydnsApi) checkPostExist(domain,user string) string {
	if a.checkK8sSvcDir(domain) {
		return errK8sSvc
	}
	res, err := a.etcdClient.Get(skydnsmsg.DnsPath(domain), true)
	if err != nil {
		if isEtcdNameNotFound(err) {
			return apiSucess
		} else {
			return err.Error()
		}
	}
	if a.checkDomainUserInfoOk(res,user,domain){
		return apiSucess
	}
	return  userNameNotMatch
}

func (a *skydnsApi) checkK8sSvcDir(domain string) bool {
	for _, k8sDomain := range a.domains {
		if strings.HasSuffix(domain ,svcSubdomain + "."+ k8sDomain){
			return true
		}
	}
	return false
}
func (a *skydnsApi) getReqBody(r *http.Request, s *apiService) {
	result, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	glog.V(4).Infof("api req body :%s\n", result)
	json.Unmarshal([]byte(result), s)
}

func (a *skydnsApi) processDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := dns.Fqdn(strings.ToLower(vars["domain"]))
	var s apiService
	a.getReqBody(r, &s)

	user := r.FormValue("user")

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}
	supDomain := a.getSupDomain(domain)
	if supDomain == ""{
		fmt.Fprintf(w, "%s\n", notSubDomain)
		return
	}
        glog.V(2).Infof("processDelete domain=%s user =%s body %v\n", domain,user,s)

	a.processLock(domain)
	defer a.processUnlock(domain)

	if a.checkK8sSvcDir(domain) {
		fmt.Fprintf(w, "%s\n", errK8sSvc)
		return
	}
	ret := ""
	if s.OpsType == "" {
		ret = a.processTypeADelete(&s, domain, user)
		fmt.Fprintf(w, "%s\n", ret)
		return
	}
	switch strings.ToUpper(s.OpsType) {
	case "A":
		fallthrough
	case "SRV":
		ret = a.processTypeADelete(&s, domain,user)
	case "CNAME":
		ret = a.deleteSkydnsRecord(domain,user)
	case "NS":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString( supDomain,"ns.dns",domain[:lenTmp])
		ret = a.deleteSkydnsRecord(name,user)
	case "MX":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString( supDomain,"mail", domain[:lenTmp])
		ret = a.deleteSkydnsRecord(name,user)
	case "TXT":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString( supDomain,"txt", domain[:lenTmp])
		ret = a.deleteSkydnsRecord(name,user)
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n", ret)
}
func (a *skydnsApi) processPost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := dns.Fqdn(strings.ToLower(vars["domain"]))
	var s apiService
	a.getReqBody(r, &s)

	user := r.FormValue("user")

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}
	supDomain := a.getSupDomain(domain)
	if supDomain == ""{
		fmt.Fprintf(w, "%s\n", notSubDomain)
		return
	}
	glog.V(2).Infof("processPost domain=%s user =%s body %v\n", domain,user,s)

	a.processLock(domain)
	defer a.processUnlock(domain)

	if "" == s.OpsType {
		fmt.Fprintf(w, "%s\n", notSupportOpsType)
		return
	}

	ret := ""
	switch strings.ToUpper(s.OpsType) {
	case "SRV":
		// check exitst
		ret = a.checkPostExist(domain,user)
		if apiSucess != ret {
			fmt.Fprintf(w, "%s\n", ret)
			return
		}
		ret = a.processTypeSRVPost(&s, domain,user)
	case "A":
		ret = a.checkPostExist(domain,user)
		if apiSucess != ret {
			fmt.Fprintf(w, "%s\n", ret)
			return
		}
		ret = a.processTypeAPost(&s, domain,user)
	case "CNAME":
		alias := dns.Fqdn(s.DomainAlias)
		supDomain := a.getSupDomain(alias)
		if supDomain == ""{
			fmt.Fprintf(w, "alias %s \n", notSubDomain)
			return
		}
		ret = a.checkPostExist(domain,user)
		if apiSucess != ret {
			fmt.Fprintf(w, "%s\n", ret)
			return
		}
		ret = a.setSkydnsRecordHost(alias,user, domain, "CNAME")
	case "NS":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString(supDomain,"ns.dns", domain[:lenTmp])
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordHost(name, user, s.NsHost, "NS")
	case "MX":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString(supDomain,"mail", domain[:lenTmp])
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordMail(name, user, s.MailHost, s.MailPriority, "MX")

	case "TXT":
		lenTmp := len(domain) - len(supDomain)-1
		name := a.buildDNSNameString(supDomain,"txt", domain[:lenTmp])
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordText(name,user, s.TxtRecord, "TXT")
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n", ret)
	return
}

func (a *skydnsApi) processPut(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := dns.Fqdn(strings.ToLower(vars["domain"]))
	var s apiService
	a.getReqBody(r, &s)
	user := r.FormValue("user")

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}
	supDomain := a.getSupDomain(domain)
	if supDomain == ""{
		fmt.Fprintf(w, "%s\n", notSubDomain)
		return
	}

	glog.V(2).Infof("processPost domain=%s user =%s body %v\n", domain,user,s)

	a.processLock(domain)
	defer a.processUnlock(domain)

	if "" == s.OpsType {
		fmt.Fprintf(w, "%s\n", notSupportOpsType)
		return
	}
	if len(s.UpdateMap) == 0 {
		fmt.Fprintf(w, "%s\n", errBodyUpdate)
		return
	}
	ret := ""
	switch strings.ToUpper(s.OpsType) {
	case "A":
		ret = a.processTypeAPut(&s, domain,user)
	case "CNAME":
		ret = a.processTypeCnamePut(&s, domain,user)
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n", ret)
	return

}
func (a *skydnsApi) processLock(domain string) {
	h := fnv.New32a()
	h.Write([]byte(domain))
	idx := int(h.Sum32()) & 0x1f
	a.domainLock[idx].Lock()
}
func (a *skydnsApi) processUnlock(domain string) {
	h := fnv.New32a()
	h.Write([]byte(domain))
	idx := int(h.Sum32()) & 0x1f
	a.domainLock[idx].Unlock()
}
func (a *skydnsApi) processGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := dns.Fqdn(strings.ToLower(vars["domain"]))
	if domain == ""{
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}
	supDomain := a.getSupDomain(domain)
	if supDomain == ""{
		fmt.Fprintf(w, "%s\n", notSubDomain)
		return
	}
	opsType := r.FormValue("type")
	if supDomain == domain && opsType == ""{
		fmt.Fprintf(w, "%s\n", noTypeInput)
		return
	}

	if opsType == "" {
		opsType = "A"
	}
	user := r.FormValue("user")
	a.processLock(domain)
	defer a.processUnlock(domain)

	svc := make(map[string]apiService)
	err := a.getSkydnsRecords(domain,user, opsType, svc)

	if err != nil {
		glog.Infof("domain :%s  ###  %s\n", domain,err.Error())
		if isEtcdNameNotFound(err){
			fmt.Fprintf(w, "%s\n", noFindDomainName)
		}else{
			fmt.Fprintf(w, "%s\n", err.Error())
		}
		return
	}
	if  len(svc) == 0{
		fmt.Fprintf(w, "%s\n", noFindDomainName)
		return
	}
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("domain :%s  ###  %s\n", domain,err.Error())
		fmt.Fprintf(w, "%s\n", errGetDomainName)
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))
	return
}
func (a *skydnsApi) processGetAll(w http.ResponseWriter, r *http.Request) {
	var s apiService
	a.getReqBody(r, &s)

	user := r.FormValue("user")
	svc := make(map[string]apiService)
	for _,supDomain := range(a.domains){
		err := a.getSkydnsRecords(supDomain,user, s.OpsType, svc)
		if err != nil{
			glog.V(3).Infof("err =%s domain =%s\n",err,supDomain)
		}
	}
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n", errGetDomainName)
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))
	return

}

func (a *skydnsApi) basicCheck(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		user := r.FormValue("user")
		if user == ""{
			fmt.Fprintf(w, "No User info\n")
			return
		}
		if token == hapi.auth {
			handler.ServeHTTP(w, r)
			return
		}else{
			fmt.Fprintf(w, "No authorized\n")
		}
	}
}

func (a *skydnsApi) getSupDomain(name string ) string {
	for _, domain := range a.domains {
		if strings.HasSuffix(name, domain){
			return domain
		}
	}
	return ""
}
func RunApi(client *etcdv3.EtcdV3, apiAddr string, dnsDomains []string, auth string, ipMonitorPath string) {

	_, err := net.Dial("tcp", apiAddr)
	if err == nil {
		glog.Fatalf("the addr is used:%s\n", apiAddr)
	}
	glog.Infof("skydns api run  with addr =%s domain : %s\n", apiAddr, dnsDomains)
	hapi.etcdClient = client
	hapi.domains = dnsDomains[:]
	hapi.auth = auth
	hapi.ipMonitorPath = ipMonitorPath

	r := mux.NewRouter()
	r.HandleFunc("/skydns/api", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/skydns/api/", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/skydns/api/{domain}", hapi.processGet).Methods("GET")
	r.HandleFunc("/skydns/api/{domain}", hapi.processDelete).Methods("DELETE")
	r.HandleFunc("/skydns/api/{domain}", hapi.processPost).Methods("POST")
	r.HandleFunc("/skydns/api/{domain}", hapi.processPut).Methods("PUT")

	http.HandleFunc("/", hapi.basicCheck(r))

	go http.ListenAndServe(apiAddr, nil)
}
