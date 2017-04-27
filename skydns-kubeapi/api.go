package main

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	skydnsmsg "github.com/ipdcode/skydns/dns-server"
	"github.com/ipdcode/skydns/utils"
	"hash/fnv"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// A subdomain added to the user specified domain for user definded.
	userSubdomain = "user"
	svcSubdomain  = "svc"

	noDomainName           = "ERR, no domain name input "
	errDomainContainDot    = "ERR,  domain name cant not contain dot "
	noFindDomainName       = "ERR, no find  domain name "
	noFindDomainIp         = "ERR, no find  domain ip "
	errDeleteDomainName    = "ERR, delete domain name error"
	errDeleteK8sSvc        = "ERR, can not del k8s svc "
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
}

// a record to etcd
type apiSkydnsRecord struct {
	Host         string `json:"host,omitempty"`
	Dnstype      string `json:"type,omitempty"`
	Ttl          uint32 `json:"ttl,omitempty"`
	Mail         bool   `json:"mail,omitempty"`

	Text string `json:"text,omitempty"`
	//SRV
	Port int `json:"port,omitempty"`
	Priority int `json:"priority,omitempty"`
	Weight int `json:"weight,omitempty"`
}

// a record to etcd for ip monitor
type apiSkydnsIpMonitor struct {
	Status string   `json:"status,omitempty"`
	Ports  []string `json:"ports,omitempty"`
}

type skydnsApi struct {
	etcdClient    *tools.EtcdV3
	domain        string
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
func (a *skydnsApi) setSkydnsRecordHost(name string, ipaddr string, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Host = ipaddr
	svc.Ttl = 30
	svc.Dnstype = dnsType
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
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
		glog.Infof("Err: %s\n", retStr)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) setSkydnsRecordMail(name string, host string, priority int, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Host = host
	svc.Dnstype = dnsType
	svc.Mail = true
	svc.Priority = priority
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
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
		glog.Infof("Err: %s\n", retStr)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) setSkydnsRecordText(name string, text string, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Text = text
	svc.Dnstype = dnsType

	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
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
		glog.Infof("Err: %s\n", retStr)
		return errSetDomainName
	} else {
		return apiSucess
	}
}

func (a *skydnsApi) updateSkydnsRecord(name string, preVal string, newVal string, dnsType string) string {
	var svc apiSkydnsRecord
	svc.Host = newVal
	svc.Dnstype = dnsType
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errUpdateDomainName
	}
	recordNew := string(b)

	glog.V(2).Infof("updateSkydnsRecord :%s", skydnsmsg.DnsPath(name))

	err = a.etcdClient.Update(skydnsmsg.DnsPath(name), recordNew)

	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errUpdateDomainName
	} else {
		return apiSucess
	}
}
func (a *skydnsApi) deleteSkydnsRecord(name string) string {
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

	err = a.etcdClient.Delete(res)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errDeleteDomainName
	}

	return apiSucess
}

func (a *skydnsApi) deleteIpMonitorRecord(ip string) error {
	key := a.ipMonitorPath + ip
	glog.V(2).Infof("deleteIpMonitorRecord :%s", key)
	res, err := a.etcdClient.Get(key, false)
	if err != nil {
		if !strings.HasPrefix(err.Error(), etcdKeyNotFound) {
			return err
		} else {
			return nil
		}

	}
	glog.V(2).Infof("deleteIpMonitorRecord :%s", key)

	err = a.etcdClient.Delete(res)
	time.Sleep(20 * time.Microsecond)
	return err
}

func (a *skydnsApi) writeIpMonitorRecord(ip string) error {
	var status apiSkydnsIpMonitor
	status.Status = "UP"
	b, err := json.Marshal(status)
	if err != nil {
		return err
	}
	recordValue := string(b)
	key := a.ipMonitorPath + ip
	glog.V(2).Infof("writeIpMonitorRecord:%s", key)

	_, err = a.etcdClient.Get(key, true)
	// the key exist
	if err == nil {
		return nil
	}

	if strings.HasPrefix(err.Error(), etcdKeyNotFound) {
		err = a.etcdClient.Set(key, recordValue)
	}
	time.Sleep(20 * time.Microsecond)

	return err
}

func (a *skydnsApi) apiLoopNodes(kv []*mvccpb.KeyValue, sx map[string]apiService) error {

	var record apiSkydnsRecord
	for _, item := range kv {

		if err := json.Unmarshal([]byte(item.Value), &record); err != nil {
			return err
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
			serv.DomainIps = append(serv.DomainIps, record.Host)
			serv.OpsType = "A"
			sx[key] = *serv
		case "CNAME":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.OpsType = "CNAME"
			serv.AliasDomain = record.Host
			sx[key] = *serv
		case "NS":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.OpsType = "NS"
			serv.NsHost = record.Host
			sx[key] = *serv

		case "MX":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
			serv.OpsType = "MX"
			serv.MailHost = record.Host
			serv.MailPriority = record.Priority
			sx[key] = *serv

		case "TXT":
			key := a.getDomainNameFromKey(string(item.Key))
			serv := new(apiService)
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
	return domainKey
}

func (a *skydnsApi) getDomainNameFromKeyA(key string) string {
	keys := strings.Split(key, "/")
	domLen := len(keys) - 1
	for i, j := 0, domLen; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	domainKey := strings.Join(keys[2:domLen-1], ".") // ingoore the first
	return domainKey
}

func (a *skydnsApi) doGetSkydnsRecords(n string, sx map[string]apiService) error {
	r, err := a.etcdClient.Get(skydnsmsg.DnsPath(n), true)
	if err != nil {
		return err
	}
	return a.apiLoopNodes(r.Kvs, sx)
}

func (a *skydnsApi) getSkydnsRecords(name string, opstype string, sx map[string]apiService) error {

	n := ""
	if name != "" {
		n = a.buildDNSNameString(a.domain, name)
		return a.doGetSkydnsRecords(n, sx)

	} else { // show all
		switch strings.ToUpper(opstype) {
		case "NS":
			n = a.buildDNSNameString(a.domain, "ns.dns")
		case "MX":
			n = a.buildDNSNameString(a.domain, "mail")
		case "TXT":
			n = a.buildDNSNameString(a.domain, "txt")
		default:
			n = a.buildDNSNameString(a.domain)
		}
		return a.doGetSkydnsRecords(n, sx)
	}
}

func (a *skydnsApi) processTypeAPost(s *apiService, domain string) string {
	if len(s.DomainIps) == 0 {
		return noDomainIps
	}
	for _, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name := a.buildDNSNameString(a.domain, domain, a.getHashIp(ipaddr))
			ret := a.setSkydnsRecordHost(name, ipaddr, "A")
			if ret != apiSucess {
				return ret
			}
			a.writeIpMonitorRecord(ipaddr)
		default:
			return notSupportIpv6
		}
	}
	return apiSucess
}

func (a *skydnsApi) setSkydnsRecordHostSRV(name string, ipaddr string, port int) string {
	var svc apiSkydnsRecord
	svc.Host = ipaddr
	svc.Ttl = 30
	svc.Port = port
	svc.Priority =10
	svc.Weight   =10
	svc.Dnstype = "SRV"
	b, err := json.Marshal(svc)
	if err != nil {
		glog.Infof("%s\n", err.Error())
		return errSetDomainName
	}
	recordValue := string(b)
	glog.V(2).Infof("setSkydnsRecordHostSRV:%s", skydnsmsg.DnsPath(name))

	err = a.etcdClient.Set(skydnsmsg.DnsPath(name), recordValue)
	time.Sleep(20 * time.Microsecond)

	if err != nil {
		retStr := err.Error()
		if strings.HasPrefix(retStr, etcdKeyalReadyExists) {
			glog.Infof("Err: %s\n", retStr)
			return errSetDomainNameExists + ipaddr
		}
		glog.Infof("Err: %s\n", retStr)
		return errSetDomainName
	} else {
		return apiSucess
	}
}
func (a *skydnsApi) processTypeSRVPost(s *apiService, domain string) string {
	if len(s.DomainIps) == 0 {
		return noDomainIps
	}
	if len(s.Ports) == 0 {
		return noDomainPorts
	}
	if len(s.DomainIps) != len(s.Ports){
		return errIPPortMatch
	}
	for idx, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name := a.buildDNSNameString(a.domain, domain, a.getHashIp(ipaddr))
			ret := a.setSkydnsRecordHostSRV(name, ipaddr, s.Ports[idx])
			if ret != apiSucess {
				return ret
			}
			a.writeIpMonitorRecord(ipaddr)
		default:
			return notSupportIpv6
		}
	}
	return apiSucess
}

func (a *skydnsApi) processTypeADelete(s *apiService, domain string) string {

	name := ""
	ret := ""
	// no ips del all
	if len(s.DomainIps) == 0 {
		svc := make(map[string]apiService)
		err := a.getSkydnsRecords(domain, "A", svc)
		name = a.buildDNSNameString(a.domain, domain)
		ret = a.deleteSkydnsRecord(name)
		if err == nil{
			for _,v := range svc{
				for _,ip := range v.DomainIps{
					a.deleteIpMonitorRecord(ip)
				}
			}
		}
		return ret
	}
	name = a.buildDNSNameString(a.domain, domain)
	_, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
	if err != nil {
		glog.Infof("domain :%s   %s\n",skydnsmsg.DnsPath(name), err.Error())
		if isEtcdNameNotFound(err){
			return noFindDomainName
		}else{
			return errDeleteDomainName
		}
	}
	// check ips
	for _, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(ipaddr))
			_, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
			if err != nil {
				glog.Infof("domain : %s  ### %s\n", skydnsmsg.DnsPath(name),err.Error())
				if isEtcdNameNotFound(err){
					return noFindDomainIp + ipaddr
				}else{
					return err.Error()
				}
			}
		default:
			return notSupportIpv6
		}
	}


	for _, ipaddr := range s.DomainIps {
		ip := net.ParseIP(ipaddr)
		switch {
		case ip == nil:
			return notIpAddr
		case ip.To4() != nil:
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(ipaddr))
			ret = a.deleteSkydnsRecord(name)
			if ret != apiSucess {
				return noFindDomainIp
			}
			a.deleteIpMonitorRecord(ipaddr)

		default:
			return notSupportIpv6
		}
	}
	if ret == apiSucess {
		svc := make(map[string]apiService)
		err := a.getSkydnsRecords(domain, "A", svc)
		if len(svc) == 0 && err == nil {
			name = a.buildDNSNameString(a.domain, domain)
			a.deleteSkydnsRecord(name)
		}
	}
	return apiSucess
}

func (a *skydnsApi) processTypeAPut(s *apiService, domain string) string {
	if len(s.UpdateMap) != 1 {
		return errPutTooManyItems
	}
	for key, val := range s.UpdateMap {
		ipPre := net.ParseIP(key)
		ipNew := net.ParseIP(val)

		if ipPre.To4() != nil && ipNew.To4() != nil {
			// check val exist
			name := a.buildDNSNameString(a.domain, domain, a.getHashIp(val))
			_, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
			if err == nil {
				return errSetDomainNameExists + val
			}
			// check key exist
			name = a.buildDNSNameString(a.domain, domain)
			_, err = a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
			if err != nil {
				if isEtcdNameNotFound(err){
					return noFindDomainName + domain
				}else{
					return err.Error()
				}
			}
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(key))
			_, err = a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
			if err != nil {
				if isEtcdNameNotFound(err){
					return noFindDomainIp + key
				}else{
					return err.Error()
				}
			}

			//del old
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(key))
			ret := a.deleteSkydnsRecord(name)
			if ret != apiSucess {
				return ret
			}
			a.deleteIpMonitorRecord(key)
			// add new
			name = a.buildDNSNameString(a.domain, domain, a.getHashIp(val))
			ret = a.setSkydnsRecordHost(name, val, "A")
			//
			if ret != apiSucess {
				return ret
			}

			a.writeIpMonitorRecord(val)

		} else {
			return notIpAddr
		}
	}
	return apiSucess
}

func (a *skydnsApi) processTypeCnamePut(s *apiService, domain string) string {
	if len(s.UpdateMap) != 1 {
		return errPutTooManyItems
	}
	for key, val := range s.UpdateMap {
		// check key exist
		name := a.buildDNSNameString(a.domain, key)
		svc := make(map[string]apiService)
		a.doGetSkydnsRecords(name, svc)
		if len(svc) == 0 {
			return noFindAliasName + key
		}
		for _, v := range svc {
			if v.OpsType == "CNAME" && v.AliasDomain != domain {
				return noMatchAliasName + key
			}
		}

		// check val exist
		name = a.buildDNSNameString(a.domain, val)
		_, err := a.etcdClient.Get(skydnsmsg.DnsPath(name), true)
		if err == nil {
			return errSetAliasNameExists + val
		}
		name = a.buildDNSNameString(a.domain, key)
		ret := a.deleteSkydnsRecord(name)
		if ret == apiSucess {
			nameNew := a.buildDNSNameString(a.domain, val)
			return a.setSkydnsRecordHost(nameNew, domain, "CNAME")

		}
		return ret
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

func (a *skydnsApi) checkPostExist(name string) bool {
	if a.checkK8sSvcDir(name) {
		return true
	}
	// check k8s namespaces
	k8sNs := a.buildDNSNameString(a.domain, svcSubdomain, name)
	_, err := a.etcdClient.Get(skydnsmsg.DnsPath(k8sNs), true)
	if err == nil {
		return true
	}
	// check user domain set
	userDir := a.buildDNSNameString(a.domain, name)
	_, err = a.etcdClient.Get(skydnsmsg.DnsPath(userDir), true)
	if err == nil {
		return true
	}
	return false
}

func (a *skydnsApi) checkK8sSvcDir(domain string) bool {
	return domain == svcSubdomain
}
func (a *skydnsApi) getReqBody(r *http.Request, s *apiService) {
	result, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	glog.V(4).Infof("api req body :%s\n", result)
	json.Unmarshal([]byte(result), s)
}

func (a *skydnsApi) processDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := strings.ToLower(vars["domain"])
	var s apiService
	a.getReqBody(r, &s)

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}

	a.processLock(domain)
	defer a.processUnlock(domain)

	if a.checkK8sSvcDir(domain) {
		fmt.Fprintf(w, "%s\n", errDeleteK8sSvc)
		return
	}
	ret := ""
	if s.OpsType == "" {
		svc := make(map[string]apiService)
		err := a.getSkydnsRecords(domain, "A", svc)
		name := a.buildDNSNameString(a.domain, domain)
		ret = a.deleteSkydnsRecord(name)
		fmt.Fprintf(w, "%s\n", ret)
		// del ip infos
		if err == nil{
			for _,v := range svc{
				for _,ip := range v.DomainIps{
					glog.Infof("ip =%s\n",ip)
					a.deleteIpMonitorRecord(ip)
				}
			}
		}else{
			glog.Infof("err =%s\n",err)
		}
		return
	}
	switch strings.ToUpper(s.OpsType) {
	case "A":
		fallthrough
	case "SRV":
		ret = a.processTypeADelete(&s, domain)
	case "CNAME":
		name := a.buildDNSNameString(a.domain, domain)
		ret = a.deleteSkydnsRecord(name)
	case "NS":
		name := a.buildDNSNameString(a.domain, "ns.dns", domain)
		ret = a.deleteSkydnsRecord(name)
	case "MX":
		name := a.buildDNSNameString(a.domain, "mail", domain)
		ret = a.deleteSkydnsRecord(name)
	case "TXT":
		name := a.buildDNSNameString(a.domain, "txt", domain)
		ret = a.deleteSkydnsRecord(name)
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n", ret)
}
func (a *skydnsApi) processPost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := strings.ToLower(vars["domain"])
	var s apiService
	a.getReqBody(r, &s)

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}

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
		dot := strings.Split(domain, ".")
		if len(dot) > 1 {
			fmt.Fprintf(w, "%s\n", errDomainContainDot)
			return
		}
		if a.checkPostExist(domain) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists)
			return
		}
		ret = a.processTypeSRVPost(&s, domain)
	case "A":
		// check exitst
		dot := strings.Split(domain, ".")
		if len(dot) > 1 {
			fmt.Fprintf(w, "%s\n", errDomainContainDot)
			return
		}
		if a.checkPostExist(domain) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists)
			return
		}
		ret = a.processTypeAPost(&s, domain)
	case "CNAME":
		if a.checkPostExist(s.DomainAlias) {
			fmt.Fprintf(w, "%s\n", errSetAliasNameExists)
			return
		}
		name := a.buildDNSNameString(a.domain, s.DomainAlias)
		ret = a.setSkydnsRecordHost(name, domain, "CNAME")
	case "NS":
		name := a.buildDNSNameString(a.domain, "ns.dns", domain)
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordHost(name, s.NsHost, "NS")
	case "MX":
		name := a.buildDNSNameString(a.domain, "mail", domain)
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordMail(name, s.MailHost, s.MailPriority, "MX")

	case "TXT":
		name := a.buildDNSNameString(a.domain, "txt", domain)
		if a.checkKeyEtcdExist(name) {
			fmt.Fprintf(w, "%s\n", errSetDomainNameExists+domain)
			return
		}
		ret = a.setSkydnsRecordText(name, s.TxtRecord, "TXT")
	default:
		ret = noOpsType
	}
	fmt.Fprintf(w, "%s\n", ret)
	return
}

func (a *skydnsApi) processPut(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := strings.ToLower(vars["domain"])
	var s apiService
	a.getReqBody(r, &s)

	if domain == "" {
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}

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
		ret = a.processTypeAPut(&s, domain)
	case "CNAME":
		ret = a.processTypeCnamePut(&s, domain)
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
	domain := strings.ToLower(vars["domain"])
	if domain == ""{
		fmt.Fprintf(w, "%s\n", noDomainName)
		return
	}
	a.processLock(domain)
	defer a.processUnlock(domain)

	svc := make(map[string]apiService)
	err := a.getSkydnsRecords(domain, "A", svc)

	if len(svc) == 0 && err != nil {
		glog.Infof("domain :%s  ###  %s\n", domain,err.Error())
		if isEtcdNameNotFound(err){
			fmt.Fprintf(w, "%s\n", noFindDomainName)
		}else{
			fmt.Fprintf(w, "%s\n", err.Error())
		}
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
	glog.Infof("s =%s\n", s)

	svc := make(map[string]apiService)
	err := a.getSkydnsRecords("", s.OpsType, svc)

	if len(svc) == 0 && err != nil {
		glog.Infof("%s\n", err.Error())
		fmt.Fprintf(w, "%s\n", errGetDomainName)
		return
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

func (a *skydnsApi) basicAuth(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token == hapi.auth {
			handler.ServeHTTP(w, r)
			return
		}
		fmt.Fprintf(w, "No authorized\n")
	}
}

func RunApi(client *tools.EtcdV3, apiAddr string, domain string, auth string, ipMonitorPath string) {

	_, err := net.Dial("tcp", apiAddr)
	if err == nil {
		glog.Fatalf("the addr is used:%s\n", apiAddr)
	}

	glog.Infof("skydns api run  with addr =%s domain : %s\n", apiAddr, domain)
	hapi.etcdClient = client
	hapi.domain = domain
	hapi.auth = auth
	hapi.ipMonitorPath = ipMonitorPath

	r := mux.NewRouter()
	r.HandleFunc("/skydns/api", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/skydns/api/", hapi.processGetAll).Methods("GET")
	r.HandleFunc("/skydns/api/{domain}", hapi.processGet).Methods("GET")
	r.HandleFunc("/skydns/api/{domain}", hapi.processDelete).Methods("DELETE")
	r.HandleFunc("/skydns/api/{domain}", hapi.processPost).Methods("POST")
	r.HandleFunc("/skydns/api/{domain}", hapi.processPut).Methods("PUT")

	http.HandleFunc("/", hapi.basicAuth(r))

	go http.ListenAndServe(apiAddr, nil)
}
