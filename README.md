# ContainerDNS

## Introduction
ContainerDNS is used as internal DNS server for k8s cluster, and use DNS library : https://github.com/miekg/dns. containerdns-kubeapi will monitor 
the services in k8s cluster,when the service is created and has been assigned with external ips, 
the user(docker)in cluster can access the service with the domain.
When the domain has multiple ips, the containerdns will choose one actived for the user randomly, 
it seems like a load balancer.
Also the containerdns offer "session persistence", that means we query one domain from one user ip,
then the user access the domain later, the user will get the same service ip.   

## Components
* `containerdns`: the main service to offer DNS query.
* `containerdns-kubeapi`: monitor the changes of k8s services, and record the change in the etcd. It offered the
   original data for containerdns, meanwhille containerdns-kubeapi offers the RESTful api for users to maintain domain records.
* `containerdns-apicmd`: it is a shell cmd for user to query\update domain record, it is based on containerdns-kubeapi.

## Design Architecture
  ![image](https://github.com/ipdcode/containerdns/blob/master/images/ContainerDNS_design_architecture.png)

## Setup / Install

Then get and compile ContainerDNS:

    go get github.com/ipdcode/containerdns
    cd $GOPATH/src/github.com/ipdcode/containerdns
    go build -v
	cd $GOPATH/src/github.com/ipdcode/containerdns/containerdns-kubeapi
	go build -v
	...


## Configuration

### containerdns
* `config-file`: read configs from the file, default "/etc/containerdns/containerdns.conf".
the config file like this:

[Dns]
dns-domain = containerdns.local.
dns-addr   = 0.0.0.0:53
nameservers = ""
subDomainServers = ""
cacheSize   = 100000
ip-monitor-path = /containerdns/monitor/status/

[Log]
log-dir    = /export/log/containerdns
log-level  = 2
log-to-stdio = true

[Etcd]
etcd-servers = http://127.0.0.1:2379
etcd-certfile = ""
etcd-keyfile = ""
etcd-cafile = ""

[Fun]
random-one = false
hone-one  = false

[Stats]

statsServer = 127.0.0.1:9600
statsServerAuthToken = @containerdns.com
...



### containerdns-kubeapi
* `config-file`: read configs from the file, default "/etc/containerdns/containerdns.conf".
the config file like this:

[General]
domain=containerdns.local
host = 192.168.169.41
etcd-server = http://127.0.0.1:2379
ip-monitor-path = /containerdns/monitor/status
log-dir    = /export/log/containerdns
log-level  = 2
log-to-stdio = false

[Kube2Skydns]
kube-enable = NO

[SkydnsApi]
api-enable = YES
api-address = 127.0.0.1:9003
containerdns-auth  = 123456789

### containerdns-scanner

* `config-file`: read configs from the file, default "/etc/containerdns/containerdns-scanner.conf".

the config file like this:
	...
	[General]
	core = 0
	enable-check = true
	hostname = hostname1
	log-dir = /export/log/containerdns
	log-level = 100
	heartbeat-interval = 30
	[Check]
	check-timeout = 2
	check-interval = 10
	scann-ports = 22, 80, 8080
	enable-icmp = true
	ping-timeout = 1000
	ping-count = 2
	[Etcd]
	etcd-machine = http://127.0.0.1:2379
	tls-key =
	tls-pem =
	ca-cert =
	status-path = /containerdns/monitor/status
	report-path = /containerdns/monitor/report
	heart-path = /containerdns/monitor/heart
	...

### containerdns-schedule

* `config-file`: read configs from the file, default "/etc/containerdns/containerdns-schedule.conf".

the config file like this:
	...
	[General]
	schedule-interval = 60
	agent-downtime = 60
	log-dir = /export/log/containerdns
	log-level = 100
	hostname = hostname1
	force-lock-time = 1800
	
	[Etcd]
	etcd-machine = http://127.0.0.1:2379
	status-path = /containerdns/monitor/status
	report-path = /containerdns/monitor/report
	heart-path = /containerdns/monitor/heart
	lock-path = /containerdns/monitor/lock
	...

### containerdns-apicmd

* `addr`: containerdns api address,such as 127.0.0.1:9001 or form env(SKYDNS_API_ADDR).
* `domain`: the domain to show
* `show`: show one domain
* `list`: show all domains

## Testing

### containerdns-apicmd
    export SKYDNS_API_ADDR=127.0.0.1:9001
    export SKYDNS_API_TOKEN=123456789
	
    containerdns-apicmd -list	
	domain:                      qiyf-nginx-5.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.113] }
	domain:                      qiyf-nginx-9.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.120] }
	domain:                      qiyf-nginx-4.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.114] }
	domain:                      qiyf-nginx-6.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.116] }
	domain:                     qiyf-nginx-14.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.125] }
	domain:                     qiyf-nginx-27.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.147] }
	domain:                     qiyf-nginx-15.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.126] }
	domain:                     qiyf-nginx-19.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.13] }
	domain:                     qiyf-nginx-30.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.148] }
	domain:                      qiyf-nginx-1.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.115] }
	domain:                     qiyf-nginx-10.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.121] }
	domain:                     qiyf-nginx-25.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.146] }

	
	containerdns-apicmd -show qiyf-nginx-5.default
    domain:                      qiyf-nginx-5.default.svc.containerdns.local       val: { type:A  ips:[192.168.19.113] }
	
### containerdns-kubeapi
    we use curl to test the user api.
####  typeA
	% curl -H "Content-Type:application/json;charset=UTF-8"  -X POST -d '{"type":"A","ips":["192.168.10.1","192.168.10.2","192.168.10.3"]}'  http://127.0.0.1:9001/containerdns/api/cctv2?token="123456789"      
    OK
#### typeCname
	% curl -H "Content-Type:application/json;charset=UTF-8"   -X POST -d '{"type":"cname","alias":"tv1"}' http://127.0.0.1:9001/containerdns/api/cctv2.containerdns.local?token="123456789"  
   OK

### containerdns

####  typeA
	% nslookup qiyf-nginx-5.default.svc.containerdns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   qiyf-nginx-5.default.svc.containerdns.local
	Address: 192.168.19.113

	if the domain have more than one ip, containerdns will return a radom one.

	% nslookup cctv2.containerdns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.containerdns.local
	Address: 192.168.10.3

	 
####  typeCname
	% nslookup tv1.containerdns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	tv1.containerdns.local    canonical name = cctv2.containerdns.local.
	Name:   cctv2.containerdns.local
	Address: 192.168.10.3
	
####  monitor
	 If the domain may have multiple ips, then dns-scanner is used to monitor the ips behand the domain. 
	 When the service is not reachable, dns-scanner will change the status of the ip. And the containerdns will monitor the ip status, 
	 when it comes down, containerdns will choose a good one.
	 
	 cctv2.containerdns.local    ips[192.168.10.1,192.168.10.2,192.168.10.3]
	 
	% nslookup cctv2.containerdns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.containerdns.local
	Address: 192.168.10.3
	
	% etcdctl get /containerdns/monitor/status/192.168.10.3
	{"status":"DOWN"}

	% nslookup cctv2.containerdns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.containerdns.local
	Address: 192.168.10.1
	
	we query the domain cctv2.containerdns.local form containerdns we get the ip 192.168.10.3, then we shut down the service, we query the domain again
	we get the ip 192.168.10.1.

## Performance Test

### Testing Conditions
#### Physical hardware
    NIC: gigabit ethernet card
 	CPUs: 32
	RAM: 32G
	OS: CentOS-7.2
#### Testing Software
    queryperf

### Test result
   ![image](https://github.com/ipdcode/containerdns/blob/master/images/DNS_performance.png)

## Future

### improve the performance of UDP packets (DNS use UDP)
    Help ContainerDNS (DNS) services improve throughput performace with DPDK technology
