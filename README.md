![image](https://github.com/ipdcode/skydns/blob/master/images/dns_red_640.png)
# SkyDNS
*Version 2.1.0*
SkyDNS is used as internal dns server for k8s cluster. skydns-kubeapi will monitor 
the services in k8s cluster,when the service is created and has been assigend with external ips, 
the user(docker)in cluster can access the service with the domain.
When the domain has mutiple ips, the skydns will radom choose one actived for the user, 
it seems like loadbalance.
Also the skydns offer "session persistence", that means we qury one domain from one user ip,
then the user accessthe domain later, the user will get the same service ip.   

## Components
* `skydns`: the main service to offer dns query.
* `skydns-kubeapi`: monitor the changes of k8s services, and record the change in the etcd. It offered the
   original data for skydns, meanwhille skydns-kubeapi offers the resful api for users to maintain domain records.
* `skydns-apicmd`: it is a shell cmd for user to query\update domain record, it is based on skydns-kubeapi.

## Design Architecture
  ![image](https://github.com/ipdcode/skydns/blob/master/images/skydns_design_architecture.png)

## Setup / Install

Then get and compile SkyDNS:

    go get github.com/ipdcode/skydns
    cd $GOPATH/src/github.com/ipdcode/skydns
    go build -v
	cd $GOPATH/src/github.com/ipdcode/skydns/skydns-kubeapi
	go build -v
	...


## Configuration

### skydns
* `config-file`: read configs from the file, default "/etc/skydns/skydns.conf".
the config file like this:

[Dns]
dns-domain = skydns.local.
dns-addr   = 0.0.0.0:53
nameservers = ""
subDomainServers = ""
cacheSize   = 100000
ip-monitor-path = /hades/monitor/status/

[Log]
log-dir    = /export/log/skydns
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
statsServerAuthToken = @skydns.com
...



### skydns-kubeapi
* `config-file`: read configs from the file, default "/etc/skydns/skydns.conf".
the config file like this:

[General]
domain=hades.local
host = 192.168.169.41
etcd-server = http://127.0.0.1:2379
ip-monitor-path = /hades/monitor/status
log-dir    = /export/log/hades
log-level  = 2
log-to-stdio = false

[Kube2Skydns]
kube-enable = NO

[SkydnsApi]
api-enable = YES
api-address = 127.0.0.1:9003
skydns-auth  = 123456789

### skydns-scanner

* `config-file`: read configs from the file, default "/etc/skydns/skydns-scanner.conf".

the config file like this:
...
[General]
core = 0
enable-check = true
hostname = hostname1
log-dir = /export/log/skydns
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
status-path = /skydns/monitor/status
report-path = /skydns/monitor/report
heart-path = /skydns/monitor/heart
...

### skydns-schedule

* `config-file`: read configs from the file, default "/etc/skydns/skydns-schedule.conf".

the config file like this:
...
[General]
schedule-interval = 60
agent-downtime = 60
log-dir = /export/log/skydns
log-level = 100
hostname = hostname1
force-lock-time = 1800

[Etcd]
etcd-machine = http://127.0.0.1:2379
status-path = /skydns/monitor/status
report-path = /skydns/monitor/report
heart-path = /skydns/monitor/heart
lock-path = /skydns/monitor/lock
...

### skydns-apicmd

* `addr`: skydns api address,such as 127.0.0.1:9001 or form env(SKYDNS_API_ADDR).
* `domain`: the domain to show
* `show`: show one domain
* `list`: show all domains

## Testing

### skydns-apicmd
    export SKYDNS_API_ADDR=127.0.0.1:9001
    export SKYDNS_API_TOKEN=123456789
	
    skydns-apicmd -list	
	domain:                      qiyf-nginx-5.default.svc.skydns.local       val: { type:A  ips:[192.168.19.113] }
	domain:                      qiyf-nginx-9.default.svc.skydns.local       val: { type:A  ips:[192.168.19.120] }
	domain:                      qiyf-nginx-4.default.svc.skydns.local       val: { type:A  ips:[192.168.19.114] }
	domain:                      qiyf-nginx-6.default.svc.skydns.local       val: { type:A  ips:[192.168.19.116] }
	domain:                     qiyf-nginx-14.default.svc.skydns.local       val: { type:A  ips:[192.168.19.125] }
	domain:                     qiyf-nginx-27.default.svc.skydns.local       val: { type:A  ips:[192.168.19.147] }
	domain:                     qiyf-nginx-15.default.svc.skydns.local       val: { type:A  ips:[192.168.19.126] }
	domain:                     qiyf-nginx-19.default.svc.skydns.local       val: { type:A  ips:[192.168.19.13] }
	domain:                     qiyf-nginx-30.default.svc.skydns.local       val: { type:A  ips:[192.168.19.148] }
	domain:                      qiyf-nginx-1.default.svc.skydns.local       val: { type:A  ips:[192.168.19.115] }
	domain:                     qiyf-nginx-10.default.svc.skydns.local       val: { type:A  ips:[192.168.19.121] }
	domain:                     qiyf-nginx-25.default.svc.skydns.local       val: { type:A  ips:[192.168.19.146] }

	
	skydns-apicmd -show qiyf-nginx-5.default
    domain:                      qiyf-nginx-5.default.svc.skydns.local       val: { type:A  ips:[192.168.19.113] }
	
### skydns-kubeapi
    we use curl to test the user api.
####  typeA
	% curl -H "Content-Type:application/json;charset=UTF-8"  -X POST -d '{"type":"A","ips":["192.168.10.1","192.168.10.2","192.168.10.3"]}'  http://127.0.0.1:9001/skydns/api/cctv2?token="123456789"      
    OK
#### typeCname
	% curl -H "Content-Type:application/json;charset=UTF-8"   -X POST -d '{"type":"cname","alias":"tv1"}' http://127.0.0.1:9001/skydns/api/cctv2.skydns.local?token="123456789"  
   OK

### skydns

####  typeA
	% nslookup qiyf-nginx-5.default.svc.skydns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   qiyf-nginx-5.default.svc.skydns.local
	Address: 192.168.19.113

	if the domain have more than one ip, skydns will return a radom one.

	% nslookup cctv2.skydns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.skydns.local
	Address: 192.168.10.3

	 
####  typeCname
	% nslookup tv1.skydns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	tv1.skydns.local    canonical name = cctv2.skydns.local.
	Name:   cctv2.skydns.local
	Address: 192.168.10.3
	
####  monitor
	 If the domain may have multiple ips, then dns-scanner is used to monitor the ips behand the domain. 
	 When the service is not reachable, dns-scanner will change the status of the ip. And the skydns will monitor the ip staus, 
	 when it comes down, skydns will choose a good one.
	 
	 cctv2.skydns.local    ips[192.168.10.1,192.168.10.2,192.168.10.3]
	 
	% nslookup cctv2.skydns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.skydns.local
	Address: 192.168.10.3
	
	% etcdctl get /skydns/monitor/status/192.168.10.3
	{"status":"DOWN"}

	% nslookup cctv2.skydns.local 127.0.0.1
	Server:         127.0.0.1
	Address:        127.0.0.1#53

	Name:   cctv2.skydns.local
	Address: 192.168.10.1
	
	we query the domain cctv2.skydns.local form skydns we get the ip 192.168.10.3, then we shut down the servic, we query the domain again
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
   ![image](https://github.com/ipdcode/skydns/blob/master/images/DNS_performance.png)

## Future

### improve the performance of UDP packets (DNS use UDP)
    Help SkyDNS (DNS) services improve throughput performace with DPDK technology
