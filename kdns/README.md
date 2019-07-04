[Chinese](README.zh_cn.md)

# KDNS

## Introduction

KDNS is a high-performance DNS Server based on DPDK. Do not rely on the database, the user updates the data through the RESTful API.


## How to use

### 1. Compilation

Required  OS release: Centos-7.2 or Centos-7.4.
Make all for the first time, after that make kdns if you just change the DNS code.

```bash
git clone https://github.com/tiglabs/containerdns.git
cd containerdns/kdns
make all
```

### 2. Startup

The default configuration path for KDNS is /etc/kdns/kdns.cfg. An example for kdns.cfg as follows :

EAL configuration reference [DPDK document](http://dpdk.org/doc/guides/testpmd_app_ug/run_app.html#eal-command-line-options).

```vim
[EAL]
cores = 1,3,5,7,9
memory = 1024,1024
mem-channels = 4
 
[NETDEV]
name-prefix = kdns
mode = rss
mbuf-num = 65535
kni-mbuf-num = 8191
rxqueue-len = 1024
txqueue-len = 2048
    
rxqueue-num = 4
txqueue-num = 4

kni-ipv4 = 2.2.2.240
kni-vip = 10.17.9.100

[COMMON]
log-file = /export/log/kdns/kdns.log

fwd-def-addrs = 114.114.114.114:53,8.8.8.8:53
fwd-thread-num = 4
fwd-mode = cache
fwd-timeout = 2
fwd-mbuf-num = 65535

all-per-second = 1000
fwd-per-second = 10
client-num = 10240

web-port = 5500
ssl-enable = no
cert-pem-file = /etc/kdns/server1.pem
key-pem-file = /etc/kdns/server1-key.pem
zones = tst.local,example.com,168.192.in-addr.arpa
```

Reserve huge pages memory:

```bash
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

Load [igb_uio](http://dpdk.org/doc/guides/linux_gsg/linux_drivers.html) module:

```bash
modprobe uio
insmod ./bin/igb_uio.ko
./bin/dpdk-devbind.py --bind=igb_uio kdns
```

Load [rte_kni](http://dpdk.org/doc/guides/linux_gsg/enable_func.html#loading-the-dpdk-kni-kernel-module) module:

```bash
insmod ./bin/rte_kni.ko
```

Start kdns:

```bash
./bin/kdns 
```

## API 

### 1. Add domain datas

```bash
curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"A","zoneName":"example.com","domainName":"chen.example.com","host":"192.168.2.2"}'  'http://127.0.0.1:5500/kdns/domain' 

curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"CNAME","zoneName":"example.com","domainName":"chen.cname.example.com","host":"chen.example.com"}' 'http://127.0.0.1:5500/kdns/domain' 

curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"SRV","zoneName":"example.com","domainName":"_srvtcp._tcp.example.com","host":"chen.example.com","priority":20,"weight":50,"port":8800}'  'http://127.0.0.1:5500/kdns/domain'
```

### 2. query domain datas

```bash
curl -H "Content-Type:application/json;charset=UTF-8" -X GET   'http://127.0.0.1:5500/kdns/perdomain/chen.example.com' 
curl -H "Content-Type:application/json;charset=UTF-8" -X GET   'http://127.0.0.1:5500/kdns/domain' 
```

### 3. statistics api

```bash
curl -H "Content-Type:application/json;charset=UTF-8" -X GET   'http://127.0.0.1:5500/kdns/statistics/get'
```

### 4. add view

```bash
 curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"cidrs":"192.168.0.0/24","viewName":"gz"}'  'http://127.0.0.1:5500/kdns/view' 
```

### 5. add lb info

```bash
 curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"A","zoneName":"example.com","domainName":"chen.example.com","lbMode":1,"host":"1.1.1.1"}'  'http://127.0.0.1:5500/kdns/domain' 
 curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"A","zoneName":"example.com","domainName":"chen.example.com","lbMode":1,"host":"2.2.2.2"}'  'http://127.0.0.1:5500/kdns/domain' 
 curl -H "Content-Type:application/json;charset=UTF-8" -X POST -d '{"type":"A","zoneName":"example.com","domainName":"chen.example.com","lbMode":1,"host":"3.3.3.3"}'  'http://127.0.0.1:5500/kdns/domain' 
```

## Performance

CPU model: Intel(R) Xeon(R) CPU E5-2698 v4 @ 2.20GHz

NIC model: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection

Jmeter version: apache-jmeter-3.1

Test sample:  single domain --- kubernetes.default.svc.skydns.local(10.0.0.1)
              50,000 domains --- random domain name with suffix skydns.local. Among them, 30,000  with one IP, 10,000 with two IPs, and 10,000 with 3-10 IPs (random).


performance data:

![performance](images/dns-performance.png "performance")
