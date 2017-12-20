package main

import (
    "flag"
    "net"
    "runtime"
    "time"
    "strings"
    "encoding/json"
    "sync/atomic"
    "github.com/golang/glog"
    "os"
    "gopkg.in/gcfg.v1"
    "github.com/tiglabs/containerdns/utils/ping"
    "github.com/tiglabs/containerdns/utils/etcdv3"
    "strconv"
    "github.com/tiglabs/containerdns/utils/logs"
    "github.com/tiglabs/containerdns/utils/alert-mail"
    "sync"
)

type DomainStatus struct {
    Domain     string
    Status     string
    ChangeDate string
}

type AlertMailBody struct {
    Target string `json:"target"`
    Rule   string `json:"rule"`
    Proto  string `json:"proto"`
}

type AgentHeartBeat struct {
    AgentName  string `json:"agent_name"`
    LastReport string `json:"last_report,omitempty"`
}

type StatusData struct {
    Status string    `json:"status"`
    Ports  []string  `json:"ports,omitempty"`
}

type AssignTask struct {
    AgentName  string `json:"agent_name"`
    UpdateTime string `json:"update_time,omitempty"`
    InitTag    int    `json:"init_data,omitempty"`
    Status     string    `json:"status"`
}

type ScannerConfig struct {
    General GeneralConfig
    Check   CheckConfig
    Etcd    EtcdConfig
    Mail    MailConfig
}

type GeneralConfig struct {
    Core              int `gcfg:"core"`
    EnableCheck       bool `gcfg:"enable-check"`
    LogDir            string `gcfg:"log-dir"`
    LogLevel          string `gcfg:"log-level"`
    HostName          string `gcfg:"hostname"`
    HeartbeatInterval int `gcfg:"heartbeat-interval"`
    Delay             int `gcfg:"delay"`
}

type CheckConfig struct {
    CheckInteval      int `gcfg:"check-interval"`
    CheckTimeout      int `gcfg:"check-timeout"`
    CheckRetryCount   int `gcfg:"check-retry-count"`
    DefaultScannPorts string `gcfg:"default-scann-ports"`
    PingTimeOut       int `gcfg:"ping-timeout"`
    PingCount         int `gcfg:"ping-count"`
    MaxThread         int `gcfg:"max-thread"`
}

type EtcdConfig struct {
    EtcdServers string `gcfg:"etcd-servers"`
    StatusPath  string `gcfg:"status-path"`
    JobPath     string `gcfg:"job-path"`
    AgentPath   string `gcfg:"agent-path"`
}

type MailConfig struct {
    AlertTo     string `gcfg:"alert-to"`
    SysIdx      int `gcfg:"sys-idx"`
    SilentTime  int `gcfg:"silent-time"`
    ServiceRoot string `gcfg:"service-room"`
}

var (
    configfile string
    runningThread int64 = 0
    config *ScannerConfig
    client *etcdv3.EtcdV3
    channelIpAddress = make(chan string)
    chanelActiveIpAddress = make(chan string)
    chaneFailIpAddress = make(chan string)

    channelSubDomain = make(chan string)
    chanelActiveSubDomain = make(chan string)
    chaneFailSubDomain = make(chan string)

    domainStatusMap = make(map[string]DomainStatus)
    ipaddrStatusMap = make(map[string]DomainStatus)
    mutex sync.Mutex
)

const (
    STATUS_UP = "UP"
    STATUS_DOWN = "DOWN"
    ETCD_KEY_EXISTS = "key exists"
)

func init() {
    flag.StringVar(&configfile, "config-file", "/etc/containerdns/containerdns-scanner.conf", "read config from the file")
    flag.Parse()
    var e error; if config, e = readConfig(configfile); e != nil {
        glog.Fatal("Read config file error, due to", e.Error())
        os.Exit(1)
    }
    flag.Lookup("log_dir").Value.Set(config.General.LogDir)
    flag.Lookup("v").Value.Set(config.General.LogLevel)
    logs.InitLogs(config.General.LogDir, config.General.LogLevel, "false")
    client = newClient(strings.Split(config.Etcd.EtcdServers, ","))
}

func readConfig(configPath string) (*ScannerConfig, error) {

    cfg := new(ScannerConfig)
    if config, err := os.Open(configPath); err != nil {
        glog.Fatalf("Couldn't open scanner configuration %s: %#v", configPath, err)
        return nil, err
    } else {
        defer config.Close()
        return cfg, gcfg.ReadInto(cfg, config)
    }
}

func _get_ip_address_by_job_key(key string) string {
    i := strings.Split(key, "/")
    return i[len(i) - 1]
}

func loopIpAddress() ([]string, error) {
    glog.V(50).Infoln("Loop jobs for ip_address in path ", GetIpaddressJobPath())
    if response, err := client.Get(GetIpaddressJobPath(), true); err == nil {
        ip_addresses := make([]string, 0, 10)
        for _, kv := range response.Kvs {
            glog.V(100).Infoln("Get job data ", string(kv.Key), "-->", string(kv.Value))
            ip_address := _get_ip_address_by_job_key(string(kv.Key))
            assign_task := AssignTask{}
            if e := json.Unmarshal([]byte(kv.Value), &assign_task); e != nil {
                glog.Error("Unmarshal report data from etcd error, due to ", e.Error())
                continue
            }
            if assign_task.AgentName == config.General.HostName {
                ip_addresses = append(ip_addresses, ip_address)
                go func() {
                    glog.V(100).Infoln("Write ip ", ip_address, " to channelIpAddress")
                    channelIpAddress <- ip_address
                }()
            }
        }
        return ip_addresses, nil
    } else {
        return nil, err
    }
}

func loopSubDomain() ([]string, error) {
    glog.V(50).Infoln("Loop jobs for sub_domain in path ", GetDnsJobPath())
    if response, err := client.Get(GetDnsJobPath(), true); err == nil {
        sub_domains := make([]string, 0, 10)
        for _, kv := range response.Kvs {
            glog.V(100).Infoln("Get domain job data", string(kv.Key), "-->", string(kv.Value))
            sub_domain := strings.TrimPrefix(string(kv.Key), GetDnsJobPath())
            assignTask := AssignTask{}
            if e := json.Unmarshal([]byte(kv.Value), &assignTask); e != nil {
                glog.Error("Unmarshal report data from etcd error, due to ", e.Error())
                continue
            }
            if assignTask.AgentName == config.General.HostName {
                sub_domains = append(sub_domains, sub_domain)
                go func() {
                    glog.V(100).Infoln("Write sub_domain ", sub_domain, "to channel")
                    channelSubDomain <- sub_domain
                }()
            }
        }
        return sub_domains, nil
    } else {
        return nil, err
    }
}

func scannerIpAddr(ipaddress string) {
    glog.V(100).Infoln("Scanning IP", ipaddress)
    var ports []string

    // if not enable check, all target is active
    if !config.General.EnableCheck {
        glog.V(100).Infoln("Disabled check by config file,", ipaddress, "is default active")
        go func() {
            chanelActiveIpAddress <- ipaddress
        }()
        goto scannerSuccess
    }

    if status_response, err := client.Get(GetStatuspath() + ipaddress, false); err != nil {
        glog.Error("get ", ipaddress, " status failed, due to ", err.Error())
    } else {
        status_data := StatusData{}
        if err := json.Unmarshal(status_response.Kvs[0].Value, &status_data); err != nil {
            glog.Error("Unmarshal status data from etcd error, due to ", err.Error())
        }

        if len(status_data.Ports) > 0 {
            ports = status_data.Ports
        } else {
            ports = strings.Split(config.Check.DefaultScannPorts, ",")
        }
    }

    for _, port := range ports {
        for i := 0; i < config.Check.CheckRetryCount; i++ {
            tcpaddr := ipaddress + ":" + port
            if conn, err := net.DialTimeout("tcp", tcpaddr, time.Second * time.Duration(config.Check.CheckTimeout)); err == nil {
                conn.Close()
                go func() {
                    chanelActiveIpAddress <- ipaddress
                }()
                goto scannerSuccess
            } else {
                glog.Warningln("telnet " + ipaddress + ":" + port + " timeout...")
                time.Sleep(time.Second * time.Duration(config.Check.CheckInteval))
            }
        }

    }

    // can not connected
    go func() {
        chaneFailIpAddress <- ipaddress
    }()

    scannerSuccess:
    atomic.AddInt64(&runningThread, -1)
}

func scannerSubDomain(sub_domain string) {
    glog.V(100).Infoln("Scanning sub_domain ", sub_domain)

    if !config.General.EnableCheck {
        glog.V(100).Infoln("Disabled check by config file, ", sub_domain, " is default active")
        go func() {
            chanelActiveSubDomain <- sub_domain
        }()
        goto scannerSubdomainSuccess
    }

    for i := 0; i < config.Check.PingCount; i++ {
        var ping_log_sequence string
        if i % 10 == 0 {
            ping_log_sequence = strconv.Itoa(i + 1) + "st"
        } else if i % 10 == 1 {
            ping_log_sequence = strconv.Itoa(i + 1) + "nd"
        } else if i % 10 == 2 {
            ping_log_sequence = strconv.Itoa(i + 1) + "rd"
        } else {
            ping_log_sequence = strconv.Itoa(i + 1) + "th"
        }
        glog.V(100).Infoln("The", ping_log_sequence, "try to ping", sub_domain)

        if ping_result := ping.Do(sub_domain, config.Check.PingTimeOut); ping_result {
            go func() {
                chanelActiveSubDomain <- sub_domain
            }()
            goto scannerSubdomainSuccess
        } else {
            glog.Warningln("ping " + sub_domain + " timeout...")
            time.Sleep(time.Second * time.Duration(config.Check.CheckInteval))
        }
    }

    // can not ping
    go func() {
        chaneFailSubDomain <- sub_domain
    }()

    scannerSubdomainSuccess:
    atomic.AddInt64(&runningThread, -1)
}

func agentHeartReport() {
    glog.V(0).Infoln("Start agent heart-beat by hostname", config.General.HostName)
    heartbeat := AgentHeartBeat{AgentName: config.General.HostName}
    for {
        glog.V(50).Infoln("Heart beat to etcd server by host ", heartbeat.AgentName)
        heartbeat.LastReport = time.Now().Local().Format("2006-01-02 15:04:05")
        bytes, _ := json.Marshal(heartbeat)
        if err := client.Set(GetAgentPath() + config.General.HostName, string(bytes)); err != nil {
            if ETCD_KEY_EXISTS == err.Error() {
                rep, _ := client.Get(GetAgentPath() + config.General.HostName, false)
                client.Update(GetAgentPath() + config.General.HostName, string(bytes), string(rep.Kvs[0].Value))
            } else {
                glog.Error("Write heart beat to etcd error, due to ", err.Error())
            }
        }
        time.Sleep(time.Second * time.Duration(config.General.HeartbeatInterval))
    }
}

func doUpdateIPStatus(ip_address, status string) {
    if status_response, err := client.Get(GetStatuspath() + ip_address, false); err == nil {
        status_data := StatusData{}
        if json_error := json.Unmarshal(status_response.Kvs[0].Value, &status_data); json_error == nil {
            if status_data.Status != status {
                glog.V(0).Infoln("Change ip", ip_address, "status from", status_data.Status, "to", status)
                status_data.Status = status
                bytes, _ := json.Marshal(status_data)
                if err := client.Set(GetStatuspath() + ip_address, string(bytes)); err != nil {
                    if ETCD_KEY_EXISTS == err.Error() {
                        rep, _ := client.Get(GetStatuspath() + ip_address, false)
                        client.Update(GetStatuspath() + ip_address, string(bytes), string(rep.Kvs[0].Value))
                    } else {
                        glog.Error("Write status data to etcd error, due to ", err.Error())
                    }
                }
            }
            if status == STATUS_DOWN {
                if _, ok := ipaddrStatusMap[ip_address]; ok {
                    old_ipaddr_stat := ipaddrStatusMap[ip_address]
                    local, _ := time.LoadLocation("Local")
                    change_time, _ := time.ParseInLocation("2006-01-02 15:04:05", old_ipaddr_stat.ChangeDate, local)
                    now := time.Now().Local()
                    if int(now.Unix() - change_time.Unix()) >= config.Mail.SilentTime {
                        alert_mail_body := AlertMailBody{Target: ip_address, Rule: "interval: " +
                                strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
                        bytes, _ := json.Marshal(alert_mail_body)
                        go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.Mail.ServiceRoot + "]" + " Warning: " + ip_address + " status is down", config.Mail.SysIdx)
                        ipaddrStatusMap[ip_address] = DomainStatus{Domain: ip_address, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
                    }
                } else {
                    ipaddrStatusMap[ip_address] = DomainStatus{Domain: ip_address, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
                    alert_mail_body := AlertMailBody{Target: ip_address, Rule: "interval: " +
                            strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
                    bytes, _ := json.Marshal(alert_mail_body)
                    go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.Mail.ServiceRoot + "]" + " Warning: " + ip_address + " status is down", config.Mail.SysIdx)
                }
            }
        } else {
            glog.Error("Format status response ", status_response.Kvs, " error, due to ", json_error.Error())
        }
    } else {
        glog.Error("Client get ", GetStatuspath() + ip_address, " vaule from etcd failed, due to ", err.Error())
    }
}

func doUpdateDomainStatus(sub_domain, status string) {
    mutex.Lock()
    defer mutex.Unlock()
    if status_response, err := client.Get(GetDnsJobPath() + sub_domain, false); err == nil {
        domain_task := AssignTask{}

        if json_error := json.Unmarshal(status_response.Kvs[0].Value, &domain_task); json_error == nil {
            if domain_task.Status != status {
                glog.V(0).Infoln("Change domain ", sub_domain, " status from ", domain_task.Status, " to ", status)
                domain_task.Status = status
                domain_task.UpdateTime = time.Now().Local().Format("2006-01-02 15:04:05")
                bytes, _ := json.Marshal(domain_task)
                if err := client.Set(GetDnsJobPath() + sub_domain, string(bytes)); err != nil {
                    if ETCD_KEY_EXISTS == err.Error() {
                        rep, _ := client.Get(GetDnsJobPath() + sub_domain, false)
                        client.Update(GetDnsJobPath() + sub_domain, string(bytes), string(rep.Kvs[0].Value))
                    } else {
                        glog.Error("Write dns status key ", GetDnsJobPath() + sub_domain, " to etcd error, due to ", err.Error())
                    }
                }
            }
            if status == STATUS_DOWN {
                if _, ok := domainStatusMap[sub_domain]; ok {
                    old_domain_stat := domainStatusMap[sub_domain]
                    local, _ := time.LoadLocation("Local")
                    change_time, _ := time.ParseInLocation("2006-01-02 15:04:05", old_domain_stat.ChangeDate, local)
                    now := time.Now().Local()
                    if int(now.Unix() - change_time.Unix()) >= config.Mail.SilentTime {
                        alert_mail_body := AlertMailBody{Target: sub_domain, Rule: "interval: " +
                                strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
                        bytes, _ := json.Marshal(alert_mail_body)
                        go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.Mail.ServiceRoot + "]" + " Warning: ping " + sub_domain + " timeout", config.Mail.SysIdx)
                        domainStatusMap[sub_domain] = DomainStatus{Domain: sub_domain, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
                    }
                } else {
                    domainStatusMap[sub_domain] = DomainStatus{Domain: sub_domain, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
                    alert_mail_body := AlertMailBody{Target: sub_domain, Rule: "interval: " +
                            strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
                    bytes, _ := json.Marshal(alert_mail_body)
                    go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.Mail.ServiceRoot + "]" + " Warning: ping " + sub_domain + " timeout", config.Mail.SysIdx)
                }
            }
        } else {
            glog.Error("Format status response ", status_response.Kvs, " error, due to ", json_error.Error())
        }
    } else {
        glog.Error("Client get ", GetDnsJobPath() + "/" + sub_domain, " vaule from etcd failed, due to ", err.Error())
    }
}

func updateJobStatus() {
    glog.V(0).Infoln("Start worker thread to update job status by handle chanels...")
    for {
        select {
        case activeIp := <-chanelActiveIpAddress:
            go doUpdateIPStatus(activeIp, STATUS_UP)
        case failIp := <-chaneFailIpAddress:
            go doUpdateIPStatus(failIp, STATUS_DOWN)
        case active_sub_domain := <-chanelActiveSubDomain:
            go doUpdateDomainStatus(active_sub_domain, STATUS_UP)
        case fail_sub_domain := <-chaneFailSubDomain:
            go doUpdateDomainStatus(fail_sub_domain, STATUS_DOWN)
        }
    }
}

func newClient(machines []string) *etcdv3.EtcdV3 {
    etcdcli := new(etcdv3.EtcdV3)
    err := etcdcli.InitEtcd(machines, "", "", "")
    if err != nil {
        glog.Fatalf("Failed to create etcd client - %v", err)
        os.Exit(1)
    }
    return etcdcli
}

func prepareScanner() {
    glog.V(0).Infoln("Start worker thread to monitor job queues...")
    for {
        select {
        case ipaddress := <- channelIpAddress:
            if runningThread < int64(config.Check.MaxThread) {
                // start worker-thread
                atomic.AddInt64(&runningThread, 1)
                go scannerIpAddr(ipaddress)
            } else {
                glog.Warning("There is ", strconv.FormatInt(runningThread, 10), " running thread, reaches the maximum limit ", strconv.Itoa(config.Check.MaxThread))
                time.Sleep(time.Second)
            }
        case sub_domain := <- channelSubDomain:
            if runningThread < int64(config.Check.MaxThread) {
                // start worker-thread
                atomic.AddInt64(&runningThread, 1)
                go scannerSubDomain(sub_domain)
            } else {
                glog.Warning("There is ", strconv.FormatInt(runningThread, 10), " running thread, reaches the maximum limit ", strconv.Itoa(config.Check.MaxThread))
                time.Sleep(time.Second)
            }

        }
    }
}

func printRunningThread() {
    glog.V(0).Infoln("Start worker thread to print scanner thread numbers interval...")
    for {
        glog.V(50).Infoln("Waiting for", atomic.LoadInt64(&runningThread), "scanner threads end")
        time.Sleep(time.Second * 5)
    }
}

func GetIpaddressJobPath() string {
    if strings.HasSuffix(config.Etcd.JobPath, "/") {
        return config.Etcd.JobPath + "ipaddress/"
    } else {
        return config.Etcd.JobPath + "/ipaddress/"
    }
}

func GetDnsJobPath() string {
    if strings.HasSuffix(config.Etcd.JobPath, "/") {
        return config.Etcd.JobPath + "domain/"
    } else {
        return config.Etcd.JobPath + "/domain/"
    }
}

func GetStatuspath() string {
    if strings.HasSuffix(config.Etcd.StatusPath, "/") {
        return config.Etcd.StatusPath
    } else {
        return config.Etcd.StatusPath + "/"
    }
}

func GetAgentPath() string {
    if strings.HasSuffix(config.Etcd.AgentPath, "/") {
        return config.Etcd.AgentPath
    } else {
        return config.Etcd.AgentPath + "/"
    }
}

func main() {
    if config.General.Core <= 0 {
        glog.V(0).Infoln("Starting containerdns-scanner-agent with", runtime.NumCPU(), "CPUs")
        runtime.GOMAXPROCS(runtime.NumCPU())
    } else {
        glog.V(0).Infoln("Starting containerdns-scanner-agent with", config.General.Core, "CPUs")
        runtime.GOMAXPROCS(config.General.Core)
    }

    // run in background
    go agentHeartReport()
    go printRunningThread()
    go updateJobStatus()
    go prepareScanner()

    for {
        glog.V(50).Infoln("Loop scanner jobs...")

        go func() {
            if _, err := loopIpAddress(); err != nil {
                glog.Error("Loop scanner ip jobs failed, due to ", err.Error())
            }
        }()

        go func() {
            if _, err := loopSubDomain(); err != nil {
                glog.Error("Loop scanner dns jobs failed, due to ", err.Error())
            }
        }()

        // delay should be greater than '(check-interval + check-timeout) * check-retry-count - check-interval '
        glog.V(50).Infoln("Sleep", strconv.Itoa(config.General.Delay), "Seconds")
        time.Sleep(time.Second * time.Duration(config.General.Delay))
    }
}
