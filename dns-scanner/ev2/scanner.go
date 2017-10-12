package main

import (
    "flag"
    "runtime"
    "time"
    "strings"
    "encoding/json"
    "sync/atomic"
    "github.com/golang/glog"
    "os"
    "github.com/ipdcode/containerdns/utils"
    "github.com/ipdcode/containerdns/utils/etcdv2"
    "strconv"
    "github.com/ipdcode/containerdns/utils/logs"
    "github.com/ipdcode/containerdns/utils/alert-mail"
    "sync"
    "gopkg.in/gcfg.v1"
)

type DomainStatus struct {
    Domain     string
    Status     string
    ChangeDate string
}

type AlertMailBody struct {
    Target string `json:"target"`
    Rule   string `json:"rule"`
}

type ScannerConfig struct {
    General GeneralConfig
    Check   CheckConfig
    Etcd    EtcdConfig
    Mail    MailConfig
}

type GeneralConfig struct {
    LogDir     string `gcfg:"log-dir"`
    LogLevel   string `gcfg:"log-level"`
    Delay      int `gcfg:"delay"`
    MaxThread  int `gcfg:"max-thread"`
    SilentTime int `gcfg:"silent-time"`
    ServiceRoot string `gcfg:"service-room"`
}

type CheckConfig struct {
    CheckInteval int `gcfg:"check-interval"`
    PingTimeOut  int `gcfg:"ping-timeout"`
    PingCount    int `gcfg:"ping-count"`
}

type EtcdConfig struct {
    EtcdMachine string `gcfg:"etcd-machine"`
    DomainPath  string `gcfg:"domain-job-path"`
}

type MailConfig struct {
    AlertTo string `gcfg:"alert-to"`
    SysIdx  int `gcfg:"sys-idx"`
}

var (
    configfile string
    runningThread int64 = 0
    config *ScannerConfig
    client *etcdv2.EtcdV2

    channelSubDomain = make(chan string)
    chanelActiveSubDomain = make(chan string)
    chaneFailSubDomain = make(chan string)
    domain_status_map = make(map[string]DomainStatus)
    mutex sync.Mutex
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
    client = newClient(strings.Split(config.Etcd.EtcdMachine, ","))
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

func _generate_real_domain(domain string) string {
    domain = strings.TrimPrefix(domain, "/")
    domain = strings.TrimSuffix(domain, "/")
    domain_list := strings.Split(domain, "/")
    // first string is "containerdns", and last string is ip's md5 value, ignore
    real_domain_list := make([]string, len(domain_list) - 1)
    for i := len(domain_list) - 1; i > 0; i-- {
        real_domain_list[len(domain_list) - 1 - i] = domain_list[i]
    }
    return strings.Join(real_domain_list[1:], ".")
}

func loopSubDomain(path string) {
    if response, err := client.Get(path, false, true); err == nil {
        if response.Node.Dir {
            for _, node := range response.Node.Nodes {
                loopSubDomain(node.Key)
            }
        } else {
            sub_domain := _generate_real_domain(response.Node.Key)
            channelSubDomain <- sub_domain
        }
    } else {
        glog.Error("loop domain path failed, due to", err.Error())
    }
}

func scannerSubDomain(sub_domain string) {
    glog.V(100).Infoln("Scanning sub_domain", sub_domain)

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
        glog.V(100).Infoln("The", ping_log_sequence, "try ping", sub_domain)

        if ping_result := tools.Ping(sub_domain, config.Check.PingTimeOut); ping_result {
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

func doUpdateDomainStatus(sub_domain, status string) {
    mutex.Lock()
    defer mutex.Unlock()
    domain_status_map_tmp := make(map[string]DomainStatus)
    if _, ok := domain_status_map[sub_domain]; ok {
        old_domain_stat := domain_status_map[sub_domain]
        local, _ := time.LoadLocation("Local")
        heart_time, _ := time.ParseInLocation("2006-01-02 15:04:05", old_domain_stat.ChangeDate, local)
        now := time.Now().Local()
        if status == "DOWN" && int(now.Unix() - heart_time.Unix()) >= config.General.SilentTime {
            alert_mail_body := AlertMailBody{Target: sub_domain, Rule: "interval: " +
                    strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
            bytes, _ := json.Marshal(alert_mail_body)
            go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.General.ServiceRoot + "]" + " Warning: ping " + sub_domain + " timeout", config.Mail.SysIdx)
            glog.V(0).Infoln("Change domain ", sub_domain, " status from ", old_domain_stat.Status, " to ", status)
            domain_stat := DomainStatus{Domain: sub_domain, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
            domain_status_map_tmp[sub_domain] = domain_stat
        }
    } else {
        domain_stat := DomainStatus{Domain: sub_domain, Status: status, ChangeDate: time.Now().Local().Format("2006-01-02 15:04:05")}
        domain_status_map_tmp[sub_domain] = domain_stat
        if status == "DOWN" {
            alert_mail_body := AlertMailBody{Target: sub_domain, Rule: "interval: " +
                    strconv.Itoa(config.Check.CheckInteval * 1000) + ", timeout: " + strconv.Itoa(config.Check.PingTimeOut) + ", max_retry: " + strconv.Itoa(config.Check.PingCount)}
            bytes, _ := json.Marshal(alert_mail_body)
            go alert_mail.AlertMail(config.Mail.AlertTo, string(bytes), "[" + config.General.ServiceRoot + "]" + " Warning: ping " + sub_domain + " timeout", config.Mail.SysIdx)
        }
    }
    domain_status_map = domain_status_map_tmp
}

func updateJobStatus() {
    glog.V(0).Infoln("Start worker thread to update job status by handle chanels...")
    for {
        select {
        case active_sub_domain := <-chanelActiveSubDomain:
            go doUpdateDomainStatus(active_sub_domain, "UP")
        case fail_sub_domain := <-chaneFailSubDomain:
            go doUpdateDomainStatus(fail_sub_domain, "DOWN")
        }
    }
}

func newClient(machines []string) *etcdv2.EtcdV2 {
    etcdcli := new(etcdv2.EtcdV2)
    err := etcdcli.InitEtcd(machines)
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
        case sub_domain := <-channelSubDomain:
            if runningThread < int64(config.General.MaxThread) {
                atomic.AddInt64(&runningThread, 1)
                go scannerSubDomain(sub_domain)
            } else {
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

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    // run in background
    go printRunningThread()
    go updateJobStatus()
    go prepareScanner()

    for {
        glog.V(50).Infoln("Loop scanner jobs...")

        go func() {
            loopSubDomain(config.Etcd.DomainPath)
        }()

        // delay should be greater than '(check-interval + check-timeout) * check-retry-count - check-interval '
        glog.V(50).Infoln("Sleep", strconv.Itoa(config.General.Delay), "Seconds")
        time.Sleep(time.Second * time.Duration(config.General.Delay))
    }
}