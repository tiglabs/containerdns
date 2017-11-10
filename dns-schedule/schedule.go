package main

import (
    "flag"
    "os"
    "github.com/golang/glog"
    "gopkg.in/gcfg.v1"
    "github.com/tigcode/containerdns/utils/logs"
    "github.com/tigcode/containerdns/dns-schedule/base"
    "github.com/tigcode/containerdns/dns-schedule/domain"
    "github.com/tigcode/containerdns/dns-schedule/ipaddr"
    "strings"
    "time"
)

var (
    configfile = ""
    resources map[string]string = make(map[string]string)
    config *base.ScheduleConfig
)

const (
    ResourceIpaddr = "ipaddr"
    ResourceDomain = "domain"
)

func init() {
    flag.StringVar(&configfile, "config-file", "/etc/containerdns/containerdns-schedule.conf", "read config from the file")
    flag.Parse()
    var e error; if config, e = readConfig(configfile); e != nil {
        glog.Fatal("Read config file error, due to", e.Error())
        os.Exit(1)
    }

    for _, resource := range strings.Split(config.General.ScheduleResources, ",") {
        resources[strings.TrimSpace(resource)] = strings.TrimSpace(resource)
    }

    logs.InitLogs(config.General.LogDir, config.General.LogLevel, "false")
    base.InitAgent(config)
}

func readConfig(configPath string) (*base.ScheduleConfig, error) {
    cfg := new(base.ScheduleConfig)
    if config, err := os.Open(configPath); err != nil {
        glog.Error("Couldn't open schedule configuration", configPath, err)
        return nil, err
    } else {
        defer config.Close()
        return cfg, gcfg.ReadInto(cfg, config)
    }
}

func SyncJobPath() error {
    if _, ok := resources[ResourceIpaddr]; ok {
        if e := ipaddr.SyncJobForIpAddress(); e != nil {
            return e
        }
    }

    if _, ok := resources[ResourceDomain]; ok {
        if e := domain.SyncJobForDomain(); e != nil {
            return e
        }
    }

    return nil
}

func WatchJobPath() {
    if _, ok := resources[ResourceIpaddr]; ok {
        glog.V(50).Infoln("start watch job path...")
        go ipaddr.WatchIpaddressPath()
    }

    if _, ok := resources[ResourceDomain]; ok {
        glog.V(50).Infoln("start watch domain path...")
        go domain.WatchDomainPath()
    }
}

func main() {
    glog.V(0).Infoln("Starting containerdns-schedule-agent")

    if err := SyncJobPath(); err != nil {
        glog.Error("Sync report and status path failed, due to ", err.Error())
        glog.Flush()
        os.Exit(1)
    } else {
        WatchJobPath()
    }

    if _, ok := resources[ResourceIpaddr]; ok {
        go ipaddr.Run()
    }

    if _, ok := resources[ResourceDomain]; ok {
        go domain.Run()
    }

    for {
        time.Sleep(time.Second * time.Duration(config.General.ScheduleInteval))
    }
}
