package base

import (
    "time"
    "os"
    "strings"
    "encoding/json"
    "github.com/golang/glog"
    "github.com/ipdcode/containerdns/utils/etcdv3"
    "errors"
    "sync"
)

type AssignTask struct {
    AgentName  string  `json:"agent_name"`
    UpdateTime string  `json:"update_time,omitempty"`
    InitTag    int     `json:"init_data,omitempty"`
    Status     string  `json:"status"`
}

type AgentHeartBeat struct {
    AgentName   string `json:"agent_name"`
    LastReport string `json:"last_report,omitempty"`
}

type ScheduleConfig struct {
    General GeneralConfig
    Etcd    EtcdConfig
}

type GeneralConfig struct {
    ScheduleInteval   int `gcfg:"schedule-interval"`
    AgentDownTime     int `gcfg:"agent-downtime"`
    LogDir            string `gcfg:"log-dir"`
    LogLevel          string `gcfg:"log-level"`
    HostName          string `gcfg:"hostname"`
    ForceLockTime     int `gcfg:"force-lock-time"`
    ScheduleResources string `gcfg:"resources"`
}

type EtcdConfig struct {
    EtcdServers string `gcfg:"etcd-servers"`
    StatusPath  string `gcfg:"status-path"`
    DomainPath  string `gcfg:"domain-path"`
    JobPath     string `gcfg:"job-path"`
    AgentPath   string `gcfg:"agent-path"`
}

type ScheduleClient struct {
    Client *etcdv3.EtcdV3
}

var (
    Schedule ScheduleClient
    Config *ScheduleConfig
    ipaddr_mutex sync.Mutex
    domain_mutex sync.Mutex
)

const (
    EtcdKeyalReadyExists = "key exists"
    EtcdKeyNoFound = "key not found"
    EtcdNoAgentWasFound = "No agent was found"
)

func InitAgent(schedule_config *ScheduleConfig) {
    Config = schedule_config
    Schedule.Client = newClient(strings.Split(Config.Etcd.EtcdServers, ","))
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

func (scheduleClient *ScheduleClient) LockIpAddressKey() (lock_error error) {
    start_time := time.Now().Local()
    for {
        lock_error = scheduleClient.Client.Set(_get_ip_address_lock_path(), Config.General.HostName)
        if lock_error != nil && strings.HasPrefix(lock_error.Error(), EtcdKeyalReadyExists) {
            now := time.Now().Local()
            if (now.Unix() - start_time.Unix()) > int64(Config.General.ForceLockTime) {
                glog.Warningln("Force locking ip_lock...")
                scheduleClient.Client.DoDelete(_get_ip_address_lock_path())
                return scheduleClient.Client.Set(_get_ip_address_lock_path(), Config.General.HostName)
            } else {
                glog.V(50).Infoln("Locked by other schedule-agent, sleep 1s")
                time.Sleep(time.Second)
            }
        } else {
            break
        }
    }
    return lock_error
}

func (scheduleClient *ScheduleClient) UnlockIpAddressKey() {
    ipaddr_mutex.Lock()
    defer ipaddr_mutex.Unlock()
    scheduleClient.Client.DoDelete(_get_ip_address_lock_path())
}

func (scheduleClient *ScheduleClient) LockDomainKey() (lock_error error) {
    start_time := time.Now().Local()
    for {
        lock_error = scheduleClient.Client.Set(_get_domain_lock_path(), Config.General.HostName)
        if lock_error != nil && strings.HasPrefix(lock_error.Error(), EtcdKeyalReadyExists) {
            now := time.Now().Local()
            if (now.Unix() - start_time.Unix()) > int64(Config.General.ForceLockTime) {
                glog.Warningln("Force locking domain_lock...")
                scheduleClient.Client.DoDelete(_get_domain_lock_path())
                return scheduleClient.Client.Set(_get_domain_lock_path(), Config.General.HostName)
            } else {
                glog.V(50).Infoln("Locked by other schedule-agent, sleep 1s")
                time.Sleep(time.Second)
            }
        } else {
            break
        }
    }
    return lock_error
}

func (scheduleClient *ScheduleClient) UnlockDomainKey() {
    domain_mutex.Lock()
    defer domain_mutex.Unlock()
    scheduleClient.Client.DoDelete(_get_domain_lock_path())
}

func LoopAgentHeartBeat(allocation map[string][]string) ([]string, []string, []string, error) {
    if response, err := Schedule.Client.Get(Config.Etcd.AgentPath, true); err == nil {
        active_agents := make([]string, 0, 10)
        inactive_agents := make([]string, 0, 10)
        new_agents := make([]string, 0, 10)

        for _, kv := range response.Kvs {
            glog.V(100).Infoln("Loop heart beat data key:", string(kv.Key), "-->", string(kv.Value))
            agent_heart_beat := AgentHeartBeat{}
            if err := json.Unmarshal(kv.Value, &agent_heart_beat); err != nil {
                glog.Error("Unmarshal heart beat data from etcd error, due to ", err.Error())
                continue
            }

            local, _ := time.LoadLocation("Local")
            heart_time, _ := time.ParseInLocation("2006-01-02 15:04:05", agent_heart_beat.LastReport, local)
            now := time.Now().Local()

            glog.V(50).Infoln("host: ", agent_heart_beat.AgentName, "hearttime: ", heart_time, "now: ", now, ", D-value is", int(now.Unix() - heart_time.Unix()))
            if int(now.Unix() - heart_time.Unix()) <= Config.General.AgentDownTime {
                // active agent
                if _, ok := allocation[agent_heart_beat.AgentName]; ok {
                    active_agents = append(active_agents, agent_heart_beat.AgentName)
                } else {
                    new_agents = append(new_agents, agent_heart_beat.AgentName)
                }

            } else {
                // down agent
                if _, ok := allocation[agent_heart_beat.AgentName]; ok {
                    inactive_agents = append(inactive_agents, agent_heart_beat.AgentName)
                } else {
                    glog.Warningln("Invalid agent", agent_heart_beat.AgentName)
                }
            }
        }
        return active_agents, inactive_agents, new_agents, err

    } else if strings.HasPrefix(err.Error(), EtcdKeyNoFound) {
        return nil, nil, nil, errors.New("No agent was found")
    }else {
        return nil, nil, nil, err
    }
}

func _get_ip_address_lock_path() string {
    if strings.HasSuffix(Config.Etcd.JobPath, "/") {
        return Config.Etcd.JobPath + "ip_lock"
    } else {
        return Config.Etcd.JobPath + "/ip_lock"
    }

}

func _get_domain_lock_path() string {
    if strings.HasSuffix(Config.Etcd.JobPath, "/") {
        return Config.Etcd.JobPath + "domain_lock"
    } else {
        return Config.Etcd.JobPath + "/domain_lock"
    }

}

func GetIpaddressJobPath() string {
    if strings.HasSuffix(Config.Etcd.JobPath, "/") {
        return Config.Etcd.JobPath + "ipaddress/"
    } else {
        return Config.Etcd.JobPath + "/ipaddress/"
    }
}

func GetDnsJobPath() string {
    if strings.HasSuffix(Config.Etcd.JobPath, "/") {
        return Config.Etcd.JobPath + "domain/"
    } else {
        return Config.Etcd.JobPath + "/domain/"
    }
}