package domain

import (
    "time"
    "math/rand"
    "strings"
    "encoding/json"
    "github.com/golang/glog"
    "golang.org/x/net/context"
    "github.com/coreos/etcd/mvcc/mvccpb"
    etcdv3 "github.com/coreos/etcd/clientv3"
    "github.com/tigcode/containerdns/dns-schedule/base"
    string_tools "github.com/tigcode/containerdns/utils/strs"
)

const (
    KEY_NOT_FOUND = "key not found"
)

func SyncJobForDomain() error {
    glog.V(100).Infoln("Sync domain job...")
    if job_domain_response, err1 := base.Schedule.Client.Get(base.GetDnsJobPath(), true); (err1 != nil && err1.Error() != KEY_NOT_FOUND) {
        return err1
    }  else if real_domain_response, err2 := base.Schedule.Client.Get(base.Config.Etcd.DomainPath, true); (err2 != nil  && err2.Error() != KEY_NOT_FOUND ){
        return err2
    } else {
        invalid_domains := make(map[string]string)
        real_domains := make(map[string]string)

        if real_domain_response != nil {
            for _, kv := range real_domain_response.Kvs {
                sub_domain := _generate_real_domain(string(kv.Key))
                real_domains[sub_domain] = string(kv.Key)
            }
        }

        if job_domain_response != nil {
            for _, kv := range job_domain_response.Kvs {
                domain := strings.TrimPrefix(string(kv.Key), base.GetDnsJobPath())
                if _, ok := real_domains[domain]; ok {
                    delete(real_domains, domain)
                } else {
                    invalid_domains[domain] = string(kv.Key)
                }
            }
        }

        glog.V(50).Infoln("New domains:", real_domains)
        glog.V(50).Infoln("Invalid domains:", invalid_domains)

        // add new job to domain job path
        for sub_domain := range real_domains {
            glog.V(50).Infoln("Add new sub domain: ", sub_domain, "to domain job path ", base.GetDnsJobPath())
            assign_task := base.AssignTask{Status: "DOWN", InitTag: 1}
            bytes, _ := json.Marshal(assign_task)
            if err := base.Schedule.Client.Set(base.GetDnsJobPath() + sub_domain, string(bytes)); err != nil {
                glog.Error("Sync new sub domain to report data failed, due to ", err)
                return err
            }
        }

        // delete invalid sub domain from job path
        for sub_domain := range invalid_domains {
            glog.V(50).Infoln("Delete invalid sub domain: ", base.GetDnsJobPath(), sub_domain)
            base.Schedule.Client.DoDelete(base.GetDnsJobPath() + sub_domain)
        }
    }

    return nil
}

func WatchDomainPath() {
    glog.V(100).Infoln("Start watch", base.Config.Etcd.DomainPath, "...")
    ctx := context.Background()
    var watcher etcdv3.WatchChan
    opts := []etcdv3.OpOption{}
    opts = append(opts, etcdv3.WithPrefix())
    opts = append(opts, etcdv3.WithPrevKV())
    watcher = base.Schedule.Client.Watch(ctx, base.Config.Etcd.DomainPath, opts...)

    for wres := range watcher {
        if wres.Err() != nil {
            err := wres.Err()
            glog.Infof("watch chan error: %v  sleep 2s", err)
            time.Sleep(2 * time.Second)
            return
        }
        for _, e := range wres.Events {
            if e.Type == mvccpb.PUT {
                sub_domain := _generate_real_domain(string(e.Kv.Key))
                glog.V(50).Infoln("Discover domain path changed, and init sub domain ", sub_domain)
                assign_task := base.AssignTask{Status: "DONW", InitTag: 1}

                bytes, _ := json.Marshal(assign_task)
                if err := base.Schedule.Client.Set(base.GetDnsJobPath() + sub_domain, string(bytes)); err != nil {
                    if strings.HasPrefix(err.Error(), base.EtcdKeyalReadyExists) {
                        glog.V(0).Infoln(string(e.Kv.Key), "already handled by other schedule-agent")
                    } else {
                        glog.Error("Set job ", base.GetDnsJobPath() + sub_domain, " failed, due to ", err.Error())
                    }
                }
            } else if e.Type == mvccpb.DELETE {
                sub_domain := _generate_real_domain(string(e.Kv.Key))
                glog.V(50).Infoln("Discover domain path change, and delete sub domain key", sub_domain)
                base.Schedule.Client.DoDelete(base.GetDnsJobPath() + sub_domain)
            } else {
                glog.Warningln("Discover unknow domain path change:", e.Type, "-->", string(e.Kv.Key))
            }
        }

    }
}

func updateDnsJob(agent_host, domain string) {
    glog.V(0).Infoln("Schedule subdomain ", domain, " to target host ", agent_host)

    assign_task := base.AssignTask{Status: "DOWN", AgentName: agent_host, UpdateTime: time.Now().Local().Format("2006-01-02 15:04:05"), InitTag: 0}
    bytes, _ := json.Marshal(assign_task)

    if rep, err := base.Schedule.Client.Get(base.GetDnsJobPath() + domain, false); err == nil {
        if update_err := base.Schedule.Client.Update(base.GetDnsJobPath() + domain, string(bytes), string(rep.Kvs[0].Value)); update_err != nil {
            glog.Error("Update domain job to etcd failed, due to ", update_err.Error())
        }
    }
}

func loopJob() (map[string][]string, []string, error) {
    glog.V(100).Infoln("Run loopJob for domain...")
    allocation := make(map[string][]string)
    init_domains := make([]string, 0, 10)

    if response, e := base.Schedule.Client.Get(base.GetDnsJobPath(), true); e == nil {
        for _, kv := range response.Kvs {
            sub_domain := strings.TrimPrefix(string(kv.Key), base.GetDnsJobPath())
            assign_task := base.AssignTask{}
            if e := json.Unmarshal(kv.Value, &assign_task); e != nil {
                glog.Error("Unmarshal domain data from etcd error, due to ", e.Error())
                continue
            }
            if assign_task.InitTag == 1 {
                init_domains = append(init_domains, sub_domain)
            } else if _, ok := allocation[assign_task.AgentName]; !ok {
                allocation[assign_task.AgentName] = make([]string, 0, 10)
                allocation[assign_task.AgentName] = append(allocation[assign_task.AgentName], sub_domain)
            } else {
                allocation[assign_task.AgentName] = append(allocation[assign_task.AgentName], sub_domain)
            }

        }
    } else {
        return nil, nil, e
    }

    return allocation, init_domains, nil
}

func scheduleWaitPool(active_agents, inactive_agents, new_agents, wait_pool []string, allocation map[string][]string) {
    glog.V(100).Infoln("Run scheduleWaitPool with active_agents:", active_agents, "inactive_agents:", inactive_agents, "new_agents:", new_agents, "wait_pool:", wait_pool,
        "allocation:", allocation)

    valid_agents := append(active_agents, new_agents...)
    valid_agents_number := len(valid_agents)

    for _, ip_pool := range allocation {
        wait_pool = append(wait_pool, ip_pool[:]...)
    }

    per := len(wait_pool) / valid_agents_number

    for index, sub_domain := range wait_pool {
        if per == 0 || (index / per) >= len(valid_agents) {
            rand.Seed(int64(time.Now().Nanosecond()))
            agent_hostname := valid_agents[rand.Intn(len(valid_agents))]
            updateDnsJob(agent_hostname, sub_domain)
        } else{
            agent_hostname := valid_agents[index / per]
            updateDnsJob(agent_hostname, sub_domain)
        }
    }
}

func Run() {
    var (
        active_agents, inactive_agents, new_agents, init_domains []string
        allocation map[string][]string
        job_error, heartbeat_error error
    )

    for {
        if lock_failed := base.Schedule.LockDomainKey(); lock_failed != nil {
            glog.Error("Lock failed, due to ", lock_failed.Error())
            time.Sleep(time.Second)
            continue
        }

        if allocation, init_domains, job_error = loopJob(); job_error != nil {
            glog.Error("Get etcd domain job data failed, due to ", job_error.Error())
            base.Schedule.UnlockDomainKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        if active_agents, inactive_agents, new_agents, heartbeat_error = base.LoopAgentHeartBeat(allocation); heartbeat_error != nil {
            if heartbeat_error.Error() == base.EtcdNoAgentWasFound {
                glog.Warning("No agent was found, will waiting")
            } else {
                glog.Error("Get agent heart beat from etcd failed, due to ", heartbeat_error.Error())
            }
            base.Schedule.UnlockDomainKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        if (len(active_agents) + len(new_agents)) == 0 {
            glog.V(0).Infoln("No active scanner-agent, waiting for heartbeat...")
            base.Schedule.UnlockDomainKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        wait_pool := make([]string, 0, 10)
        if len(init_domains) > 0 {
            glog.V(100).Infoln(init_domains, "need to be initialized")
            wait_pool = append(wait_pool, init_domains[:]...)
        }

        scheduleWaitPool(active_agents, inactive_agents, new_agents, wait_pool, allocation)
        base.Schedule.UnlockDomainKey()
        time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
    }
}

func _generate_real_domain(domain string) string {
    domain = string_tools.TrimSlash(domain)
    domain_list := strings.Split(domain, "/")
    // first string is "containerdns", and last string is ip's md5 value, ignore
    real_domain_list := make([]string, len(domain_list)-2)
    for i := len(domain_list)-2; i > 0; i-- {
        real_domain_list[len(domain_list) - 2 - i] = domain_list[i]
    }
    return strings.Join(real_domain_list, ".")
}