package ipaddr

import (
    "time"
    "strings"
    "math/rand"
    "encoding/json"
    "github.com/golang/glog"
    "golang.org/x/net/context"
    "github.com/coreos/etcd/mvcc/mvccpb"
    etcdv3 "github.com/coreos/etcd/clientv3"
    "github.com/tiglabs/containerdns/dns-schedule/base"
)

const (
    KEY_NOT_FOUND = "key not found"
)

func _get_ip_address_by_job_key(key string) string {
    i := strings.Split(key, "/")
    return i[len(i) - 1]
}

func SyncJobForIpAddress() error {
    glog.V(100).Infoln("Sync ipaddress job...")
    if job_response, err1 := base.Schedule.Client.Get(base.GetIpaddressJobPath(), true); ( err1 != nil && err1.Error() != KEY_NOT_FOUND ){
        return err1
    } else if status_response, err2 := base.Schedule.Client.Get(base.Config.Etcd.StatusPath, true); ( err2 != nil  && err2.Error() != KEY_NOT_FOUND ) {
        return err2
    } else {
        status_ips := make(map[string]string)
        invalid_ips := make(map[string]string)

        if status_response != nil {
            for _, kv := range status_response.Kvs {
                ip_address := _get_ip_address_by_job_key(string(kv.Key))
                status_ips[ip_address] = ip_address
            }
        }

        if job_response != nil {
            for _, kv := range job_response.Kvs {
                ip_address := _get_ip_address_by_job_key(string(kv.Key))
                if _, ok := status_ips[ip_address]; ok {
                    delete(status_ips, ip_address)
                } else {
                    invalid_ips[ip_address] = ip_address
                }
            }
        }


        glog.V(50).Infoln("New status ips: ", status_ips)
        glog.V(50).Infoln("Invalid job ips: ", invalid_ips)

        // add new port to job path
        for ipaddress, _ := range status_ips {
            glog.V(50).Infoln("Add new ip ", ipaddress, " to ipaddr job path ", base.GetIpaddressJobPath())
            assign_task := base.AssignTask{InitTag: 1}
            bytes, _ := json.Marshal(assign_task)
            if err := base.Schedule.Client.Set(base.GetIpaddressJobPath() + ipaddress, string(bytes)); err != nil {
                glog.Error("Sync status path to job path failed, due to ", err)
                return err
            }
        }

        // delete invalid port from report path
        for _, ip_address := range invalid_ips {
            glog.V(50).Infoln("Delete invalid job data ", base.GetIpaddressJobPath(), ip_address)
            base.Schedule.Client.DoDelete(base.GetIpaddressJobPath() + ip_address)
        }
    }
    return nil
}

func WatchIpaddressPath() {
    glog.V(100).Infoln("Start watch ", base.Config.Etcd.StatusPath, "...")
    ctx := context.Background()
    var watcher etcdv3.WatchChan
    opts := []etcdv3.OpOption{}
    opts = append(opts, etcdv3.WithPrefix())
    opts = append(opts, etcdv3.WithPrevKV())
    watcher = base.Schedule.Client.Watch(ctx, base.Config.Etcd.StatusPath, opts...)

    for wres := range watcher {
        if wres.Err() != nil {
            err := wres.Err()
            glog.Infof("watch chan error: %v  sleep 2s", err)
            time.Sleep(2 * time.Second)
            return
        }
        for _, e := range wres.Events {
            if e.Type == mvccpb.PUT {
                ip_address := _get_ip_address_by_job_key(string(e.Kv.Key))
                glog.V(50).Infoln("Discover " + ip_address + " status path changed")
                assign_task := base.AssignTask{InitTag: 1}
                bytes, _ := json.Marshal(assign_task)
                if err := base.Schedule.Client.Set(base.GetIpaddressJobPath() + ip_address, string(bytes)); err != nil {
                    if strings.HasPrefix(err.Error(), base.EtcdKeyalReadyExists) {
                        glog.V(0).Infoln(string(e.Kv.Key), "already handled by other schedule-agent")
                    } else {
                        glog.Error("Set job ", base.GetIpaddressJobPath() + ip_address, " failed, due to ", err.Error())
                    }
                }
            } else if e.Type == mvccpb.DELETE {
                ip_address := _get_ip_address_by_job_key(string(e.Kv.Key))
                glog.V(50).Infoln("Discover status path change, and delete job key", ip_address)
                base.Schedule.Client.DoDelete(base.GetIpaddressJobPath() + ip_address)
            } else {
                glog.Warningln("Discover unknow status path changed:", e.Type, "-->", string(e.Kv.Key))
            }
        }
    }
}

func updateIpAddressJob(agent_hostname, ipaddress string) {
    glog.V(0).Infoln("Schedule ip", ipaddress, "to target host ", agent_hostname)

    assign_task := base.AssignTask{AgentName: agent_hostname, InitTag: 0, UpdateTime: time.Now().Local().Format("2006-01-02 15:04:05")}
    bytes, _ := json.Marshal(assign_task)

    if rep, err := base.Schedule.Client.Get(base.GetIpaddressJobPath() + ipaddress, false); err == nil {
        if update_err := base.Schedule.Client.Update(base.GetIpaddressJobPath() + ipaddress, string(bytes), string(rep.Kvs[0].Value)); update_err != nil {
            glog.Error("Update ipaddress job to etcd failed, due to ", update_err.Error())
        }
    }

}

func loopJob() (map[string][]string, []string, error) {
    glog.V(100).Infoln("Run loopJob for ipaddr...")
    allocation := make(map[string][]string)
    init_ips := make([]string, 0, 10)

    if response, err := base.Schedule.Client.Get(base.GetIpaddressJobPath(), true); err == nil {
        for _, kv := range response.Kvs {
            ip_address := _get_ip_address_by_job_key(string(kv.Key))
            assign_task := base.AssignTask{}
            if err := json.Unmarshal(kv.Value, &assign_task); err != nil {
                glog.Error("Unmarshal job data from etcd error, due to ", err.Error())
                continue
            }
            if assign_task.InitTag == 1 {
                init_ips = append(init_ips, ip_address)
            } else if _, ok := allocation[assign_task.AgentName]; !ok {
                allocation[assign_task.AgentName] = make([]string, 0, 10)
                allocation[assign_task.AgentName] = append(allocation[assign_task.AgentName], ip_address)
            } else {
                allocation[assign_task.AgentName] = append(allocation[assign_task.AgentName], ip_address)
            }

        }
    } else {
        glog.Error("Get ", base.GetIpaddressJobPath(), " with prefix failed, due to ", err.Error())
        return nil, nil, err
    }

    return allocation, init_ips, nil
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

    for index, ip_address := range wait_pool {
        if per == 0 || (index / per) >= len(valid_agents) {
            rand.Seed(int64(time.Now().Nanosecond()))
            agent_hostname := valid_agents[rand.Intn(len(valid_agents))]
            updateIpAddressJob(agent_hostname, ip_address)
        } else{
            agent_hostname := valid_agents[index / per]
            updateIpAddressJob(agent_hostname, ip_address)
        }
    }
}

func Run() {
    var (
        active_agents, inactive_agents, new_agents, init_ips []string
        allocation map[string][]string
        job_error, heartbeat_error error
    )

    for {
        if lock_failed := base.Schedule.LockIpAddressKey(); lock_failed != nil {
            glog.Error("Lock failed, due to ", lock_failed.Error())
            time.Sleep(time.Second)
            continue
        }

        if allocation, init_ips, job_error = loopJob(); job_error != nil {
            base.Schedule.UnlockIpAddressKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        if active_agents, inactive_agents, new_agents, heartbeat_error = base.LoopAgentHeartBeat(allocation); heartbeat_error != nil {
            if heartbeat_error.Error() == base.EtcdNoAgentWasFound {
                glog.Warning("No agent was found, will waiting")
            } else {
                glog.Error("Get agent heart beat from etcd failed, due to ", heartbeat_error.Error())
            }
            base.Schedule.UnlockIpAddressKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        if (len(active_agents) + len(new_agents)) == 0 {
            glog.V(0).Infoln("No active scanner-agent, waiting for heartbeat...")
            base.Schedule.UnlockIpAddressKey()
            time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
            continue
        }

        wait_pool := make([]string, 0, 10)
        if len(init_ips) > 0 {
            glog.V(100).Infoln(init_ips, "need to be initialized")
            wait_pool = append(wait_pool, init_ips[:]...)
        }

        scheduleWaitPool(active_agents, inactive_agents, new_agents, wait_pool, allocation)
        base.Schedule.UnlockIpAddressKey()
        time.Sleep(time.Second * time.Duration(base.Config.General.ScheduleInteval))
    }
}