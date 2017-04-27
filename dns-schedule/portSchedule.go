package main

import (
	"encoding/json"
	"flag"
	"fmt"
	etcd_client "github.com/coreos/etcd/client"
	"github.com/golang/glog"
	"github.com/ipdcode/skydns/utils"
	"gopkg.in/gcfg.v1"
	"math/rand"
	"os"
	"strings"
	"time"
)

type reportData struct {
	Hostname   string `json:"hostname,omitempty"`
	Updatetime string `json:"updatetime,omitempty"`
	Initdata   int    `json:"initdata,omitempty"`
}

type heartBeat struct {
	Hostname   string `json:"hostname"`
	Lastreport string `json:"lastreport,omitempty"`
}

type statusData struct {
	Status string `json:"status"`
}

const (
	glogFlushPeriod = 5 * time.Second
)

type scheduleConfig struct {
	General GeneralConfig
	Etcd    EtcdConfig
}

type GeneralConfig struct {
	ScheduleInteval int    `gcfg:"schedule-interval"`
	AgentDownTime   int    `gcfg:"agent-downtime"`
	LogDir          string `gcfg:"log-dir"`
	LogLevel        string `gcfg:"log-level"`
	HostName        string `gcfg:"hostname"`
	ForceLockTime   int    `gcfg:"force-lock-time"`
}

type EtcdConfig struct {
	EtcdMachine   string `gcfg:"etcd-machine"`
	StatusPath    string `gcfg:"status-path"`
	ReportPath    string `gcfg:"report-path"`
	HeartBeatPath string `gcfg:"heart-path"`
	LockPath      string `gcfg:"lock-path"`
}

type ScheduleClient struct {
	Client *tools.EtcdOps
}

var (
	configfile           = ""
	config               *scheduleConfig
	scheduleClient       ScheduleClient
	etcdKeyalReadyExists = "105: Key already exists"
)

func glogFlush(period time.Duration) {
	for range time.Tick(period) {
		glog.Flush()
	}
}

func init() {
	flag.StringVar(&configfile, "config-file", "/etc/skydns/skydns-schedule.conf", "read config from the file")
	flag.Parse()
	var e error
	if config, e = readConfig(configfile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(config.General.LogDir)
	flag.Lookup("v").Value.Set(config.General.LogLevel)
	glog.V(100).Infoln("Load config file -->", config.General, config.Etcd)
	scheduleClient.Client = newClient(strings.Split(config.Etcd.EtcdMachine, ","))
}

func readConfig(configPath string) (*scheduleConfig, error) {

	cfg := new(scheduleConfig)
	var config *os.File
	config, err := os.Open(configPath)
	if err != nil {
		glog.Fatalf("Couldn't open schedule configuration %s: %#v", configPath, err)
	}
	defer config.Close()
	err = gcfg.ReadInto(cfg, config)
	return cfg, err
}

func loopReportData() (map[string][]string, []string, int, error) {
	glog.V(100).Infoln("Run loopReportData...")
	r, e := scheduleClient.Client.Get(config.Etcd.ReportPath, false, false)

	allocationdata := make(map[string][]string)
	initdata := make([]string, 0, 10)
	totalnum := 0

	if r.Node.Dir && e == nil {
		for _, n := range r.Node.Nodes {
			glog.V(100).Infoln("Loop report data key:", n.Key, "-->", n.Value)
			i := strings.Split(n.Key, "/")
			ipaddress := i[len(i)-1]
			var reportdata reportData
			if e := json.Unmarshal([]byte(n.Value), &reportdata); e != nil {
				glog.Error("Unmarshal report data from etcd error, due to", e.Error())
				continue
			}
			if reportdata.Initdata == 1 {
				initdata = append(initdata, ipaddress)
			} else if _, ok := allocationdata[reportdata.Hostname]; !ok {
				allocationdata[reportdata.Hostname] = make([]string, 0, 10)
				allocationdata[reportdata.Hostname] = append(allocationdata[reportdata.Hostname], ipaddress)
			} else {
				allocationdata[reportdata.Hostname] = append(allocationdata[reportdata.Hostname], ipaddress)
			}

			totalnum += 1
		}
		return allocationdata, initdata, totalnum, e
	} else if e != nil {
		return nil, nil, -1, e
	} else {
		return nil, nil, -1, fmt.Errorf("%s must be a directory", r.Node.Key)
	}
}

func loopHeartBeat(allocationdata map[string][]string) ([]string, []string, []string, error) {
	glog.V(100).Infoln("Run loopHeartBeat...")
	r, e := scheduleClient.Client.Get(config.Etcd.HeartBeatPath, false, false)
	if r.Node.Dir && e == nil {

		active_agents := make([]string, 0, 10)
		inactive_agents := make([]string, 0, 10)
		new_agents := make([]string, 0, 10)

		for _, n := range r.Node.Nodes {
			glog.V(100).Infoln("Loop heart beat data key:", n.Key, "-->", n.Value)
			var heartbeat heartBeat
			if jsonerror := json.Unmarshal([]byte(n.Value), &heartbeat); jsonerror != nil {
				glog.Error("Unmarshal heart beat data from etcd error, due to", jsonerror.Error())
				continue
			}

			loc, _ := time.LoadLocation("Local")
			hearttime, _ := time.ParseInLocation("2006-01-02 15:04:05", heartbeat.Lastreport, loc)
			now := time.Now().Local()

			glog.V(50).Infoln("host: ", heartbeat.Hostname, "hearttime: ", hearttime, "now: ", now, ", D-value is", int(now.Unix()-hearttime.Unix()))
			if int(now.Unix()-hearttime.Unix()) <= config.General.AgentDownTime {
				// active agent
				if _, ok := allocationdata[heartbeat.Hostname]; ok {
					active_agents = append(active_agents, heartbeat.Hostname)
				} else {
					new_agents = append(new_agents, heartbeat.Hostname)
				}

			} else {
				// down agent
				if _, ok := allocationdata[heartbeat.Hostname]; ok {
					inactive_agents = append(inactive_agents, heartbeat.Hostname)
				} else {
					glog.Warningln("Invalid agent", heartbeat.Hostname)
				}
			}
		}
		return active_agents, inactive_agents, new_agents, e

	} else if e != nil {
		return nil, nil, nil, e
	} else {
		return nil, nil, nil, fmt.Errorf("%s must be a directory", r.Node.Key)
	}

}

func updateReportData(agent, ipaddress string) {
	glog.V(0).Infoln("Schedule ip", ipaddress, "to target host", agent)

	var reportdata reportData
	reportdata.Hostname = agent
	reportdata.Updatetime = time.Now().Local().Format("2006-01-02 15:04:05")
	reportdata.Initdata = 0
	bytes, _ := json.Marshal(reportdata)

	if update_err := scheduleClient.Client.Update(config.Etcd.ReportPath+"/"+ipaddress, string(bytes), "", false); update_err != nil {
		glog.Error("Update report data to etcd failed, due to ", update_err.Error())
	}
}

func watchStatusDnsPath() {
	glog.V(100).Infoln("Start watch", config.Etcd.StatusPath, "...")
	recv := make(chan *etcd_client.Response)
	go scheduleClient.Client.Watch(config.Etcd.StatusPath, 0, true, recv)
	for {
		select {
		case response := <-recv:
			if response != nil {
				if response.Action == "delete" || response.Action == "compareAndDelete" {
					i := strings.Split(response.Node.Key, "/")
					ipaddress := i[len(i)-1]
					glog.V(50).Infoln("Discover status path change, and delete report key", ipaddress)
					scheduleClient.Client.DeleteRaw(config.Etcd.ReportPath + "/" + ipaddress)
				} else if response.Action == "create" {
					i := strings.Split(response.Node.Key, "/")
					ipaddress := i[len(i)-1]
					glog.V(50).Infoln("Discover status path change, and init report key", ipaddress)
					var reportdata reportData
					reportdata.Initdata = 1

					bytes, _ := json.Marshal(reportdata)
					if writeerr := scheduleClient.Client.Set(config.Etcd.ReportPath+"/"+ipaddress, string(bytes)); writeerr != nil {
						if strings.HasPrefix(writeerr.Error(), etcdKeyalReadyExists) {
							glog.V(0).Infoln(response.Node.Key, "already handled by other schedule-agent")
						} else {
							glog.Error("Init report data to etcd failed, due to ", writeerr)
						}
					}
				} else {
					glog.V(100).Infoln("Discover status path change:", response.Action, "-->", response.Node.Key)
				}

			} else {
				// we can see an response == nil, probably when we can't connect to etcd.
				glog.Error("Get watch response failed...")
			}
		}
	}
}

func syncReportData() error {
	glog.V(100).Infoln("Sync report and status path...")
	r_nodes, efr := scheduleClient.Client.Get(config.Etcd.ReportPath, false, false)
	s_nodes, efs := scheduleClient.Client.Get(config.Etcd.StatusPath, false, false)
	if efr != nil {
		return efr
	} else if efs != nil {
		return efs
	}

	status_ips := make(map[string]string)
	report_ips := make(map[string]string)

	for _, n := range s_nodes.Node.Nodes {
		i := strings.Split(n.Key, "/")
		ipaddress := i[len(i)-1]
		status_ips[ipaddress] = ipaddress
	}

	for _, n := range r_nodes.Node.Nodes {
		i := strings.Split(n.Key, "/")
		ipaddress := i[len(i)-1]
		if _, ok := status_ips[ipaddress]; ok {
			delete(status_ips, ipaddress)
		} else {
			report_ips[ipaddress] = ipaddress
		}
	}

	glog.V(50).Infoln("New status ips:", status_ips)
	glog.V(50).Infoln("Invalid report ips:", report_ips)

	// add new port to report path
	for ipaddress, _ := range status_ips {
		glog.V(50).Infoln("Add new ip", ipaddress, "to report path")
		var reportdata reportData
		reportdata.Initdata = 1
		bytes, _ := json.Marshal(reportdata)
		if writeerr := scheduleClient.Client.Set(config.Etcd.ReportPath+"/"+ipaddress, string(bytes)); writeerr != nil {
			glog.Error("Sync new status data to report data failed, due to ", writeerr)
			return writeerr
		}
	}

	// delete invalid port from report path
	for _, ipaddress := range report_ips {
		glog.V(50).Infoln("Delete invalid report data", ipaddress)
		scheduleClient.Client.DeleteRaw(config.Etcd.ReportPath + "/" + ipaddress)
	}
	return nil
}

func newClient(machines []string) *tools.EtcdOps {
	etcdcli := tools.EtcdOps{}
	err := etcdcli.InitEtcd(machines)
	if err != nil {
		glog.Fatalf("Failed to create etcd client - %v", err)
		os.Exit(1)
	}
	return &etcdcli
}

func scheduleWaitPool(active_agents, inactive_agents, new_agents, waitpool []string, allocationdata map[string][]string, totalnum int) {
	// has down agents and do not has new agents
	glog.V(100).Infoln("Run scheduleWaitPool with active_agents:", active_agents, "inactive_agents:", inactive_agents, "new_agents:", new_agents, "waitpool:", waitpool,
		"allocationdata:", allocationdata, "totalnum:", totalnum)

	active_agent_num := len(active_agents) + len(new_agents)
	if len(inactive_agents) > 0 && len(new_agents) == 0 {
		glog.V(50).Infoln("Get", len(inactive_agents), "inactive agents and no new active agent")
		for _, agent := range inactive_agents {
			waitpool = append(waitpool, allocationdata[agent]...)
		}

		glog.V(50).Infoln("Waitpool -->", waitpool)

		per := len(waitpool) / active_agent_num

		for index, ipaddress := range waitpool {
			var agent string
			if per != 0 && (index/per) < len(active_agents) {
				agent = active_agents[index/per]
			} else {
				rand.Seed(int64(time.Now().Nanosecond()))
				rand_agent := rand.Intn(len(active_agents))
				agent = active_agents[rand_agent]
			}
			updateReportData(agent, ipaddress)
		}

	} else if len(new_agents) > 0 && len(inactive_agents) == 0 {
		glog.V(50).Infoln("Get", len(new_agents), "new agents and no inactive agents")
		per := totalnum / active_agent_num
		for _, ipaddress_pool := range allocationdata {
			if len(ipaddress_pool) > per {
				waitpool = append(waitpool, ipaddress_pool[per:]...)
			}
		}

		for host, ipaddress_pool := range allocationdata {
			if len(ipaddress_pool) < per {
				glog.V(0).Infoln("Reallocation ip pool to old active host")
				tmp_pool := waitpool[0:(per - len(ipaddress_pool))]
				waitpool = waitpool[(per - len(ipaddress_pool)):]
				for _, ipaddress := range tmp_pool {
					updateReportData(host, ipaddress)
				}
			}
		}

		glog.V(50).Infoln("Waitpool -->", waitpool)

		valid_agents := append(active_agents, new_agents...)
		for index, ipaddress := range waitpool {
			var agent string
			if per != 0 && (index/per) < len(new_agents) {
				agent = new_agents[index/per]
			} else {
				rand.Seed(int64(time.Now().Nanosecond()))
				rand_agent := rand.Intn(len(valid_agents))
				agent = valid_agents[rand_agent]
			}
			updateReportData(agent, ipaddress)
		}

	} else if len(new_agents) > 0 && len(inactive_agents) > 0 {
		glog.V(50).Infoln("Get", len(new_agents), "new agents and", len(inactive_agents), "inactive agents")
		per := totalnum / active_agent_num

		for _, agent := range inactive_agents {
			waitpool = append(waitpool, allocationdata[agent]...)
			delete(allocationdata, agent)
		}

		glog.V(50).Infoln("Waitpool -->", waitpool)

		for _, ipaddress_pool := range allocationdata {
			if len(ipaddress_pool) > per {
				glog.V(0).Infoln("Reallocation ip pool from old active host")
				waitpool = append(waitpool, ipaddress_pool[per:]...)
			}
		}

		for host, ipaddress_pool := range allocationdata {
			if len(ipaddress_pool) < per {
				glog.V(0).Infoln("Reallocation ip pool to old active host")
				tmp_pool := waitpool[0:(per - len(ipaddress_pool))]
				waitpool = waitpool[(per - len(ipaddress_pool)):]
				for _, ipaddress := range tmp_pool {
					updateReportData(host, ipaddress)
				}
			}
		}

		valid_agents := append(active_agents, new_agents...)
		for index, ipaddress := range waitpool {
			var agent string
			if per != 0 && (index/per) < len(new_agents) {
				agent = new_agents[index/per]
			} else {
				rand.Seed(int64(time.Now().Nanosecond()))
				rand_agent := rand.Intn(len(valid_agents))
				agent = valid_agents[rand_agent]
			}
			updateReportData(agent, ipaddress)
		}

	} else if len(waitpool) > 0 {
		glog.V(50).Infoln("No agent status change, but discover new report ip", waitpool)
		per := len(waitpool) / active_agent_num

		for index, ipaddress := range waitpool {
			var agent string
			if per != 0 && index/per < len(active_agents) {
				agent = active_agents[index/per]
			} else {
				rand.Seed(int64(time.Now().Nanosecond()))
				rand_agent := rand.Intn(len(active_agents))
				agent = active_agents[rand_agent]
			}
			updateReportData(agent, ipaddress)
		}
	}
}

func (scheduleClient *ScheduleClient) LockKey() (lock_error error) {
	start_time := time.Now().Local()
	for {
		lock_error = scheduleClient.Client.Set(config.Etcd.LockPath+"/lock", config.General.HostName)
		if lock_error != nil && strings.HasPrefix(lock_error.Error(), etcdKeyalReadyExists) {
			now := time.Now().Local()
			if (now.Unix() - start_time.Unix()) > int64(config.General.ForceLockTime) {
				glog.Warningln("Force locking...")
				scheduleClient.Client.DeleteRaw(config.Etcd.LockPath + "/lock")
				return scheduleClient.Client.Set(config.Etcd.LockPath+"/lock", config.General.HostName)
			} else {
				glog.V(50).Infoln("Locked by other schdule-agent, sleep 1s")
				time.Sleep(time.Second)
			}
		} else {
			break
		}
	}
	return lock_error
}

func (scheduleClient *ScheduleClient) UnlockKey() {
	scheduleClient.Client.DeleteRaw(config.Etcd.LockPath + "/lock")
}

func main() {
	glog.V(0).Infoln("Starting skydns-schedule-agent...")
	go glogFlush(glogFlushPeriod)
	defer glog.Flush()
	err := syncReportData()
	if err != nil {
		glog.Error("Sync report and status path failed, due to", err.Error())
		os.Exit(1)
	}
	go watchStatusDnsPath()

	var (
		active_agents, inactive_agents, new_agents, initdata []string
		allocationdata                                       map[string][]string
		reportdata_error, heartbeat_error                    error
		total_num                                            int
	)

	for {
		if lock_failed := scheduleClient.LockKey(); lock_failed != nil {
			glog.Error("Lock failed, due to ", lock_failed.Error())
			continue
		}

		if allocationdata, initdata, total_num, reportdata_error = loopReportData(); reportdata_error != nil {
			glog.Error("Get etcd report data failed, due to", reportdata_error.Error())
			time.Sleep(time.Second)
			scheduleClient.UnlockKey()
			continue
		}

		if active_agents, inactive_agents, new_agents, heartbeat_error = loopHeartBeat(allocationdata); heartbeat_error != nil {
			glog.Error("Get heart beat from etcd failed, due to", heartbeat_error.Error())
			time.Sleep(time.Second)
			scheduleClient.UnlockKey()
			continue
		}

		glog.V(100).Infoln("Current allocation data:", allocationdata)

		glog.V(50).Infoln("active_agents:", active_agents, "inactive_agents:", inactive_agents, "new_agents:", new_agents)

		if (len(active_agents) + len(new_agents)) == 0 {
			glog.V(0).Infoln("No active scanner-agent, waiting for heartbeat...")
			time.Sleep(time.Second * 10)
			scheduleClient.UnlockKey()
			continue
		}

		waitpool := make([]string, 0, 10)
		if len(initdata) > 0 {
			glog.V(100).Infoln(initdata, "need to be initialized")
			waitpool = append(waitpool, initdata[:]...)
		}

		scheduleWaitPool(active_agents, inactive_agents, new_agents, waitpool, allocationdata, total_num)
		scheduleClient.UnlockKey()
		time.Sleep(time.Second * time.Duration(config.General.ScheduleInteval))
	}
}
