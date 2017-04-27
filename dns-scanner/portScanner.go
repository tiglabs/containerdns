package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/coreos/go-etcd/etcd"
	"github.com/golang/glog"
	"github.com/ipdcode/skydns/utils"
	"gopkg.in/gcfg.v1"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type reportData struct {
	Hostname   string `json:"hostname"`
	Updatetime string `json:"updatetime,omitempty"`
}

type heartBeat struct {
	Hostname   string `json:"hostname"`
	Lastreport string `json:"lastreport,omitempty"`
}

type statusData struct {
	Status string   `json:"status"`
	Ports  []string `json:"ports,omitempty"`
}

type scannerConfig struct {
	General GeneralConfig
	Check   CheckConfig
	Etcd    EtcdConfig
}

type GeneralConfig struct {
	Core              int    `gcfg:"core"`
	EnableCheck       bool   `gcfg:"enable-check"`
	LogDir            string `gcfg:"log-dir"`
	LogLevel          string `gcfg:"log-level"`
	HostName          string `gcfg:"hostname"`
	HeartbeatInterval int    `gcfg:"heartbeat-interval"`
}

type CheckConfig struct {
	CheckTimeout int    `gcfg:"check-timeout"`
	CheckInteval int    `gcfg:"check-interval"`
	ScannPorts   string `gcfg:"scann-ports"`
	EnableICMP   bool   `gcfg:"enable-icmp"`
	PingTimeOut  int    `gcfg:"ping-timeout"`
	PingCount    int    `gcfg:"ping-count"`
}

type EtcdConfig struct {
	EtcdMachine   string `gcfg:"etcd-machine"`
	TlsKey        string `gcfg:"tls-key"`
	TlsPem        string `gcfg:"tls-pem"`
	CaCert        string `gcfg:"ca-cert"`
	StatusPath    string `gcfg:"status-path"`
	ReportPath    string `gcfg:"report-path"`
	HeartBeatPath string `gcfg:"heart-path"`
}

const (
	glogFlushPeriod = 5 * time.Second
)

var (
	configfile          = ""
	runningThread int64 = 0
	config        *scannerConfig
	client        *etcd.Client
)

func glogFlush(period time.Duration) {
	for range time.Tick(period) {
		glog.Flush()
	}
}

func init() {
	flag.StringVar(&configfile, "config-file", "/etc/skydns/skydns-scanner.conf", "read config from the file")
	flag.Parse()
	var e error
	if config, e = readConfig(configfile); e != nil {
		glog.Fatal("Read config file error, due to", e.Error())
		os.Exit(1)
	}
	flag.Lookup("log_dir").Value.Set(config.General.LogDir)
	flag.Lookup("v").Value.Set(config.General.LogLevel)
	client = newClient(strings.Split(config.Etcd.EtcdMachine, ","), config.Etcd.TlsPem, config.Etcd.TlsKey, config.Etcd.CaCert)
}

func readConfig(configPath string) (*scannerConfig, error) {

	cfg := new(scannerConfig)
	var config *os.File
	config, err := os.Open(configPath)
	if err != nil {
		glog.Fatalf("Couldn't open scanner configuration %s: %#v", configPath, err)
	}
	defer config.Close()
	err = gcfg.ReadInto(cfg, config)
	return cfg, err
}

func loopIpAddress(channelIpAddress chan string) ([]string, error) {
	glog.V(50).Infoln("Loop ip address for path", config.Etcd.ReportPath)
	if r, e := client.Get(config.Etcd.ReportPath, false, true); e == nil {
		ipAddresses := make([]string, 0, 10)
		if r.Node.Dir {
			for _, n := range r.Node.Nodes {
				glog.V(100).Infoln("Get report data", n.Key, "-->", n.Value)
				i := strings.Split(n.Key, "/")
				ipaddress := i[len(i)-1]
				var reportdata reportData
				if e := json.Unmarshal([]byte(n.Value), &reportdata); e != nil {
					glog.Error("Unmarshal report data from etcd error, due to", e.Error())
					continue
				}
				if reportdata.Hostname == config.General.HostName {
					ipAddresses = append(ipAddresses, ipaddress)
					go func() {
						glog.V(100).Infoln("Write ip", ipaddress, "to channelIpAddress")
						channelIpAddress <- ipaddress
					}()
				}
			}
			return ipAddresses, e
		} else {
			return nil, fmt.Errorf("%s must be a directory", config.Etcd.ReportPath)
		}
	} else {
		return nil, fmt.Errorf("traverse %s from etcd failed", config.Etcd.ReportPath)
	}

}

func scanner(ipaddress string, chanelActiveIpAddress, chaneFailIpAddress, chanHandledIpAddress chan string) {
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

	if config.Check.EnableICMP {
		glog.V(100).Infoln("Enable icmp check")
		for i := 0; i < config.Check.PingCount; i++ {
			var ping_log_sequence string
			if i%10 == 0 {
				ping_log_sequence = strconv.Itoa(i+1) + "st"
			} else if i%10 == 1 {
				ping_log_sequence = strconv.Itoa(i+1) + "nd"
			} else if i%10 == 2 {
				ping_log_sequence = strconv.Itoa(i+1) + "rd"
			} else {
				ping_log_sequence = strconv.Itoa(i+1) + "th"
			}
			glog.V(100).Infoln("The", ping_log_sequence, "try to ping", ipaddress)

			if ping_result := tools.Ping(ipaddress, config.Check.PingTimeOut); ping_result {
				go func() {
					chanelActiveIpAddress <- ipaddress
				}()
				goto scannerSuccess
			}
		}
	}

	if status_response, c_error := client.Get(config.Etcd.StatusPath+"/"+ipaddress, false, false); c_error != nil {
		glog.Error("get", ipaddress, "status failed, due to", c_error.Error())
	} else {
		var statusdata statusData

		if e := json.Unmarshal([]byte(status_response.Node.Value), &statusdata); e != nil {
			glog.Error("Unmarshal status data from etcd error, due to", e.Error())
		}

		if len(statusdata.Ports) > 0 {
			ports = statusdata.Ports
		} else {
			ports = strings.Split(config.Check.ScannPorts, ",")
		}
	}

	for _, port := range ports {
		tcpaddr := ipaddress + ":" + port
		conn, err := net.DialTimeout("tcp", tcpaddr, time.Second*time.Duration(config.Check.CheckTimeout))
		if err == nil {
			conn.Close()
			go func() {
				chanelActiveIpAddress <- ipaddress
			}()
			goto scannerSuccess
		}
	}

	// can not connected
	go func() {
		chaneFailIpAddress <- ipaddress
	}()

scannerSuccess:
	go func() {
		chanHandledIpAddress <- ipaddress
	}()

	atomic.AddInt64(&runningThread, -1)
}

func heartReport() {
	glog.V(0).Infoln("Start heart beat...")
	for {
		glog.V(50).Infoln("Heart beat to etcd server from host", config.General.HostName)
		var heartbeat heartBeat
		heartbeat.Hostname = config.General.HostName
		heartbeat.Lastreport = time.Now().Local().Format("2006-01-02 15:04:05")
		bytes, _ := json.Marshal(heartbeat)
		_, writeerr := client.Set(config.Etcd.HeartBeatPath+"/"+config.General.HostName, string(bytes), uint64(0))
		if writeerr != nil {
			glog.Error("Write heart beat to etcd error, due to", writeerr.Error())
		}
		time.Sleep(time.Second * time.Duration(config.General.HeartbeatInterval))
	}
}

func doUpdateStatus(ip_address, status string) {
	if status_response, c_error := client.Get(config.Etcd.StatusPath+"/"+ip_address, false, false); c_error == nil {
		var statusdata statusData

		if jsonerror := json.Unmarshal([]byte(status_response.Node.Value), &statusdata); jsonerror == nil {
			if statusdata.Status != status {
				glog.V(0).Infoln("Change ip", ip_address, "status from", statusdata.Status, "to", status)
				statusdata.Status = status
				bytes, _ := json.Marshal(statusdata)
				_, writeerr := client.Set(config.Etcd.StatusPath+"/"+ip_address, string(bytes), uint64(0))
				if writeerr != nil {
					glog.Error("Write status data to etcd error, due to", writeerr.Error())
				}

				var reportdata reportData
				reportdata.Updatetime = time.Now().Local().Format("2006-01-02 15:04:05")
				reportdata.Hostname = config.General.HostName
				reportbytes, _ := json.Marshal(reportdata)
				_, writereporterr := client.Set(config.Etcd.ReportPath+"/"+ip_address, string(reportbytes), uint64(0))
				if writereporterr != nil {
					glog.Error("Write report data to etcd error, due to", writeerr.Error())
				}
			}
		} else {
			glog.Error("Format status response", status_response.Node.Value, "error, due to", jsonerror.Error())
		}
	} else {
		glog.Error("Client get status vaule from etcd failed, due to ", c_error.Error())
	}
}

func updateStatus(chanelActiveIpAddress, chaneFailIpAddress chan string) {
	glog.V(0).Infoln("Start monitor chanel to update status...")
	for {
		select {
		case activeIp := <-chanelActiveIpAddress:
			go doUpdateStatus(activeIp, "UP")
		case failIp := <-chaneFailIpAddress:
			go doUpdateStatus(failIp, "DOWN")
		}
	}
}

func newClient(machines []string, tlsCert, tlsKey, tlsCACert string) (client *etcd.Client) {
	// set default if not specified in env
	glog.V(50).Infoln("Get etcd server by url:", machines, "cert:", tlsCert, "key:", tlsKey, "cacert:", tlsCACert)
	if len(machines) == 1 && machines[0] == "" {
		glog.Error("Need to specify the etcd server")
		os.Exit(1)
	}
	if strings.HasPrefix(machines[0], "https://") {
		var err error
		if client, err = etcd.NewTLSClient(machines, tlsCert, tlsKey, tlsCACert); err != nil {
			glog.Error("skydns: failure to connect:", err.Error())
			os.Exit(1)
		}
		return client
	}
	return etcd.NewClient(machines)
}

func main() {
	if config.General.Core <= 0 {
		glog.V(0).Infoln("Starting skydns-scanner-agent with", runtime.NumCPU(), "CPUs")
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		glog.V(0).Infoln("Starting skydns-scanner-agent with", config.General.Core, "CPUs")
		runtime.GOMAXPROCS(config.General.Core)
	}

	go glogFlush(glogFlushPeriod)
	defer glog.Flush()

	channelIpAddress := make(chan string)
	chanelActiveIpAddress := make(chan string)
	chaneFailIpAddress := make(chan string)
	chanHandledIpAddress := make(chan string)

	ipAddresses, err := loopIpAddress(channelIpAddress)
	if err != nil {
		glog.Error("loopIpAddress failed, due to", err.Error())
	}

	// run in background
	go heartReport()
	go updateStatus(chanelActiveIpAddress, chaneFailIpAddress)

	handled_ips := make([]string, 0, 10)
	start_time := time.Now().Unix()

	for {
		select {
		case ipaddress := <-channelIpAddress:
			// start worker-thread
			atomic.AddInt64(&runningThread, 1)
			go scanner(ipaddress, chanelActiveIpAddress, chaneFailIpAddress, chanHandledIpAddress)

		case handled_ip := <-chanHandledIpAddress:
			handled_ips = append(handled_ips, handled_ip)

			if len(handled_ips) == len(ipAddresses) {
				now := time.Now().Unix()
				if now-start_time < int64(config.Check.CheckInteval) {
					glog.V(50).Infoln("sleep ", int64(config.Check.CheckInteval)+start_time-now, "Seconds")
					time.Sleep(time.Second * time.Duration(int64(config.Check.CheckInteval)+start_time-now))
				}
				handled_ips = make([]string, 0, 10)
				ipAddresses, err = loopIpAddress(channelIpAddress)
				if err != nil {
					glog.Error("loopIpAddress failed, due to", err.Error())
				}
				start_time = time.Now().Unix()
			}

		default:
			if atomic.LoadInt64(&runningThread) > 0 {
				glog.V(50).Infoln("Waiting for", atomic.LoadInt64(&runningThread), "scanner threads end")
				time.Sleep(time.Second * 1)
			} else {
				glog.V(50).Infoln("No running thread on this agent, and the pool length that waiting for handle is", len(ipAddresses), ", sleep 1s")
				time.Sleep(time.Second)
				if len(ipAddresses) == 0 {
					glog.V(0).Infoln("Reload job for this agent...")
					ipAddresses, err = loopIpAddress(channelIpAddress)
					if err != nil {
						glog.Error("loopIpAddress failed, due to", err.Error())
					}
				}
			}

		}
	}
}
