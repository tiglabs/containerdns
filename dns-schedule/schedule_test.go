package main

import (
    "testing"
    "fmt"
)

func TestReadConfig(t *testing.T) {
    configPath := "/etc/containerdns/containerdns-schedule.conf"
    scanner_config, err := readConfig(configPath)
    if err != nil {
        t.Error(err.Error())
    } else {

        print_func := func(schedule_config *ScheduleConfig) {
            fmt.Println("[General]")
            fmt.Println("AgentDownTime:", schedule_config.General.AgentDownTime)
            fmt.Println("ForceLockTime:", schedule_config.General.ForceLockTime)
            fmt.Println("HostName:", schedule_config.General.HostName)
            fmt.Println("ScheduleInteval:", schedule_config.General.ScheduleInteval)
            fmt.Println("LogDir:", schedule_config.General.LogDir)
            fmt.Println("LogLevel:", schedule_config.General.LogLevel)
            fmt.Println("")
            fmt.Println("[Etcd]")
            fmt.Println("EtcdMachine:", schedule_config.Etcd.EtcdMachine)
            fmt.Println("HeartBeatPath:", schedule_config.Etcd.HeartBeatPath)
            fmt.Println("ReportPath:", schedule_config.Etcd.ReportPath)
            fmt.Println("StatusPath:", schedule_config.Etcd.StatusPath)
            fmt.Println("LockPath:", schedule_config.Etcd.LockPath)
        }

        print_func(scanner_config)
    }
}

func TestLoopReportData(t *testing.T) {
    if _, _, _, err := loopJob(); err != nil {
        t.Error(err.Error())
    }
}

func TestSyncReportData(t *testing.T) {
    if err := syncReportData(); err != nil {
        t.Error(err.Error())
    }
}

func TestLoopHeartBeat(t *testing.T) {
    allocationdata, _, _, _ := loopJob()
    _, _, _, heartbeat_error := loopAgentHeartBeat(allocationdata)

    if heartbeat_error != nil {
        t.Error(heartbeat_error.Error())
    }
}

func TestScheduleWaitPool(t *testing.T) {
    allocationdata, initdata, total_num, _ := loopJob()
    active_agents, inactive_agents, new_agents, _ := loopAgentHeartBeat(allocationdata)

    waitpool := make([]string, 0, 10)
    if len(initdata) > 0 {
        waitpool = append(waitpool, initdata[:]...)
    }

    if (len(active_agents) + len(new_agents)) == 0 {
        return
    }

    scheduleWaitPool(active_agents, inactive_agents, new_agents, waitpool, allocationdata, total_num)
}