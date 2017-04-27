package main

import (
	"fmt"
	"testing"
	"time"
)

func TestScanner(t *testing.T) {
	ip_address := "10.8.65.104"
	chanelActiveIpAddress := make(chan string)
	chaneFailIpAddress := make(chan string)
	chanHandledIpAddress := make(chan string)

	scanner(ip_address, chanelActiveIpAddress, chaneFailIpAddress, chanHandledIpAddress)

	time.Sleep(time.Second)

	for i := 0; i < 2; i++ {
		select {
		case <-chanelActiveIpAddress:
		case <-chaneFailIpAddress:
		case <-chanHandledIpAddress:
		default:
			t.Error("At least return two channel with messages")
		}
	}
}

func TestLoopIpAddress(t *testing.T) {
	channelIpAddress := make(chan string)
	_, err := loopIpAddress(channelIpAddress)

	if err != nil {
		t.Error(err.Error())
	}
}

func TestReadConfig(t *testing.T) {
	configPath := "/etc/skydns/skydns-scanner.conf"
	scanner_config, err := readConfig(configPath)
	if err != nil {
		t.Error(err.Error())
	} else {

		print_func := func(scanner_config *scannerConfig) {
			fmt.Println("[General]")
			fmt.Println("Core:", scanner_config.General.Core)
			fmt.Println("EnableCheck:", scanner_config.General.EnableCheck)
			fmt.Println("HeartbeatInterval:", scanner_config.General.HeartbeatInterval)
			fmt.Println("HostName:", scanner_config.General.HostName)
			fmt.Println("LogDir:", scanner_config.General.LogDir)
			fmt.Println("LogLevel:", scanner_config.General.LogLevel)
			fmt.Println("")
			fmt.Println("[Check]")
			fmt.Println("CheckInteval:", scanner_config.Check.CheckInteval)
			fmt.Println("CheckTimeout:", scanner_config.Check.CheckTimeout)
			fmt.Println("ScannPorts:", scanner_config.Check.ScannPorts)
			fmt.Println("EnableICMP:", scanner_config.Check.EnableICMP)
			fmt.Println("PingTimeOut:", scanner_config.Check.PingTimeOut)
			fmt.Println("PingCount:", scanner_config.Check.PingCount)
			fmt.Println("")
			fmt.Println("[Etcd]")
			fmt.Println("EtcdMachine:", scanner_config.Etcd.EtcdMachine)
			fmt.Println("HeartBeatPath:", scanner_config.Etcd.HeartBeatPath)
			fmt.Println("ReportPath:", scanner_config.Etcd.ReportPath)
			fmt.Println("StatusPath:", scanner_config.Etcd.StatusPath)
		}

		print_func(scanner_config)
	}
}
