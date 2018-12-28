package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
)

type apiService struct {
	AliasDomain string            `json:"alias-domain,omitempty"`
	OpsType     string            `json:"type,omitempty"`
	DomainIps   []string          `json:"ips,omitempty"`
	DomainAlias string            `json:"alias,omitempty"`
	UpdateMap   map[string]string `json:"update,omitempty"`
}

var cmdToken string = ""
var cmdAddr string = ""
var cmdMethod string = ""
var cmdDomain string = ""
var cmdIps string = ""
var cmdAlias string = ""
var cmdUpdates string = ""
var cmdShow string = ""
var cmdList bool = false

func env(key, def string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return def
}
func init() {
	flag.StringVar(&cmdDomain, "domain", "", "domain to operation")
	flag.StringVar(&cmdMethod, "method", "", " create, update, or delete")
	flag.StringVar(&cmdShow, "show", "", "show the domain ")
	flag.BoolVar(&cmdList, "list", false, "show the domain ")
	flag.StringVar(&cmdAddr, "addr", env("CONDNS_API_ADDR", ""), "the api addr to access such as 127.0.0.1:9001 or form env(CONDNS_API_ADDR)")
	flag.StringVar(&cmdToken, "token", env("CONDNS_API_TOKEN", ""), "the token to auth, or from env(CONDNS_API_TOKEN)")
	flag.StringVar(&cmdIps, "ips", "", "the ips of domain for create ,such as  10.0.0.0;10.0.0.1")
	flag.StringVar(&cmdAlias, "alias", "", "the alias of domain for create ")
	flag.StringVar(&cmdUpdates, "updates", "", "the data to update,such as ips:10.0.0.0->192.168.0.1;10.0.0.1->192.168.0.2  or alias: baidu->baidu1 ")
}

func doreq(a apiService) (error, string) {
	b, err := json.Marshal(a)
	if err != nil {
		return err, ""
	}

	body := bytes.NewBuffer([]byte(b))

	client := &http.Client{}
	cmdUrl := cmdAddr + cmdDomain + "?token=" + cmdToken
	req, err := http.NewRequest(cmdMethod, cmdUrl, body)
	if err != nil {
		return err, ""
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")

	res, err := client.Do(req)
	defer res.Body.Close()
	if err != nil {
		return err, ""
	}
	result, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err, ""
	}
	ret := fmt.Sprintf("%s", result)
	return err, ret

}
func cmdApiCreate() {
	if cmdDomain == "" {
		fmt.Print("domain must be input\n")
		return
	}
	if cmdIps == "" && cmdAlias == "" {
		fmt.Print("either ips or alias must be offered\n")
		return
	}
	if cmdIps != "" && cmdAlias != "" {
		fmt.Print("either ips or alias must be offered\n")
		return
	}
	var a apiService
	if cmdIps != "" {
		a.OpsType = "A"
		a.DomainIps = strings.Split(cmdIps, ";")
	}
	if cmdAlias != "" {
		a.OpsType = "CNAME"
		a.DomainAlias = cmdAlias
	}
	err, ret := doreq(a)
	if err != nil {
		fmt.Printf("err :%s\n", err.Error())
	} else {
		fmt.Print(ret)
	}
}
func doShowResult(ret string) {
	svc := make(map[string]apiService)
	if err := json.Unmarshal([]byte(ret), &svc); err == nil {
		for k, v := range svc {
			fmt.Printf("domain:  %56s       val: { ", k)
			if v.OpsType == "A" {
				fmt.Printf("type:A  ips:%s }\n", v.DomainIps)
			} else {
				fmt.Printf("type:Cname  alias:%s }\n", v.AliasDomain)
			}
		}
	} else {
		fmt.Printf("domain :%s not found\n", cmdShow)
	}

}
func cmdApiList() {
	var a apiService
	err, ret := doreq(a)
	if err != nil {
		fmt.Printf("err :%s\n", err.Error())
	} else {
		doShowResult(ret)
	}
}
func cmdApiShow() {
	var a apiService
	cmdDomain = cmdShow
	err, ret := doreq(a)
	if err != nil {
		fmt.Printf("domain :%s not found \n", cmdDomain)
	} else {
		doShowResult(ret)
	}
}
func cmdApiDelete() {
	var a apiService
	if cmdDomain == "" {
		fmt.Print("domain must be input\n")
		return
	}
	err, ret := doreq(a)
	if err != nil {
		fmt.Printf("err :%s\n", err.Error())
	} else {
		fmt.Print(ret)
	}
}
func cmdApiUpdate() {

	if cmdDomain == "" {
		fmt.Print("domain must be input\n")
		return
	}
	if cmdUpdates == "" {
		fmt.Print("updates must be offered\n")
		return
	}
	var a apiService
	if strings.HasPrefix(cmdUpdates, "ips:") {
		a.OpsType = "A"
		ips := strings.Split(cmdUpdates[4:], ";")
		a.UpdateMap = make(map[string]string, len(ips))
		for _, ip := range ips {
			data := strings.Split(ip, "->")
			if len(data) != 2 {
				fmt.Print("updates data err,input like ips:10.0.0.0->192.168.0.1;10.0.0.1->192.168.0.2 \n")
				return
			}
			a.UpdateMap[data[0]] = data[1]
		}
		err, ret := doreq(a)
		if err != nil {
			fmt.Printf("err :%s\n", err.Error())
		} else {
			fmt.Print(ret)
		}
	} else if strings.HasPrefix(cmdUpdates, "alias:") {
		a.OpsType = "CNAME"
		a.UpdateMap = make(map[string]string, 1)
		skipN := len("alias:")
		data := strings.Split(cmdUpdates[skipN:], "->")
		if len(data) != 2 {
			fmt.Print("updates data err,input like alias: baidu->baidu1 \n")
			return
		}
		a.UpdateMap[data[0]] = data[1]
		err, ret := doreq(a)
		if err != nil {
			fmt.Printf("err :%s\n", err.Error())
		} else {
			fmt.Print(ret)
		}
	} else {
		fmt.Print("updates data err,input like ips:10.0.0.0->192.168.0.1;10.0.0.1->192.168.0.2    or    alias: baidu->baidu1  \n")
		return
	}
}

func main() {
	flag.Parse()
	if cmdToken == "" {
		fmt.Print("token must be input\n")
		return
	}
	if cmdAddr == "" {
		fmt.Print("url must be input \n")
		return
	} else {
		_, err := net.Dial("tcp", cmdAddr)
		if err != nil {
			fmt.Printf(" the addr : %s can not access \n", cmdAddr)
			return
		}
	}
	if !strings.HasSuffix(cmdAddr, "/containerdns/api/") {
		cmdAddr = "http://" + cmdAddr + "/containerdns/api/"
	}
	if cmdList {
		cmdMethod = "GET"
		cmdApiList()
		return
	}
	if cmdShow != "" {
		cmdMethod = "GET"
		cmdApiShow()
		return
	}
	switch strings.ToLower(cmdMethod) {
	case "create":
		cmdMethod = "POST"
		cmdApiCreate()
	case "delete":
		cmdMethod = "DELETE"
		cmdApiDelete()
	case "update":
		cmdMethod = "PUT"
		cmdApiUpdate()
	default:
		fmt.Print("method must be  create delete or update \n")
	}

}
