package alert_mail

import (
    "net/http"
    "strings"
    "io/ioutil"
    "encoding/json"
    "github.com/golang/glog"
)

type MailAlert struct {
    To      string `json:"to"`
    Text    string `json:"text"`
    Subject string `json:"subject"`
    SysIdx  int `json:"sys_idx"`
}

func AlertMail(mail_to, text, subject string, sys_idx int) {
    client := &http.Client{}
    mail_alert := MailAlert{To: mail_to, Text: text, Subject: subject, SysIdx: sys_idx}
    bytes, _ := json.Marshal(mail_alert)
    req, _ := http.NewRequest("POST", "http://mjdos.jd.local/api/notification/sendemail", strings.NewReader(string(bytes)))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    if resp, err := client.Do(req); err != nil {
        glog.Error("Send mail with subject " + mail_alert.Subject + " to " + mail_alert.To + " failed, due to ", err.Error())
    } else {
        defer resp.Body.Close()
        if body, err := ioutil.ReadAll(resp.Body); err == nil {
            glog.V(50).Infoln("Send alert mail <<" + string(bytes) + ">> finished, and get response body <<" + string(body) + ">>")
        } else {
            glog.Error("Send alert mail with subject " + mail_alert.Subject + " to " + mail_alert.To + " succeed, but get response body from mjdos failed, due to  ", err.Error())
        }
    }
}