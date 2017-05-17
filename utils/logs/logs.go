/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logs

import (
	"flag"
	"time"
	"github.com/golang/glog"
)

const (
    glogFlushPeriod = 2 * time.Second
)

func glogFlush(period time.Duration) {
    for range time.Tick(period) {
        glog.Flush()
    }
}

func InitLogs(log_dir, log_level, stderr string) {
	flag.Lookup("logtostderr").Value.Set(stderr)
	flag.Lookup("log_dir").Value.Set(log_dir)
    flag.Lookup("v").Value.Set(log_level)
	go glogFlush(glogFlushPeriod)
}