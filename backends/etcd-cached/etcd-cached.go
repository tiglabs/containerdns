// Copyright (c) 2017 The skydns Authors. All rights reserved.

package etcdCached

import (
	"errors"
	"encoding/json"
	etcdv3 "github.com/coreos/etcd/clientv3"
	dnsServer "github.com/ipdcode/skydns/dns-server"
	"golang.org/x/net/context"
	"time"
	"github.com/coreos/etcd/mvcc/mvccpb"
)
const ErrorCodeKeyNotFound = "key not found"

type Backend struct {
	clientv3 etcdv3.Client
	ctx      context.Context
	timeOut  time.Duration
}

// NewBackend returns a new Backend for skydns, backed by etcd.
func NewBackend(clientv3 etcdv3.Client, ctx context.Context,timeOut int , ttl uint32, priority uint16) *Backend {
	backend := new(Backend)
	backend.clientv3 = clientv3
	backend.ctx = ctx
	backend.timeOut = time.Duration(timeOut) * time.Second
	return backend
}

func (g *Backend) Records(name string) ([]dnsServer.ServiceRecord, error) {
	dnsServer.EtcdCachesLock.RLock()
	defer dnsServer.EtcdCachesLock.RUnlock()
	if val, ok := dnsServer.EtcdRecordCaches[name]; ok {
		return val, nil
	} else {
		str := ErrorCodeKeyNotFound + name
		return nil, errors.New(str)

	}
}

func (g *Backend) Get(name string) ([]dnsServer.ServiceRecord, int64, error) {

	path := dnsServer.DnsPath(name)
	ctx, cancel := context.WithTimeout(g.ctx, g.timeOut )
	defer cancel()
	r, err := g.clientv3.Get(ctx, path, etcdv3.WithPrefix())
	if err != nil {
		return nil, 0, err
	}
	msgs, err := LoopNodes(r.Kvs)
	return msgs, r.Header.Revision, nil

}
func (g *Backend) GetRaw(path string) (*etcdv3.GetResponse, error) {
	ctx, cancel := context.WithTimeout(g.ctx, g.timeOut)
	defer cancel()
	return g.clientv3.Get(ctx, path, etcdv3.WithPrefix())
}

func (g *Backend) ReverseRecord(name string) (*dnsServer.ServiceRecord, error) {
	return nil, errors.New(" cahce not support PTR")
}

func LoopNodes(kv []*mvccpb.KeyValue) (sx []dnsServer.ServiceRecord, err error) {
	for _, item := range kv {
		serv := new(dnsServer.ServiceRecord)
		if err := json.Unmarshal(item.Value, serv); err != nil {
			return nil, err
		}
		serv.Key = string(item.Key)
		serv.DnsTtl = calculateTtl(item, serv)

		if serv.DnsPriority == 0 {
			serv.DnsPriority = int(10)
		}

		sx = append(sx, *serv)
	}
	return sx, nil
}

func calculateTtl(kv *mvccpb.KeyValue, serv *dnsServer.ServiceRecord) uint32 {
	etcdTtl := uint32(kv.Lease)
	if etcdTtl == 0 && serv.DnsTtl == 0 {
		return 10
	}
	if etcdTtl == 0 {
		return serv.DnsTtl
	}
	if serv.DnsTtl == 0 {
		return etcdTtl
	}
	if etcdTtl < serv.DnsTtl {
		return etcdTtl
	}
	return serv.DnsTtl
}
