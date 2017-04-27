package tools

import (
	"errors"
	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"time"
	"strings"
	"net"
	"net/http"
)

type EtcdV3 struct {
	client *clientv3.Client
	ctx    context.Context
	timeOut  time.Duration
}

func newHTTPSTransport(certFile, keyFile, caFile string) (*http.Transport, error) {
	info := transport.TLSInfo{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}
	cfg, err := info.ClientConfig()
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     cfg,
	}

	return tr, nil
}
func (etcdcli *EtcdV3) ttlOpts(ctx context.Context, ttl int64) ([]clientv3.OpOption, error) {
	if ttl == 0 {
		return nil, nil
	}
	// put keys within into same lease. We shall benchmark this and optimize the performance.
	lcr, err := etcdcli.client.Lease.Grant(ctx, ttl)
	if err != nil {
		return nil, err
	}
	return []clientv3.OpOption{clientv3.WithLease(clientv3.LeaseID(lcr.ID))}, nil
}
func notFound(key string) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(key), "=", 0)
}

func (etcdcli *EtcdV3) InitEtcd(etcdServerList []string, etcdCertfile,etcdKeyFile,etcdCafile string) error {

	tr, err := newHTTPSTransport(etcdCertfile, etcdKeyFile, etcdCafile)
	if err != nil {
		return  err
	}
	etcdCfg := clientv3.Config{
		Endpoints: etcdServerList,
		TLS: tr.TLSClientConfig,
	}
	etcdClient, err := clientv3.New(etcdCfg)
	if err != nil {
		return  err
	}
	etcdcli.client = etcdClient
	etcdcli.ctx = context.Background()
	etcdcli.timeOut = 30 * time.Second
	return nil
}

// Get implements storage.Interface.Get.
func (etcdcli *EtcdV3) Get(key string, recursive bool) (*clientv3.GetResponse, error) {

	var getResp *clientv3.GetResponse
	var err error

	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()

	if recursive {
		getResp, err = etcdcli.client.KV.Get(ctx, key, clientv3.WithPrefix())
	} else {
		getResp, err = etcdcli.client.KV.Get(ctx, key)
	}

	if err != nil {
		return nil, err
	}
	if len(getResp.Kvs) == 0 {
		return nil, errors.New("key not found")
	}

	return getResp, nil
}

// Create implements storage.Interface.Creat
func (etcdcli *EtcdV3) Set(key string, val string) error {
	glog.V(2).Infof("#####set key=%s val =%s\n ", key,val)
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	opts, err := etcdcli.ttlOpts(ctx, int64(0))
	if err != nil {
		return err
	}

	txnResp, err := etcdcli.client.KV.Txn(ctx).If(
		notFound(key),
	).Then(
		clientv3.OpPut(key, val, opts...),
	).Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return errors.New("key exists")
	}
	return nil
}

func (etcdcli *EtcdV3) Update(key string, val string) error {
	glog.V(2).Infof("#####   Update key=%s val =%s\n ", key,val)
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	getResp, err := etcdcli.client.KV.Get(ctx, key)
	if err != nil {
		return err
	}
	for {
		opts, err := etcdcli.ttlOpts(ctx, int64(0))
		if err != nil {
			return err
		}

		txnResp, err := etcdcli.client.KV.Txn(ctx).If(
			clientv3.Compare(clientv3.ModRevision(key), "=", getResp.Kvs[0].ModRevision),
		).Then(
			clientv3.OpPut(key, val, opts...),
		).Else(
			clientv3.OpGet(key),
		).Commit()
		if err != nil {
			return err
		}
		if !txnResp.Succeeded {
			getResp = (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
			glog.V(4).Infof("GuaranteedUpdate of %s failed because of a conflict, going to retry", key)
			continue
		}
		return nil
	}
}

func (etcdcli *EtcdV3) DoDelete(key string) error {
	// We need to do get and delete in single transaction in order to
	// know the value and revision before deleting it.
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	txnResp, err := etcdcli.client.KV.Txn(ctx).If().Then(
		clientv3.OpGet(key),
		clientv3.OpDelete(key),
	).Commit()
	if err != nil {
		return err
	}
	getResp := txnResp.Responses[0].GetResponseRange()
	if len(getResp.Kvs) == 0 {
		return errors.New("key not found")
	}
	return nil
}

func (etcdcli *EtcdV3) Delete(res *clientv3.GetResponse) error {

	for _, item := range res.Kvs {
		err := etcdcli.DoDelete(string(item.Key))
		if err != nil  && !strings.HasPrefix(err.Error(),"key not found"){
			glog.Infof("%s\n", err.Error())
		}
		time.Sleep(20 * time.Microsecond)
	}
	return nil
}
