package etcdv3

import (
	"errors"
	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"time"
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
func keyFound(key string) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(key), ">", 0)
}

func (etcdcli *EtcdV3) InitEtcd(etcdServerList []string, etcdCertfile, etcdKeyFile, etcdCafile string) error {

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
	glog.V(4).Infof("#####set key=%s val =%s\n ", key,val)
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

// Create implements storage.Interface.Creat
func (etcdcli *EtcdV3) SetKeys(keys []string, vals []string) error {
	glog.V(4).Infof("#####set keys=%s vals =%s\n ", keys,vals)
	if len(keys) != len(vals){
		return errors.New("not match ")
	}
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	opts, err := etcdcli.ttlOpts(ctx, int64(0))
	if err != nil {
		return err
	}
	var ifOps [] clientv3.Cmp
	var setOps []  clientv3.Op
	for idx ,key := range keys{
		ifOp := notFound(key)
		setOp := clientv3.OpPut(key, vals[idx], opts...)
		ifOps = append(ifOps,ifOp)
		setOps = append(setOps,setOp)
	}
	txnResp, err := etcdcli.client.KV.Txn(ctx).If(
		ifOps...
	).Then(
		setOps...
	).Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return errors.New("key exists")
	}
	return nil
}

// Create implements storage.Interface.Creat
func (etcdcli *EtcdV3) DeleteKeys(keys []string) error {
	glog.V(4).Infof("#####DeleteKeys keys=%s \n ", keys)
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	var ifOps [] clientv3.Cmp
	var delOps []  clientv3.Op
	for _ ,key := range keys{
		ifOp := keyFound(key)
		delOp := clientv3.OpDelete(key)
		ifOps = append(ifOps,ifOp)
		delOps = append(delOps,delOp)
	}
	txnResp, err := etcdcli.client.KV.Txn(ctx).If(
		ifOps...
	).Then(
		delOps...
	).Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return errors.New("key not exists")
	}
	return nil
}
// Create implements storage.Interface.Creat
func (etcdcli *EtcdV3) DeleteAndSetKey(keyOld,keyNew,value string) error {
	glog.V(4).Infof("#####DeleteAndSetKey keyOld=%s  keyNew=%s value =%s\n ", keyOld,keyNew,value )
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()
	opts, err := etcdcli.ttlOpts(ctx, int64(0))
	if err != nil {
		return err
	}
	txnResp, err := etcdcli.client.KV.Txn(ctx).If(
		keyFound(keyOld),
		notFound(keyNew),
	).Then(

		clientv3.OpDelete(keyOld),
		clientv3.OpPut(keyNew, value, opts...),
	).Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return errors.New("del or set key err")
	}
	return nil
}

func (etcdcli *EtcdV3) Update(key string, val string, valPre string) error {
	glog.V(4).Infof("#####   Update key=%s val =%s valPre =%s\n ", key,val,valPre)
	ctx, cancel := context.WithTimeout(etcdcli.ctx, etcdcli.timeOut)
	defer cancel()

	opts, err := etcdcli.ttlOpts(ctx, int64(0))
	if err != nil {
		return err
	}

	txnResp, err := etcdcli.client.KV.Txn(ctx).If(
		clientv3.Compare(clientv3.Value(key), "=", valPre),
	).Then(
		clientv3.OpPut(key, val, opts...),
	).Commit()
	if err != nil {
		return err
	}
	if !txnResp.Succeeded {
		return errors.New("Update error")
	}
	return nil
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
        var keys [] string
	for _, item := range res.Kvs {
		keys = append(keys, string(item.Key))
	}
	return etcdcli.DeleteKeys(keys)
}

func (s *EtcdV3)Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
    return s.client.Watch(ctx, key, opts...)
}