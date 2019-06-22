package xautoserver

import (
	"crypto/tls"
	"time"
	"sync/atomic"
)

type certInfo struct {
	cert	*tls.Certificate
	// cert files latest mtime
	// unixts
	uts		int64
	// last check time
	chktime	int64
}

func newCertInfo(cert *tls.Certificate, mtime int64) *certInfo {
	return &certInfo{
		cert: cert,
		uts: mtime,
		chktime: time.Now().Unix(),
	}
}

func (ci *certInfo) shouldWatch(threshold int64) bool {

	// no need for lock
	chktime := atomic.LoadInt64(&ci.chktime)
	curtime := time.Now().Unix()

	// CAS automatic store curtime in ci.chktime if success
	return ((curtime - chktime) > threshold) && atomic.CompareAndSwapInt64(&ci.chktime, chktime, curtime)
}

func (ci *certInfo) mtime() int64 {
	return ci.uts
}

func (ci *certInfo) tlscert() *tls.Certificate {
	return ci.cert
}

