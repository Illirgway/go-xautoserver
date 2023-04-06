//  Copyright (C) 2019 - 2023 Illirgway
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

package xautoserver

import (
	"crypto/tls"
	"sync/atomic"
	"time"
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

