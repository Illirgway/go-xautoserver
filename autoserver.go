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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

const (
	pkgErrPrefix	= "xautoserver"
)

// https://blog.bracebin.com/achieving-perfect-ssl-labs-score-with-go
func ListenAndServe(addr string, handler http.Handler, config *Config) error {

	// fast-check address
	// https://golang.org/src/net/http/server.go?s=86961:87002#L2790
	// https://golang.org/src/net/http/server.go?s=86961:87002#L3070
	if addr == "" {

		proto := "http"

		if config.IsTLS() {
			proto = "https"
		}

		addr = net.JoinHostPort("", proto)
	} else {
		// validate address
		// http.*Server.ListenAndServe() ==> net.DefaultResolver.resolveAddrList("tcp", addr) ==> net.DefaultResolver.internetAddrList()
		// net.ResolveTCPAddr("tcp", addr) ==> net.DefaultResolver.internetAddrList()

		if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
			return fmt.Errorf("%s init new server error: %s", pkgErrPrefix, err.Error())
		}
	}

	srv := config.httpServer(addr, handler)

	// TODO? add graceful stop
	if config.IsTLS() {

		logger := log.New(os.Stderr, pkgErrPrefix + " ", log.LstdFlags)

		manager, err := newManager(config.TLS, logger)

		if err != nil {
			return fmt.Errorf("%s init tls manager error: %s", pkgErrPrefix, err.Error())
		}

		logger.Printf("TLS manager forged with init certs mtime %d", manager.Mtime())

		// disable http/2 server
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
		srv.TLSConfig = manager.TLSStrongConfig()

		err = srv.ListenAndServeTLS("", "")

		manager.Stop()

		return err
	}

	return srv.ListenAndServe()
}
