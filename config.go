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
	"net/http"
	"time"
)

type Config struct {
	// timeouts
	ReadHeaderTimeout	time.Duration
	ReadTimeout			time.Duration
	WriteTimeout		time.Duration

	// limits
	MaxHeaderBytes		int

	// tls enabled if this is exist (not nil)
	TLS					*TLSConfig

	// cb fn that gets srv
	SrvCb				func(*http.Server)
}

func (c *Config) IsTLS() bool {
	return (c != nil) && (c.TLS != nil)
}

func (c *Config) httpServer(addr string, handler http.Handler) *http.Server {

	var srv *http.Server

	if c != nil {
		srv = &http.Server{
			Addr: addr,
			Handler: handler,

			ReadHeaderTimeout: c.ReadHeaderTimeout,
			ReadTimeout: c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,

			MaxHeaderBytes: c.MaxHeaderBytes,
		}
	} else {
		srv = &http.Server{
			Addr: addr,
			Handler: handler,
		}
	}

	if c.SrvCb != nil {
		c.SrvCb(srv)
	}

	return srv
}
