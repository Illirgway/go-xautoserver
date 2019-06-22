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

	// tls enabled if this is filled (not nil)
	TLS					*TLSConfig
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

	return srv
}
